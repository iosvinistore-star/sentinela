# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
POST /api/v1/logs/analisar — a metade React da correção da lacuna do
dashboard antigo: antes, um upload de log só desenhava gráficos e nunca
criava incidentes de verdade (só o CLI, via `responder_a_incidentes`,
criava). Aqui (e na rota HTMX equivalente, fase 7), o upload chama a MESMA
orquestração assíncrona (`services.resposta_incidentes.responder_a_incidentes`),
escopada pela empresa de quem está logado.
"""
import asyncio
import os
import tempfile

from fastapi import APIRouter, Depends, Form, Request, UploadFile, File, HTTPException

from sentinela.auth.dependencies import conexao_tenant, exigir_csrf_header, exigir_papel
from sentinela.core.analisador_logs import processar_arquivo_logs
from sentinela.core.limites_upload import LimiteUploadExcedidoError, mensagem_amigavel
from sentinela.services.resposta_incidentes import responder_a_incidentes

router = APIRouter(prefix="/logs", tags=["logs"])
MAX_LOG_UPLOAD_BYTES = 10 * 1024 * 1024


@router.post("/analisar", dependencies=[Depends(exigir_csrf_header)])
async def analisar_log(
    request: Request,
    arquivo: UploadFile = File(...),
    limite: int = Form(5),
    verificar_reputacao: bool = Form(True),
    bloquear: bool = Form(False),
    modo_resposta: str = Form("manual"),
    duracao_bloqueio_horas: float = Form(24),
    # Fase C / C1 -- upload de log é uma ação MUTÁVEL (cria incidentes,
    # pode bloquear IP) -- VIEWER não pode. Retrofit de `exigir_login`
    # (que aceitava viewer) para `exigir_papel("admin", "analista")`.
    usuario: dict = Depends(exigir_papel("admin", "analista")),
    conn=Depends(conexao_tenant),
):
    if not 1 <= limite <= 100:
        raise HTTPException(status_code=422, detail="limite deve estar entre 1 e 100")
    if not 0 < duracao_bloqueio_horas <= 168:
        raise HTTPException(status_code=422, detail="duração do bloqueio deve estar entre 0 e 168 horas")
    limitador_uploads = request.app.state.limitador_uploads
    fd, caminho_tmp = tempfile.mkstemp(suffix=".log")
    total = 0
    try:
        with os.fdopen(fd, "wb") as tmp:
            while True:
                chunk = await arquivo.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_LOG_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="arquivo de log excede o limite de 10 MB")
                tmp.write(chunk)

        # Volume por usuário/empresa (ver core/limites_upload.py) -- só
        # depois de conhecer `total` de verdade (não dá pra confiar em
        # Content-Length, que o cliente controla). Levanta ANTES de gastar
        # CPU processando o arquivo.
        try:
            await limitador_uploads.reservar_volume(usuario["sub"], usuario["empresa_id"], total)
        except LimiteUploadExcedidoError as exc:
            raise HTTPException(status_code=429, detail=mensagem_amigavel(exc)) from exc

        # processar_arquivo_logs é CPU-bound (regex sobre até 10 MB de texto
        # hostil) e SÍNCRONO -- chamá-lo direto aqui bloquearia o único
        # event loop do processo (a app sobe com um único worker uvicorn),
        # travando TODOS os tenants enquanto o regex roda. `asyncio.to_thread`
        # tira esse trabalho do event loop, igual já é feito para
        # core.firewall/core.reputacao em services/firewall.py e
        # services/reputacao.py -- este era o único ponto de entrada que
        # tinha ficado de fora desse padrão. `limitador_uploads.processamento()`
        # (mesmo módulo) limita quantas dessas análises rodam ao mesmo
        # tempo -- protege a threadpool compartilhada do processo, não é
        # uma cota por cliente.
        try:
            async with limitador_uploads.processamento():
                relatorio = await asyncio.to_thread(processar_arquivo_logs, caminho_tmp)
        except LimiteUploadExcedidoError as exc:
            raise HTTPException(status_code=429, detail=mensagem_amigavel(exc)) from exc
    finally:
        os.unlink(caminho_tmp)

    # bloquear é uma ação host-wide (ver services/firewall.py) e é
    # admin-only em toda outra rota do sistema (POST/DELETE
    # /firewall/bloqueios, e a versão HTMX deste mesmo upload em
    # web/routes_logs.py) -- sem esta checagem, um analista autenticado
    # conseguia bloquear IP de verdade só usando a API JSON em vez da tela,
    # um escalonamento de privilégio real.
    pode_bloquear = bloquear and usuario["papel"] == "admin"

    respostas = await responder_a_incidentes(
        conn, usuario["empresa_id"], relatorio,
        limite_ataques=limite,
        verificar_reputacao=verificar_reputacao,
        bloquear=pode_bloquear,
        dry_run=False,
        modo_resposta=modo_resposta,
        duracao_horas=duracao_bloqueio_horas or None,
        origem="api",
        usuario_id=usuario["sub"],
        automacao_habilitada=request.app.state.settings.firewall_automacao_habilitada,
    )
    relatorio["respostas_incidentes"] = respostas
    return relatorio
