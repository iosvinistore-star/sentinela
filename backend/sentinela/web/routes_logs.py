# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
GET /logs/upload, POST /logs/upload -- metade HTMX da correção da lacuna do
dashboard antigo (ver api/v1/logs.py para a metade React da mesma correção;
ambas chamam `services.resposta_incidentes.responder_a_incidentes`).
"""
import asyncio
import os
import tempfile

from fastapi import APIRouter, Depends, Form, Request, UploadFile, File, HTTPException

from sentinela.auth.dependencies import exigir_csrf_header
from sentinela.core.analisador_logs import processar_arquivo_logs
from sentinela.core.limites_upload import LimiteUploadExcedidoError, mensagem_amigavel
from sentinela.services.resposta_incidentes import responder_a_incidentes
from sentinela.web.deps import conexao_tenant_web, exigir_login_web, exigir_papel_web, templates

router = APIRouter()
MAX_LOG_UPLOAD_BYTES = 10 * 1024 * 1024


@router.get("/logs/upload")
async def formulario(request: Request, usuario: dict = Depends(exigir_login_web)):
    return templates.TemplateResponse(request, "logs/upload.html", {"usuario": usuario})


@router.post("/logs/upload", dependencies=[Depends(exigir_csrf_header)])
async def analisar(
    request: Request,
    arquivo: UploadFile = File(...),
    limite: int = Form(5),
    verificar_reputacao: bool = Form(False),
    bloquear: bool = Form(False),
    duracao_bloqueio_horas: float = Form(24),
    # Fase C / C1 -- ver api/v1/logs.py:analisar_log (mesmo retrofit).
    usuario: dict = Depends(exigir_papel_web("admin", "analista")),
    sessao=Depends(conexao_tenant_web),
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

        # Ver core/limites_upload.py -- volume por usuário/empresa, checado
        # só depois de conhecer `total` de verdade.
        try:
            await limitador_uploads.reservar_volume(usuario["sub"], usuario["empresa_id"], total)
        except LimiteUploadExcedidoError as exc:
            raise HTTPException(status_code=429, detail=mensagem_amigavel(exc)) from exc

        # Ver comentário equivalente em api/v1/logs.py: processar_arquivo_logs
        # é CPU-bound e síncrono -- sem to_thread, bloqueia o único event
        # loop do processo (um único worker uvicorn) para todos os tenants.
        # `limitador_uploads.processamento()` limita quantas análises rodam
        # ao mesmo tempo (protege a threadpool compartilhada do processo).
        try:
            async with limitador_uploads.processamento():
                relatorio = await asyncio.to_thread(processar_arquivo_logs, caminho_tmp)
        except LimiteUploadExcedidoError as exc:
            raise HTTPException(status_code=429, detail=mensagem_amigavel(exc)) from exc
    finally:
        os.unlink(caminho_tmp)

    # bloquear só é honrado se o usuário for admin -- mesma regra da API
    # (registrar_bloqueio é uma ação host-wide); um analista marcando o
    # checkbox (que nem aparece pra ele no template) não teria efeito aqui
    # de qualquer forma, mas a checagem explícita documenta a intenção.
    pode_bloquear = bloquear and usuario["papel"] == "admin"

    respostas = await responder_a_incidentes(
        sessao, usuario["empresa_id"], relatorio,
        limite_ataques=limite,
        verificar_reputacao=verificar_reputacao,
        bloquear=pode_bloquear,
        dry_run=False,
        duracao_horas=duracao_bloqueio_horas or None,
        origem="web",
        usuario_id=usuario["sub"],
        automacao_habilitada=request.app.state.settings.firewall_automacao_habilitada,
    )
    relatorio["respostas_incidentes"] = respostas
    return templates.TemplateResponse(request, "logs/_resultado.html", {"usuario": usuario, "relatorio": relatorio})
