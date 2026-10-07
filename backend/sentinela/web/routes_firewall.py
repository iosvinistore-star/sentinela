# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""GET /firewall, POST /firewall/bloqueios, DELETE /firewall/bloqueios/{ip} -- HTMX.
Listar é para qualquer usuário logado; bloquear/remover é admin-only (ação host-wide)."""
from fastapi import APIRouter, Depends, Form, Request

from sentinela.auth.dependencies import exigir_csrf_header
from sentinela.services import firewall as servico
from sentinela.web.deps import conexao_tenant_web, exigir_login_web, exigir_papel_web, templates

router = APIRouter()


@router.get("/firewall")
async def listar(request: Request, usuario: dict = Depends(exigir_login_web), sessao=Depends(conexao_tenant_web)):
    bloqueios = await servico.listar_bloqueios(sessao, usuario["empresa_id"])
    return templates.TemplateResponse(request, "firewall/lista.html", {"usuario": usuario, "bloqueios": bloqueios})


@router.post("/firewall/bloqueios", dependencies=[Depends(exigir_csrf_header)])
async def bloquear(request: Request, ip: str = Form(...),
                     # max_length: mesmo motivo do BloquearRequest.motivo em
                     # api/v1/firewall.py -- `motivo` é `text` sem teto no banco.
                     motivo: str = Form(..., max_length=500),
                     # 0 = permanente (ver template); negativo não fazia sentido nenhum
                     # e chegava sem checagem até o `ipset` como timeout inválido -- mesma
                     # lacuna do endpoint JSON em api/v1/firewall.py, aqui fechada com
                     # ge=0 em vez de gt=0 por causa da convenção "0 = permanente" do form.
                     duracao_horas: float = Form(24, ge=0, le=8760),
                     usuario: dict = Depends(exigir_papel_web("admin")), sessao=Depends(conexao_tenant_web)):
    await servico.registrar_bloqueio(
        sessao, usuario["empresa_id"], ip, motivo,
        dry_run=False, duracao_horas=duracao_horas or None, origem="web", usuario_id=usuario["sub"],
    )
    bloqueios = await servico.listar_bloqueios(sessao, usuario["empresa_id"])
    return templates.TemplateResponse(request, "firewall/_tabela.html", {"usuario": usuario, "bloqueios": bloqueios})


@router.delete("/firewall/bloqueios/{ip}", dependencies=[Depends(exigir_csrf_header)])
async def remover(ip: str, request: Request,
                    usuario: dict = Depends(exigir_papel_web("admin")), sessao=Depends(conexao_tenant_web)):
    await servico.remover_bloqueio(
        sessao, request.app.state.db, usuario["empresa_id"], ip, origem="web", usuario_id=usuario["sub"],
    )
    bloqueios = await servico.listar_bloqueios(sessao, usuario["empresa_id"])
    return templates.TemplateResponse(request, "firewall/_tabela.html", {"usuario": usuario, "bloqueios": bloqueios})
