# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""GET /incidentes, GET /incidentes/{id}, POST /incidentes/{id}/status -- HTMX."""
from fastapi import APIRouter, Depends, Form, HTTPException, Request

from sentinela.auth.dependencies import exigir_csrf_header
from sentinela.services import incidentes as servico
from sentinela.web.deps import conexao_tenant_web, exigir_login_web, exigir_papel_web, templates

router = APIRouter()

_STATUS_VALIDOS = ["OPEN", "EM_ANDAMENTO", "RESOLVIDO", "FALSO_POSITIVO"]


@router.get("/incidentes")
async def listar(request: Request, status: str | None = None,
                   usuario: dict = Depends(exigir_login_web), conn=Depends(conexao_tenant_web)):
    incidentes = await servico.listar_incidentes(conn, status=status or None)
    return templates.TemplateResponse(request, "incidentes/lista.html", {
        "usuario": usuario, "incidentes": incidentes,
        "status_filtro": status, "status_validos": _STATUS_VALIDOS,
    })


@router.get("/incidentes/{incident_id}")
async def detalhe(incident_id: str, request: Request,
                    usuario: dict = Depends(exigir_login_web), conn=Depends(conexao_tenant_web)):
    incidente = await servico.obter_incidente(conn, usuario["empresa_id"], incident_id)
    if incidente is None:
        raise HTTPException(status_code=404, detail="incidente não encontrado")
    return templates.TemplateResponse(request, "incidentes/detalhe.html", {
        "usuario": usuario, "incidente": incidente, "status_validos": _STATUS_VALIDOS,
    })


@router.post("/incidentes/{incident_id}/status", dependencies=[Depends(exigir_csrf_header)])
async def atualizar_status(incident_id: str, request: Request, status: str = Form(...),
                             # max_length: mesmo motivo do
                             # AtualizarStatusRequest.observacoes em api/v1/incidentes.py.
                             observacoes: str = Form("", max_length=4000),
                             # Fase C / C1 -- VIEWER é somente leitura, ver
                             # api/v1/incidentes.py:atualizar_status.
                             usuario: dict = Depends(exigir_papel_web("admin", "analista")), conn=Depends(conexao_tenant_web)):
    if status not in _STATUS_VALIDOS:
        raise HTTPException(status_code=422, detail="status inválido")
    incidente = await servico.atualizar_status(
        conn, usuario["empresa_id"], incident_id, status, observacoes, usuario_id=usuario["sub"],
    )
    if incidente is None:
        raise HTTPException(status_code=404, detail="incidente não encontrado")
    return templates.TemplateResponse(request, "incidentes/_detalhe_conteudo.html", {
        "usuario": usuario, "incidente": incidente, "status_validos": _STATUS_VALIDOS,
    })
