# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Sentinela SaaS -- licenciamento. Duas famílias de rota, mesmo espírito da
separação já usada em api/v1/agentes.py:

  - `router` (prefix "/licencas"): a MÁQUINA do cliente (Sentinela Agent) se
    autenticando com o token de longa duração da própria licença (header
    X-Sentinela-License-Token, ver auth/dependencies.py:licenca_atual). Sem
    cookie, sem CSRF -- mesmo raciocínio de api/v1/agentes.py:heartbeat.

  - `admin_router` (prefix "/admin"): sessão humana de SUPERADMIN
    provisionando/gerenciando licenças de qualquer empresa -- mesmo padrão
    de api/v1/admin.py (conexao_superadmin, exigir_csrf_header).

Ver ARQUITETURA_LICENCIAMENTO.md para o desenho completo.
"""
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from sentinela.auth.dependencies import conexao_superadmin, conexao_tenant_licenca, exigir_csrf_header, exigir_superadmin, licenca_atual
from sentinela.auth.rbac import exigir_saas_owner
from sentinela.services import empresas as servico_empresas
from sentinela.services import licenciamento as servico
from sentinela.services.licenciamento import PlanoInvalidoError

router = APIRouter(prefix="/licencas", tags=["licencas"])
admin_router = APIRouter(prefix="/admin", tags=["licencas-admin"])


def _status_para_http(status_licenca: str) -> None:
    """Traduz um status de licença não-'ativa' para o HTTPException apropriado.
    Chamada por activate/validate -- NÃO por status/deactivate, que devolvem
    o status tal como está sem erro (ver ARQUITETURA_LICENCIAMENTO.md §5)."""
    if status_licenca != "ativa":
        raise HTTPException(status_code=403, detail=f"licença {status_licenca}")


@router.post("/activate")
async def activate(licenca: dict = Depends(licenca_atual), sessao=Depends(conexao_tenant_licenca)):
    resultado = await servico.ativar_licenca(sessao, licenca)
    if resultado is None:
        raise HTTPException(status_code=404, detail="licença não encontrada")
    _status_para_http(resultado["status"])
    return {"licenca": resultado}


@router.post("/validate")
async def validate(licenca: dict = Depends(licenca_atual), sessao=Depends(conexao_tenant_licenca)):
    resultado = await servico.validar_licenca(sessao, licenca)
    if resultado is None:
        raise HTTPException(status_code=404, detail="licença não encontrada")
    _status_para_http(resultado["status"])
    return {"licenca": resultado}


@router.post("/deactivate")
async def deactivate(licenca: dict = Depends(licenca_atual), sessao=Depends(conexao_tenant_licenca)):
    """Best-effort -- nunca falha por causa do status da licença (ver
    ARQUITETURA_LICENCIAMENTO.md §5): mesmo uma licença já suspensa/revogada
    pode (e deve) aceitar um aviso de desinstalação do agente."""
    resultado = await servico.desativar_licenca(sessao, licenca)
    if resultado is None:
        raise HTTPException(status_code=404, detail="licença não encontrada")
    return {"licenca": resultado}


@router.get("/status")
async def status(licenca: dict = Depends(licenca_atual), sessao=Depends(conexao_tenant_licenca)):
    """Leitura pontual, sem side-effect -- devolve o status tal como está,
    inclusive não-'ativa' (o Agent decide o que fazer; não é papel desta
    rota de inspeção levantar 403)."""
    resultado = await servico.obter_status_licenca(sessao, licenca)
    if resultado is None:
        raise HTTPException(status_code=404, detail="licença não encontrada")
    return {"licenca": resultado}


# --------------------------------------------------------------------------
# Rotas administrativas (superadmin) -- provisionamento centralizado.
# --------------------------------------------------------------------------

class CriarLicencaRequest(BaseModel):
    plano_id: uuid.UUID
    expira_em: datetime | None = None


class RenovarLicencaRequest(BaseModel):
    nova_expiracao: datetime | None = None


@admin_router.get("/planos")
async def listar_planos(su: dict = Depends(exigir_superadmin), sessao=Depends(conexao_superadmin)):
    return {"planos": await servico.listar_planos(sessao)}


@admin_router.get("/empresas/{empresa_id}/licencas")
async def listar_licencas_da_empresa(empresa_id: uuid.UUID, su: dict = Depends(exigir_superadmin),
                                       sessao=Depends(conexao_superadmin)):
    if await servico_empresas.obter_empresa(sessao, str(empresa_id)) is None:
        raise HTTPException(status_code=404, detail="empresa não encontrada")
    return {"licencas": await servico.listar_licencas(sessao)}


@admin_router.post("/empresas/{empresa_id}/licencas", dependencies=[Depends(exigir_csrf_header)])
async def criar_licenca_da_empresa(empresa_id: uuid.UUID, dados: CriarLicencaRequest,
                                     su: dict = Depends(exigir_superadmin), sessao=Depends(conexao_superadmin)):
    if await servico_empresas.obter_empresa(sessao, str(empresa_id)) is None:
        raise HTTPException(status_code=404, detail="empresa não encontrada")
    try:
        licenca, token = await servico.criar_licenca(
            sessao, str(empresa_id), str(dados.plano_id), expira_em=dados.expira_em, ator_superadmin_id=su["sub"],
        )
    except PlanoInvalidoError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    # `token` só existe aqui -- nunca mais recuperável depois desta resposta
    # (só o hash persiste), mesma filosofia de api/v1/agentes.py:criar_agente.
    return {"licenca": licenca, "token": token}


@admin_router.post("/licencas/{licenca_id}/suspender", dependencies=[Depends(exigir_csrf_header)])
async def suspender_licenca(licenca_id: uuid.UUID,
                              # Fase C / C4 -- suspender licença é uma operação
                              # EXCLUSIVA de SaaS Owner (não de qualquer superadmin
                              # / SaaS Admin). Ver auth/rbac.py:exigir_saas_owner.
                              su: dict = Depends(exigir_saas_owner),
                              sessao=Depends(conexao_superadmin)):
    empresa_id = await servico.obter_empresa_da_licenca(sessao, licenca_id)
    if empresa_id is None:
        raise HTTPException(status_code=404, detail="licença não encontrada")
    resultado = await servico.suspender_licenca(sessao, empresa_id, licenca_id, ator_superadmin_id=su["sub"])
    return {"licenca": resultado}


@admin_router.post("/licencas/{licenca_id}/revogar", dependencies=[Depends(exigir_csrf_header)])
async def revogar_licenca(licenca_id: uuid.UUID,
                            # Fase C / C4 -- ver suspender_licenca acima (mesmo motivo).
                            su: dict = Depends(exigir_saas_owner),
                            sessao=Depends(conexao_superadmin)):
    empresa_id = await servico.obter_empresa_da_licenca(sessao, licenca_id)
    if empresa_id is None:
        raise HTTPException(status_code=404, detail="licença não encontrada")
    resultado = await servico.revogar_licenca(sessao, empresa_id, licenca_id, ator_superadmin_id=su["sub"])
    return {"licenca": resultado}


@admin_router.post("/licencas/{licenca_id}/renovar", dependencies=[Depends(exigir_csrf_header)])
async def renovar_licenca(licenca_id: uuid.UUID, dados: RenovarLicencaRequest,
                            su: dict = Depends(exigir_superadmin), sessao=Depends(conexao_superadmin)):
    empresa_id = await servico.obter_empresa_da_licenca(sessao, licenca_id)
    if empresa_id is None:
        raise HTTPException(status_code=404, detail="licença não encontrada")
    try:
        resultado = await servico.renovar_licenca(
            sessao, empresa_id, licenca_id, nova_expiracao=dados.nova_expiracao, ator_superadmin_id=su["sub"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"licenca": resultado}
