# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Dashboard operacional do SOC."""
from fastapi import APIRouter, Depends
from sentinela.auth.dependencies import conexao_tenant, exigir_login
from sentinela.services.dashboard import obter_dashboard

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

@router.get("")
async def dashboard(usuario: dict = Depends(exigir_login), sessao=Depends(conexao_tenant)):
    return await obter_dashboard(sessao, usuario["empresa_id"])
