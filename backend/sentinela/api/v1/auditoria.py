# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""GET /api/v1/auditoria -- log de auditoria da própria empresa (admin-only)."""
from fastapi import APIRouter, Depends, Query

from sentinela.auth.dependencies import conexao_tenant, exigir_papel
from sentinela.services import auditoria as servico

router = APIRouter(prefix="/auditoria", tags=["auditoria"])


@router.get("")
async def listar_auditoria(
    # Mesmo raciocínio de api/v1/incidentes.py:listar_incidentes -- sem
    # teto, `?limite=` grande vira uma consulta cara sem custo pra quem
    # chama (RLS ainda impede vazamento entre tenants, mas não limita o
    # tamanho da consulta dentro do próprio tenant).
    limite: int = Query(100, gt=0, le=500),
    usuario: dict = Depends(exigir_papel("admin")),
    sessao=Depends(conexao_tenant),
):
    return {"auditoria": await servico.listar_auditoria(sessao, limite=limite)}
