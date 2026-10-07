# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""UEBA heurística por entidade (ver siem/ueba.py)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from sentinela.auth.dependencies import conexao_tenant, exigir_csrf_header, exigir_papel
from sentinela.services import siem as servico_siem

router = APIRouter(prefix="/ueba", tags=["ueba"])


@router.get("/anomalias")
async def anomalias(limite: int = Query(100, ge=1, le=1000), usuario=Depends(exigir_papel("admin", "analista")),
                    sessao=Depends(conexao_tenant)):
    return await servico_siem.listar_anomalias(sessao, usuario["empresa_id"], limite)


@router.post("/reavaliar", dependencies=[Depends(exigir_csrf_header)])
async def reavaliar(limite: int = Query(500, ge=1, le=5000), usuario=Depends(exigir_papel("admin", "analista")),
                    sessao=Depends(conexao_tenant)):
    return await servico_siem.reavaliar_ueba(sessao, usuario["empresa_id"], limite)
