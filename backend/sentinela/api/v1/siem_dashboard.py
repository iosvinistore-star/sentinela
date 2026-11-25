# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from sentinela.auth.dependencies import conexao_tenant, exigir_papel
from sentinela.services import siem as servico_siem

router = APIRouter(prefix="/siem/dashboard", tags=["siem-dashboard"])


@router.get("/resumo")
async def resumo_siem(
    horas: int = Query(24, ge=1, le=168),
    usuario: dict = Depends(exigir_papel("admin", "analista")),
    sessao=Depends(conexao_tenant),
):
    return await servico_siem.resumo(sessao, usuario["empresa_id"], horas)


@router.get("/fontes")
async def fontes_siem(
    usuario: dict = Depends(exigir_papel("admin", "analista")),
    sessao=Depends(conexao_tenant),
):
    return await servico_siem.fontes_ativas(sessao, usuario["empresa_id"])


@router.get("/soc-executivo")
async def soc_executivo(usuario=Depends(exigir_papel("admin", "analista")), sessao=Depends(conexao_tenant)):
    return await servico_siem.soc_executivo(sessao, usuario["empresa_id"])


@router.get("/correlacoes")
async def correlacoes_recentes(
    limite: int = Query(50, ge=1, le=500),
    usuario: dict = Depends(exigir_papel("admin", "analista")),
    sessao=Depends(conexao_tenant),
):
    """Correlações mais recentes com o resumo do evento de origem (V8.2).

    Até a V8.2 as correlações eram gravadas mas não havia rota de leitura --
    nenhuma tela conseguia mostrá-las ao analista.
    """
    return await servico_siem.correlacoes_recentes(sessao, usuario["empresa_id"], limite)
