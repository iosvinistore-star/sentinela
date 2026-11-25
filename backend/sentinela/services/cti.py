# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Indicadores CTI (STIX/TAXII) por tenant."""
from sentinela.repositories.siem import CtiRepositorio


async def gravar_indicadores(sessao, empresa_id, indicadores: list[dict]) -> int:
    if indicadores:
        await CtiRepositorio(sessao).upsert_lote(empresa_id, indicadores)
    return len(indicadores)


async def listar_indicadores(sessao, empresa_id, limite: int) -> list[dict]:
    return await CtiRepositorio(sessao).listar_recentes(empresa_id, limite)


async def indicadores_para_feed(sessao, empresa_id, depois_do_id: int, limite: int) -> list[dict]:
    return await CtiRepositorio(sessao).listar_para_feed(empresa_id, depois_do_id, limite)
