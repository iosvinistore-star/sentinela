# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
from __future__ import annotations

import asyncio
import logging

from sentinela.repositories.siem import RetencaoSiemRepositorio

log = logging.getLogger(__name__)

# Linhas por transação. A 4.000 EPS entram ~345 milhões de eventos/dia: um
# único DELETE...RETURNING * gigante (como antes) seguraria locks e WAL por
# horas. Em fatias, cada transação é curta e a rotina pode ser interrompida.
TAMANHO_FATIA = 50_000
MAX_FATIAS_POR_EXECUCAO = 2_000


async def executar_retencao_siem(db, hot_days: int = 90, cold_days: int = 365,
                                 tamanho_fatia: int = TAMANHO_FATIA) -> dict[str, int]:
    """Move eventos antigos do armazenamento quente para o frio e expira os mais antigos.

    ``db`` é o ``Database``: cada fatia roda na SUA PRÓPRIA sessão/transação superadmin
    (BYPASSRLS, todos os tenants) e é confirmada antes da próxima -- assim uma retenção
    grande nunca vira uma transação única gigante segurando locks e WAL.

    V8.2: antes a rotina usava ``pool.acquire()`` sem SET ROLE; o login role
    é NOINHERIT e sem privilégio nas tabelas, então a retenção de 90/365 dias
    exigida pelo edital NUNCA arquivou nem expirou um único evento.
    """
    if hot_days < 1 or cold_days <= hot_days:
        raise ValueError("cold_days deve ser maior que hot_days")
    arquivados = 0
    expirados = 0
    for _ in range(MAX_FATIAS_POR_EXECUCAO):
        async with db.superadmin_session() as sessao:
            removidos, arquivados_na_fatia = await RetencaoSiemRepositorio(sessao).mover_fatia_para_frio(
                hot_days, cold_days, tamanho_fatia,
            )
        arquivados += arquivados_na_fatia
        expirados += removidos - arquivados_na_fatia
        if removidos < tamanho_fatia:
            break
    for _ in range(MAX_FATIAS_POR_EXECUCAO):
        async with db.superadmin_session() as sessao:
            n = await RetencaoSiemRepositorio(sessao).expirar_fatia_do_frio(cold_days, tamanho_fatia)
        expirados += n
        if n < tamanho_fatia:
            break
    return {"arquivados": arquivados, "expirados": expirados}


async def rodar_retencao_siem_periodicamente(pool, intervalo_horas: int = 24, hot_days: int = 90, cold_days: int = 365):
    """Loop de retenção; falha de uma execução não derruba o processo."""
    intervalo = max(3600, intervalo_horas * 3600)
    while True:
        try:
            resultado = await executar_retencao_siem(pool, hot_days, cold_days)
            log.info("Retenção SIEM executada: %s", resultado)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Falha na retenção SIEM")
        await asyncio.sleep(intervalo)
