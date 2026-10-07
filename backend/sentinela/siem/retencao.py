# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
from __future__ import annotations

import asyncio
import logging

log = logging.getLogger(__name__)

# Linhas por transação. A 4.000 EPS entram ~345 milhões de eventos/dia: um
# único DELETE...RETURNING * gigante (como antes) seguraria locks e WAL por
# horas. Em fatias, cada transação é curta e a rotina pode ser interrompida.
TAMANHO_FATIA = 50_000
MAX_FATIAS_POR_EXECUCAO = 2_000


async def executar_retencao_siem(conn, hot_days: int = 90, cold_days: int = 365,
                                 tamanho_fatia: int = TAMANHO_FATIA) -> dict[str, int]:
    """Move eventos antigos do armazenamento quente para o frio e expira os mais antigos.

    ``conn`` precisa ser uma conexão que enxergue todos os tenants (role
    app_superadmin, BYPASSRLS) -- ver ``rodar_retencao_siem_periodicamente``.

    V8.2: antes a rotina usava ``pool.acquire()`` sem SET ROLE; o login role
    é NOINHERIT e sem privilégio nas tabelas, então a retenção de 90/365 dias
    exigida pelo edital NUNCA arquivou nem expirou um único evento.
    """
    if hot_days < 1 or cold_days <= hot_days:
        raise ValueError("cold_days deve ser maior que hot_days")
    arquivados = 0
    expirados = 0
    for _ in range(MAX_FATIAS_POR_EXECUCAO):
        async with conn.transaction():
            movidos = await conn.fetchrow(
                """
                WITH alvo AS (
                    SELECT id FROM eventos_siem
                    WHERE timestamp < now() - ($1::int * interval '1 day')
                    ORDER BY timestamp
                    LIMIT $3
                ), moved AS (
                    DELETE FROM eventos_siem e USING alvo WHERE e.id = alvo.id
                    RETURNING e.*
                ), inserted AS (
                    INSERT INTO eventos_siem_cold (
                        id, empresa_id, agente_id, timestamp, source, source_type,
                        hostname, source_ip, destination_ip, source_port, destination_port,
                        protocol, username, event_type, action, severity, message,
                        raw_event, tags, mitre_techniques, iocs, criado_em, arquivado_em
                    )
                    SELECT id, empresa_id, agente_id, timestamp, source, source_type,
                           hostname, source_ip, destination_ip, source_port, destination_port,
                           protocol, username, event_type, action, severity, message,
                           raw_event, tags, mitre_techniques, iocs, criado_em, now()
                    FROM moved
                    WHERE timestamp >= now() - ($2::int * interval '1 day')
                    ON CONFLICT (id) DO NOTHING
                    RETURNING 1
                ) SELECT (SELECT count(*) FROM moved) AS removidos, (SELECT count(*) FROM inserted) AS arquivados
                """,
                hot_days, cold_days, tamanho_fatia,
            )
        removidos = int(movidos["removidos"])
        arquivados += int(movidos["arquivados"])
        # Eventos quentes já mais velhos que cold_days vão direto para expiração.
        expirados += removidos - int(movidos["arquivados"])
        if removidos < tamanho_fatia:
            break
    for _ in range(MAX_FATIAS_POR_EXECUCAO):
        async with conn.transaction():
            status = await conn.execute(
                """DELETE FROM eventos_siem_cold WHERE id IN (
                       SELECT id FROM eventos_siem_cold
                       WHERE timestamp < now() - ($1::int * interval '1 day')
                       LIMIT $2)""",
                cold_days, tamanho_fatia,
            )
        n = int(status.rsplit(" ", 1)[-1]) if status else 0
        expirados += n
        if n < tamanho_fatia:
            break
    return {"arquivados": arquivados, "expirados": expirados}


async def rodar_retencao_siem_periodicamente(pool, intervalo_horas: int = 24, hot_days: int = 90, cold_days: int = 365):
    """Loop de retenção; falha de uma execução não derruba o processo."""
    intervalo = max(3600, intervalo_horas * 3600)
    while True:
        try:
            async with pool.superadmin_session() as conn:
                resultado = await executar_retencao_siem(conn, hot_days, cold_days)
                log.info("Retenção SIEM executada: %s", resultado)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Falha na retenção SIEM")
        await asyncio.sleep(intervalo)
