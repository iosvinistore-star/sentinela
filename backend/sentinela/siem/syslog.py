# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
from __future__ import annotations

import json
import logging
import os

from sentinela.siem.servico import SIEMBatcher, normalizar_syslog

logger = logging.getLogger(__name__)


class _Protocol:
    def __init__(self, loop, batcher: SIEMBatcher, source_map: dict[str, str]):
        self.loop = loop
        self.batcher = batcher
        self.source_map = source_map
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        logger.info("SIEM Syslog UDP ativo")

    def datagram_received(self, data, addr):
        host = addr[0]
        tenant = self.source_map.get(host)
        if not tenant:
            logger.warning("Syslog descartado: origem sem tenant configurado", extra={"source_ip": host})
            return
        try:
            text = data.decode("utf-8", errors="replace")
            evento = normalizar_syslog(text, "syslog-udp", host)
            if not self.batcher.put_nowait(tenant, evento):
                logger.warning("Fila SIEM cheia/indisponível -- evento Syslog descartado", extra={"source_ip": host})
        except Exception:
            logger.exception("Falha ao normalizar Syslog UDP")

    def error_received(self, exc):
        logger.error("Erro no transporte Syslog UDP: %s", exc)

    def connection_lost(self, exc):
        logger.info("SIEM Syslog UDP encerrado")


async def iniciar_syslog_udp(pool):
    if os.getenv("SENTINELA_SYSLOG_UDP_ENABLED", "false").lower() != "true":
        return None
    # Listener desligado por padrão (SENTINELA_SYSLOG_UDP_ENABLED); quando ligado
    # precisa receber de equipamentos de rede. Restrinja via firewall/env.
    host = os.getenv("SENTINELA_SYSLOG_UDP_HOST", "0.0.0.0")  # nosec B104
    port = int(os.getenv("SENTINELA_SYSLOG_UDP_PORT", "5514"))
    raw_map = os.getenv("SENTINELA_SYSLOG_SOURCES", "{}")
    try:
        source_map = json.loads(raw_map)
        if not isinstance(source_map, dict):
            raise ValueError("SENTINELA_SYSLOG_SOURCES deve ser objeto JSON")
    except Exception as exc:
        raise RuntimeError("SENTINELA_SYSLOG_SOURCES inválido") from exc

    batch_size = int(os.getenv("SENTINELA_SIEM_BATCH_SIZE", "500"))
    flush_ms = int(os.getenv("SENTINELA_SIEM_FLUSH_MS", "100"))
    max_queue = int(os.getenv("SENTINELA_SIEM_MAX_QUEUE", "20000"))
    batcher = SIEMBatcher(pool, batch_size=batch_size, flush_interval=flush_ms / 1000, max_queue=max_queue)
    await batcher.start()

    import asyncio
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _Protocol(loop, batcher, {str(k): str(v) for k, v in source_map.items()}),
        local_addr=(host, port),
    )
    return transport, batcher
