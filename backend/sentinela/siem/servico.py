# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
from typing import Any


_SEVERIDADES = {"DEBUG", "INFO", "NOTICE", "WARNING", "WARN", "ERROR", "HIGH", "CRITICAL", "ALERT", "EMERGENCY"}
_SYSLOG_RE = re.compile(r"^(?:<(?P<pri>\d{1,3})>)?(?P<rest>.*)$")


_MESES = {"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"}
_RFC3164_TS = re.compile(r"^(?P<mes>[A-Za-z]{3})\s+(?P<dia>\d{1,2})\s+(?P<hora>\d{2}:\d{2}:\d{2})\s+(?P<resto>.*)$", re.DOTALL)
_RFC5424 = re.compile(r"^1\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+\S+\s+\S+\s+(?:-|\[.*?\])\s?(?P<msg>.*)$", re.DOTALL)


def _parse_rfc3164_ts(mes: str, dia: str, hora: str) -> datetime | None:
    agora = datetime.now(timezone.utc)
    try:
        ts = datetime.strptime(f"{agora.year} {mes} {int(dia)} {hora}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    # Virada de ano: "Dec 31" recebido em 1º de janeiro.
    if (ts - agora).days > 1:
        ts = ts.replace(year=agora.year - 1)
    return ts


def normalizar_syslog(mensagem: str, origem: str, origem_ip: str | None = None) -> dict[str, Any]:
    """Normaliza Syslog RFC 3164 / RFC 5424 sem depender de parser externo.

    V8.2: antes o hostname era sempre o 2º token após o PRI -- em RFC 3164
    ("Oct 11 22:14:15 host app: msg") isso gravava o DIA DO MÊS ("11") como
    hostname, e o timestamp do dispositivo era descartado.
    """
    m = _SYSLOG_RE.match(mensagem.strip())
    pri = int(m.group("pri")) if m and m.group("pri") else None
    rest = m.group("rest") if m else mensagem
    severity = "INFO"
    facility = None
    if pri is not None and pri <= 191:
        facility, sev = divmod(pri, 8)
        severity = ["EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG"][sev]
    hostname = None
    message = rest
    timestamp = None
    m5424 = _RFC5424.match(rest)
    m3164 = _RFC3164_TS.match(rest)
    if m5424:
        hostname = None if m5424.group("host") == "-" else m5424.group("host")
        message = m5424.group("msg") or rest
        ts_txt = m5424.group("ts")
        if ts_txt != "-":
            try:
                timestamp = datetime.fromisoformat(ts_txt.replace("Z", "+00:00"))
            except ValueError:
                timestamp = None
    elif m3164 and m3164.group("mes").lower() in _MESES:
        timestamp = _parse_rfc3164_ts(m3164.group("mes"), m3164.group("dia"), m3164.group("hora"))
        partes = m3164.group("resto").split(None, 1)
        if partes and not partes[0].endswith(":"):
            hostname = partes[0]
            message = partes[1] if len(partes) > 1 else ""
        else:
            message = m3164.group("resto")
    return {
        "timestamp": timestamp or datetime.now(timezone.utc),
        "source": origem,
        "source_type": "syslog",
        "hostname": hostname[:255] if hostname else None,
        "source_ip": origem_ip,
        "event_type": "syslog",
        "severity": severity,
        "message": message or rest,
        "raw_event": mensagem,
        "tags": ["syslog"] + ([f"facility:{facility}"] if facility is not None else []),
    }


def _rows(empresa_id: str, eventos: list[dict[str, Any]], agente_id: str | None = None):
    for evento in eventos:
        e = dict(evento)
        yield (
            empresa_id, agente_id, e.get("timestamp") or datetime.now(timezone.utc),
            e.get("source", "unknown"), e.get("source_type", "generic"), e.get("hostname"),
            e.get("source_ip"), e.get("destination_ip"), e.get("source_port"), e.get("destination_port"),
            e.get("protocol"), e.get("username"), e.get("event_type", "log"), e.get("action"),
            str(e.get("severity", "INFO")).upper(), e.get("message", ""), e.get("raw_event", e.get("message", "")),
            json.dumps(e.get("tags", [])), json.dumps(e.get("mitre_techniques", [])), json.dumps(e.get("iocs", [])),
        )


_EVENT_INSERT = """
INSERT INTO eventos_siem (
    empresa_id, agente_id, timestamp, source, source_type, hostname,
    source_ip, destination_ip, source_port, destination_port, protocol,
    username, event_type, action, severity, message, raw_event, tags,
    mitre_techniques, iocs
) VALUES (
    $1,$2,$3,$4,$5,$6,$7::inet,$8::inet,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18::jsonb,$19::jsonb,$20::jsonb
)
"""


async def persistir_eventos(conn, empresa_id: str, eventos: list[dict[str, Any]], agente_id: str | None = None) -> int:
    """Persiste em lote e retorna a quantidade inserida. Use persistir_eventos_com_ids quando a correlação imediata for necessária."""
    return len(await persistir_eventos_com_ids(conn, empresa_id, eventos, agente_id))


async def persistir_eventos_com_ids(conn, empresa_id: str, eventos: list[dict[str, Any]], agente_id: str | None = None) -> list[int]:
    """Insere o lote em uma única instrução e devolve os IDs exatos na mesma ordem do lote."""
    if not eventos:
        return []
    # PostgreSQL limita uma instrução a 65535 parâmetros; cada evento usa 20.
    # Mantemos margem e dividimos lotes grandes sem alterar a API de ingestão.
    if len(eventos) > 3000:
        ids: list[int] = []
        for inicio in range(0, len(eventos), 3000):
            ids.extend(await persistir_eventos_com_ids(conn, empresa_id, eventos[inicio:inicio + 3000], agente_id))
        return ids
    rows = list(_rows(empresa_id, eventos, agente_id))
    values = ",".join(
        f"(${i*20+1},${i*20+2},${i*20+3},${i*20+4},${i*20+5},${i*20+6},${i*20+7}::inet,${i*20+8}::inet,${i*20+9},${i*20+10},${i*20+11},${i*20+12},${i*20+13},${i*20+14},${i*20+15},${i*20+16},${i*20+17},${i*20+18}::jsonb,${i*20+19}::jsonb,${i*20+20}::jsonb)"
        for i in range(len(rows))
    )
    args = [v for row in rows for v in row]
    # Só placeholders ($n) gerados aqui entram na string; valores vão em *args.
    sql = f"""INSERT INTO eventos_siem (empresa_id,agente_id,timestamp,source,source_type,hostname,source_ip,destination_ip,source_port,destination_port,protocol,username,event_type,action,severity,message,raw_event,tags,mitre_techniques,iocs) VALUES {values} RETURNING id"""  # nosec B608
    result = await conn.fetch(sql, *args)
    return [int(r["id"]) for r in result]


class SIEMBatcher:
    """Fila assíncrona de ingestão para reduzir round-trips ao PostgreSQL.

    Agrupa eventos por tenant e descarrega por tamanho OU idade do lote.

    V8.2:
    * Descarrega com a conexão escopada ao tenant (``tenant_scoped_connection``).
      Antes usava ``pool.acquire()`` cru: o login role ``sentinela_app`` é
      NOINHERIT e não tem privilégio nas tabelas, então NENHUM evento Syslog
      era gravado (o erro só aparecia no log).
    * Descarga por idade: antes só havia flush quando a fila ficava ociosa por
      ``flush_interval``; sob fluxo contínuo de um tenant, os poucos eventos
      de outro tenant ficavam retidos indefinidamente.
    * Após persistir, aplica a mesma correlação (CTI/Sigma/UEBA/SOAR) da
      ingestão do Agent -- antes o Syslog nunca era correlacionado.
    * ``put_nowait`` síncrono: o protocolo UDP fazia ``create_task(put(...))``
      e testava o Task (sempre verdadeiro), então descarte por fila cheia
      nunca era detectado. Contadores ``descartados``/``falhas`` expostos.
    """

    def __init__(self, pool, batch_size: int = 500, flush_interval: float = 0.100, max_queue: int = 20000,
                 correlacionar: bool = True):
        self.pool = pool
        self.batch_size = max(1, batch_size)
        self.flush_interval = max(0.01, flush_interval)
        self.queue: asyncio.Queue[tuple[str, dict[str, Any], str | None]] | None = None
        self.max_queue = max(1, max_queue)
        self.correlacionar = correlacionar
        self._task = None
        self._stopping = False
        self.descartados = 0
        self.falhas = 0
        self.persistidos = 0

    async def start(self):
        if self._task is not None:
            return
        self.queue = asyncio.Queue(maxsize=self.max_queue)
        self._stopping = False
        self._task = asyncio.create_task(self._run(), name="siem-batcher")

    def put_nowait(self, empresa_id: str, evento: dict[str, Any], agente_id: str | None = None) -> bool:
        if self.queue is None or self._stopping:
            self.descartados += 1
            return False
        try:
            self.queue.put_nowait((empresa_id, evento, agente_id))
            return True
        except asyncio.QueueFull:
            self.descartados += 1
            return False

    async def put(self, empresa_id: str, evento: dict[str, Any], agente_id: str | None = None) -> bool:
        return self.put_nowait(empresa_id, evento, agente_id)

    async def _run(self):
        loop = asyncio.get_running_loop()
        pending: dict[tuple[str, str | None], list[dict[str, Any]]] = {}
        primeiro_em: dict[tuple[str, str | None], float] = {}
        try:
            while not self._stopping or (self.queue and not self.queue.empty()):
                try:
                    item = await asyncio.wait_for(self.queue.get(), timeout=self.flush_interval)
                    key = (item[0], item[2])
                    pending.setdefault(key, []).append(item[1])
                    primeiro_em.setdefault(key, loop.time())
                    self.queue.task_done()
                    if len(pending[key]) >= self.batch_size:
                        primeiro_em.pop(key, None)
                        await self._flush_key(key, pending)
                except asyncio.TimeoutError:
                    pass
                agora = loop.time()
                for key in [k for k, t0 in primeiro_em.items() if agora - t0 >= self.flush_interval]:
                    primeiro_em.pop(key, None)
                    await self._flush_key(key, pending)
        finally:
            for key in list(pending):
                await self._flush_key(key, pending)

    async def _flush_key(self, key, pending):
        eventos = pending.pop(key, None)
        if not eventos:
            return
        tenant, agente_id = key
        from sentinela.db.pool import tenant_scoped_connection
        try:
            async with tenant_scoped_connection(self.pool, tenant) as conn:
                ids = await persistir_eventos_com_ids(conn, tenant, eventos, agente_id)
                if self.correlacionar:
                    from sentinela.siem.correlacao_siem import correlacionar_lote
                    await correlacionar_lote(conn, tenant, list(zip(ids, eventos)))
            self.persistidos += len(eventos)
        except Exception:
            # Não reencaminhamos indefinidamente: evita crescimento sem limite em falha de banco.
            self.falhas += len(eventos)
            import logging
            logging.getLogger(__name__).exception("Falha ao persistir lote SIEM (tenant=%s, eventos=%d)", tenant, len(eventos))

    async def stop(self):
        if self._task is None:
            return
        self._stopping = True
        await self._task
        self._task = None
        self.queue = None
