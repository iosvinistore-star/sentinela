# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Correlação SIEM -> CTI + Sigma + UEBA -> SOAR, em LOTE e sem ação destrutiva.

Mudanças da V8.2 (ver RELATORIO_REVISAO_V8_2.md):

* Orientada a lote. Antes, cada evento fazia ~5 consultas (inclusive recarregar
  TODAS as regras Sigma e playbooks do tenant e um scan UEBA de 24h). Agora um
  lote carrega regras/playbooks uma vez, faz UMA consulta CTI para todos os
  tokens do lote e uma consulta UEBA por entidade distinta.
* A correlação é SEMPRE registrada em ``siem_correlacoes`` quando passa do
  limiar -- antes só era gravada se existisse playbook para o gatilho, então
  um match CTI sem playbook simplesmente se perdia.
* Disparos Sigma do caminho automático passam a ser gravados em
  ``sigma_alertas`` (a documentação já dizia isso; o código não fazia).
* ``netflow_connection`` (score 35) deixou de gerar correlação sozinho: todo
  fluxo NetFlow com destino virava uma linha de correlação.
* Playbooks continuam apenas registrados (``execucao_destrutiva: false``).
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

from sentinela.siem.sigma import SigmaErro, compilar_regra
from sentinela.siem.ueba import avaliar_lote, chave_entidade

log = logging.getLogger(__name__)

LIMIAR_CORRELACAO = int(os.getenv("SENTINELA_CORRELACAO_LIMIAR", "50"))
_SEVERIDADES_ALTAS = {"HIGH", "CRITICAL", "ALERT", "EMERGENCY"}
_MAX_TOKENS_POR_EVENTO = 64
_MAX_TOKENS_POR_LOTE = 20_000
_PONTUACAO = str.maketrans({c: " " for c in "[](),;'\"<>{}|="})


def _tokens(evento: dict[str, Any]) -> set[str]:
    valores = {str(v).strip().lower() for v in (
        evento.get("source_ip"), evento.get("destination_ip"), evento.get("hostname"), evento.get("username"),
    ) if v}
    for ioc in evento.get("iocs") or []:
        valores.add(str(ioc).strip().lower())
    mensagem = str(evento.get("message") or "").lower().translate(_PONTUACAO)
    for i, token in enumerate(mensagem.split()):
        if i >= _MAX_TOKENS_POR_EVENTO:
            break
        token = token.strip(".:")
        if 3 <= len(token) <= 2048:
            valores.add(token)
    return valores


def regras_deterministicas(evento: dict[str, Any]) -> list[tuple[str, int]]:
    source_type = str(evento.get("source_type") or "generic").lower()
    event_type = str(evento.get("event_type") or "log").lower()
    severity = str(evento.get("severity") or "INFO").upper()
    regras: list[tuple[str, int]] = []
    if source_type == "windows_event_log" and event_type in {"4625", "4771", "failed_logon"}:
        regras.append(("windows_failed_auth", 55))
    if source_type == "netflow" and evento.get("destination_ip"):
        regras.append(("netflow_connection", 35))
    if source_type in {"snmp", "snmp_trap"} and severity in _SEVERIDADES_ALTAS:
        regras.append(("snmp_alert", 60))
    if severity in _SEVERIDADES_ALTAS:
        regras.append(("high_severity", 50))
    return regras


async def carregar_contexto(conn, empresa_id: str) -> dict[str, Any]:
    """Regras Sigma compiladas + playbooks ativos do tenant (uma vez por lote)."""
    sigma = []
    for r in await conn.fetch(
        "SELECT id, nome, nivel, logsource, detection FROM sigma_regras WHERE empresa_id=$1 AND ativo=true", empresa_id
    ):
        regra = dict(r)
        for campo in ("logsource", "detection"):
            if isinstance(regra[campo], str):
                regra[campo] = json.loads(regra[campo])
        try:
            sigma.append((regra, compilar_regra(regra)))
        except SigmaErro as exc:  # regra antiga gravada antes da validação
            log.warning("Regra Sigma ignorada (inválida): id=%s erro=%s", regra["id"], exc)
    playbooks = []
    for p in await conn.fetch(
        "SELECT id, nome, gatilho, acoes FROM soar_playbooks WHERE empresa_id=$1 AND ativo=true", empresa_id
    ):
        pb = dict(p)
        if isinstance(pb["acoes"], str):
            pb["acoes"] = json.loads(pb["acoes"])
        playbooks.append(pb)
    return {"sigma": sigma, "playbooks": playbooks}


async def correlacionar_lote(conn, empresa_id: str, eventos: list[tuple[int, dict[str, Any]]],
                             contexto: dict[str, Any] | None = None) -> dict[str, int]:
    """Correlaciona eventos já persistidos. Devolve contadores do lote."""
    vazio = {"correlacoes": 0, "playbooks": 0, "sigma_alertas": 0, "anomalias_ueba": 0}
    if not eventos:
        return vazio
    ctx = contexto or await carregar_contexto(conn, empresa_id)

    # CTI: uma consulta para o lote inteiro.
    tokens_por_evento = {eid: _tokens(ev) for eid, ev in eventos}
    todos: set[str] = set()
    for t in tokens_por_evento.values():
        todos |= t
        if len(todos) >= _MAX_TOKENS_POR_LOTE:
            break
    cti_por_valor: dict[str, list[dict[str, Any]]] = {}
    if todos:
        for r in await conn.fetch(
            """SELECT id, indicator_type, valor, confidence FROM cti_indicadores
                WHERE empresa_id=$1 AND lower(valor) = ANY($2::text[])
                  AND (valid_until IS NULL OR valid_until > now())""",
            empresa_id, list(todos),
        ):
            cti_por_valor.setdefault(r["valor"].lower(), []).append(dict(r))

    # UEBA: por entidade distinta do lote.
    anomalias = await avaliar_lote(conn, empresa_id, eventos)

    correlacoes_rows: list[tuple] = []
    execucoes_rows: list[tuple] = []
    sigma_rows: list[tuple] = []
    for evento_id, ev in eventos:
        regras = regras_deterministicas(ev)
        cti = [i for tok in tokens_por_evento[evento_id] for i in cti_por_valor.get(tok, [])][:20]
        if cti:
            regras.append(("cti_match", 70))
        entidade = chave_entidade(ev)
        anomalia = anomalias.get(entidade) if entidade else None
        # Uma correlação por anomalia NOVA (no evento representativo), não uma
        # por evento da entidade enquanto a anomalia da hora estiver aberta.
        if anomalia and anomalia.get("nova") and anomalia.get("evento_id") == evento_id:
            regras.append(("ueba_anomaly", 75))
        sigma_hits = [regra for regra, comp in ctx["sigma"] if comp.casa(ev)]
        for regra in sigma_hits:
            sigma_rows.append((empresa_id, regra["id"], evento_id, str(regra["nivel"]).upper(),
                               json.dumps({"regra": regra["nome"], "automatico": True})))
        if sigma_hits:
            regras.append(("sigma_match", 80))
        if not regras:
            continue

        regra, score = max(regras, key=lambda x: x[1])
        score = min(100, score + (20 if cti and regra != "cti_match" else 0) + 5 * (len(regras) - 1))
        if score < LIMIAR_CORRELACAO:
            continue
        severity = str(ev.get("severity") or "INFO").upper()
        gatilhos = {r for r, _ in regras} | {"qualquer_alto_risco"}
        playbooks = [pb for pb in ctx["playbooks"] if pb["gatilho"] in gatilhos]
        detalhes = {
            "modo": "correlacao_automatica_auditavel",
            "regra": regra,
            "regras": [r for r, _ in regras],
            "evento_id": evento_id,
            "ueba": anomalia,
            "sigma": [{"id": r["id"], "nome": r["nome"], "nivel": r["nivel"]} for r in sigma_hits],
            "cti": cti,
            "playbooks": [pb["id"] for pb in playbooks],
            "execucao_destrutiva": False,
        }
        correlacoes_rows.append((empresa_id, regra, [evento_id], severity, score, bool(cti),
                                 playbooks[0]["id"] if playbooks else None, json.dumps(detalhes, default=str)))
        for pb in playbooks:
            execucoes_rows.append((empresa_id, pb["id"],
                                   json.dumps({**detalhes, "acoes_planejadas": pb["acoes"]}, default=str)))

    if sigma_rows:
        await conn.executemany(
            """INSERT INTO sigma_alertas (empresa_id, regra_id, evento_id, severidade, evidencias)
               VALUES ($1,$2,$3,$4,$5::jsonb) ON CONFLICT (regra_id, evento_id) DO NOTHING""",
            sigma_rows,
        )
    if correlacoes_rows:
        await conn.executemany(
            """INSERT INTO siem_correlacoes (empresa_id, regra, evento_ids, severidade, score, cti_match, playbook_id, detalhes)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)""",
            correlacoes_rows,
        )
    if execucoes_rows:
        await conn.executemany(
            "INSERT INTO soar_execucoes (empresa_id, playbook_id, status, resultado) VALUES ($1,$2,'CORRELACIONADO',$3::jsonb)",
            execucoes_rows,
        )
    return {
        "correlacoes": len(correlacoes_rows),
        "playbooks": len(execucoes_rows),
        "sigma_alertas": len(sigma_rows),
        "anomalias_ueba": sum(1 for a in anomalias.values() if a.get("nova")),
    }


async def correlacionar_evento(conn, empresa_id: str, evento_id: int, evento: dict[str, Any]) -> dict[str, Any]:
    """Compatibilidade: correlaciona um único evento."""
    r = await correlacionar_lote(conn, empresa_id, [(evento_id, evento)])
    return {"correlacionado": r["correlacoes"] > 0, "playbooks": r["playbooks"], "sigma_alertas": r["sigma_alertas"]}
