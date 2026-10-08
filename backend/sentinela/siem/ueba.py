# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""UEBA heurística: pico de volume por entidade contra a própria linha de base.

O que mudou na V8.2 e por quê:

* Antes, a contagem da ÚLTIMA HORA de UMA entidade era comparada com a
  média horária do TENANT INTEIRO. Em qualquer tenant com mais de uma
  entidade essa razão é < 1 quase sempre -- o detector praticamente nunca
  disparava por volume, e quando disparava era por severidade (que não é
  comportamento). Agora a linha de base é a média horária da PRÓPRIA
  entidade nas 24h anteriores.
* Antes, cada evento ingerido fazia um ``avg`` sobre as últimas 24h do
  tenant (a 4.000 EPS, ~345 milhões de linhas por consulta, por evento).
  Agora a avaliação é por LOTE: uma consulta indexada por entidade
  distinta do lote, com teto de entidades por lote.
* Antes, uma entidade em pico gravava uma anomalia POR EVENTO. Agora há no
  máximo uma anomalia por entidade por hora (índice único + ON CONFLICT).

Isto continua sendo heurística estatística simples e auditável -- não é
ML. A matriz do edital deve descrevê-lo assim.
"""
from __future__ import annotations

import os
from typing import Any

from sentinela.repositories.siem import EventoSiemRepositorio, UebaRepositorio

__all__ = ["chave_entidade", "avaliar_lote", "avaliar_anomalia", "calcular_score"]

SEVERIDADE_PESO = {"DEBUG": 0, "INFO": 0, "NOTICE": 5, "LOW": 10, "WARNING": 25, "WARN": 25, "MEDIUM": 35,
                   "ERROR": 40, "HIGH": 60, "CRITICAL": 90, "ALERT": 90, "EMERGENCY": 100}
EVENTOS_FALHA_AUTH = {"failed_logon", "4625", "4771", "auth_failure"}

RAZAO_MINIMA = float(os.getenv("SENTINELA_UEBA_RAZAO_MINIMA", "3.0"))
VOLUME_MINIMO = int(os.getenv("SENTINELA_UEBA_VOLUME_MINIMO", "20"))
FATOR_ENTIDADE_NOVA = int(os.getenv("SENTINELA_UEBA_FATOR_ENTIDADE_NOVA", "10"))
MAX_ENTIDADES_POR_LOTE = int(os.getenv("SENTINELA_UEBA_MAX_ENTIDADES_LOTE", "200"))

def chave_entidade(evento: dict[str, Any]) -> tuple[str, str] | None:
    """(tipo, valor) da entidade principal do evento, ou None se não houver."""
    if evento.get("username"):
        return "usuario", str(evento["username"])
    if evento.get("source_ip"):
        return "ip", str(evento["source_ip"])
    if evento.get("hostname"):
        return "host", str(evento["hostname"])
    return None


def calcular_score(atual: int, media: float, severidade: str, falha_auth: bool) -> tuple[float, list[str]]:
    """Score 0..100 e motivos. Só há anomalia se houver pico de volume."""
    base = max(media, 1.0)
    razao = atual / base
    motivos: list[str] = []
    if atual < VOLUME_MINIMO or razao < RAZAO_MINIMA:
        return 0.0, motivos
    # Entidade sem nenhum histórico nas 24h anteriores: qualquer volume é
    # "infinitas vezes" a linha de base. Sem esta trava, toda entidade nova
    # (usuário/IP/host visto pela primeira vez) virava anomalia -- no
    # benchmark da V8.2 isso gerou 16 mil correlações em 30 s.
    if media <= 0 and atual < VOLUME_MINIMO * FATOR_ENTIDADE_NOVA:
        return 0.0, motivos
    motivos.append(f"volume {razao:.1f}x acima da linha de base da entidade")
    score = min(60.0, 30.0 + (razao - RAZAO_MINIMA) * 5.0)
    peso = SEVERIDADE_PESO.get(str(severidade or "INFO").upper(), 0)
    if peso >= 60:
        motivos.append("severidade elevada")
    score += peso * 0.25
    if falha_auth:
        motivos.append("falhas de autenticação")
        score += 15.0
    return round(min(score, 100.0), 1), motivos


async def avaliar_lote(sessao, empresa_id: str, eventos: list[tuple[int, dict[str, Any]]]) -> dict[tuple[str, str], dict[str, Any]]:
    """Avalia as entidades de um lote já persistido.

    Devolve {(tipo, valor): anomalia} só para entidades anômalas. A anomalia é
    gravada (no máximo uma por entidade por hora) e devolvida mesmo se já
    existia, para que a correlação dos eventos do lote a enxergue.
    """
    por_entidade: dict[tuple[str, str], dict[str, Any]] = {}
    for evento_id, ev in eventos:
        chave = chave_entidade(ev)
        if chave is None:
            continue
        agg = por_entidade.get(chave)
        if agg is None:
            if len(por_entidade) >= MAX_ENTIDADES_POR_LOTE:
                continue
            agg = por_entidade[chave] = {"evento_id": evento_id, "severidade": "INFO", "falha_auth": False}
        if SEVERIDADE_PESO.get(str(ev.get("severity") or "INFO").upper(), 0) > SEVERIDADE_PESO.get(agg["severidade"], 0):
            agg["severidade"] = str(ev.get("severity")).upper()
            agg["evento_id"] = evento_id
        if str(ev.get("event_type") or "").lower() in EVENTOS_FALHA_AUTH:
            agg["falha_auth"] = True

    eventos_repo = EventoSiemRepositorio(sessao)
    ueba_repo = UebaRepositorio(sessao)
    anomalias: dict[tuple[str, str], dict[str, Any]] = {}
    for (tipo, valor), agg in sorted(por_entidade.items()):
        atual, media = await eventos_repo.volume_da_entidade(empresa_id, tipo, valor)
        score, motivos = calcular_score(atual, media, agg["severidade"], agg["falha_auth"])
        if not motivos:
            continue
        chave_txt = f"{tipo}:{valor}"
        evidencias = {"total_hora": atual, "media_horaria_24h": round(media, 2), "tipo": tipo,
                      "severidade_max": agg["severidade"], "falha_auth": agg["falha_auth"]}
        registro = await ueba_repo.registrar_anomalia(
            empresa_id, agg["evento_id"], chave_txt, tipo, score, "; ".join(motivos), evidencias,
        )
        anomalias[(tipo, valor)] = {"id": registro["id"], "evento_id": agg["evento_id"], "score": float(registro["score"]),
                                    "motivo": registro["motivo"], "nova": bool(registro["nova"]), "chave": chave_txt}
    return anomalias


async def avaliar_anomalia(sessao, empresa_id: str, evento_id: int, evento: dict[str, Any]) -> dict[str, Any] | None:
    """Compatibilidade com a API anterior (avaliação de um único evento)."""
    resultado = await avaliar_lote(sessao, empresa_id, [(evento_id, evento)])
    chave = chave_entidade(evento)
    return resultado.get(chave) if chave else None
