# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Syslog, modelo de evento e score UEBA -- V8.2."""
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from sentinela.siem.correlacao_siem import regras_deterministicas
from sentinela.siem.modelos import EventoSIEMEntrada
from sentinela.siem.servico import normalizar_syslog
from sentinela.siem.ueba import calcular_score, chave_entidade


def test_syslog_rfc3164_hostname_e_timestamp():
    """Bug V8.1: o hostname gravado era o dia do mês ('11')."""
    e = normalizar_syslog("<34>Oct 11 22:14:15 mymachine su: 'su root' failed", "syslog-udp", "10.0.0.5")
    assert e["hostname"] == "mymachine"
    assert e["message"].startswith("su:")
    assert (e["timestamp"].month, e["timestamp"].day, e["timestamp"].hour) == (10, 11, 22)
    assert e["severity"] == "CRITICAL"


def test_syslog_rfc5424():
    e = normalizar_syslog("<165>1 2026-09-22T10:00:00Z fw01 app 1 ID47 - pacote bloqueado", "x")
    assert e["hostname"] == "fw01"
    assert e["message"] == "pacote bloqueado"
    assert e["timestamp"] == datetime(2026, 9, 22, 10, 0, tzinfo=timezone.utc)


def test_evento_rejeita_ip_invalido_e_normaliza():
    with pytest.raises(ValidationError):
        EventoSIEMEntrada(source="x", message="m", source_ip="999.1.1.1")
    e = EventoSIEMEntrada(source="x", message="m", source_ip=" 10.0.0.1 ", destination_ip="")
    assert e.source_ip == "10.0.0.1" and e.destination_ip is None


def test_timestamp_sem_fuso_vira_utc():
    e = EventoSIEMEntrada(source="x", message="m", timestamp="2026-09-22T10:00:00")
    assert e.timestamp.tzinfo is not None


def test_ueba_sem_pico_nao_e_anomalia_mesmo_com_severidade_alta():
    """Severidade sozinha não é comportamento anômalo."""
    score, motivos = calcular_score(atual=25, media=20, severidade="CRITICAL", falha_auth=True)
    assert motivos == [] and score == 0


def test_ueba_pico_por_entidade():
    score, motivos = calcular_score(atual=200, media=10, severidade="WARNING", falha_auth=True)
    assert motivos and score >= 60


def test_ueba_entidade_nova_exige_volume_muito_maior():
    assert calcular_score(atual=50, media=0, severidade="INFO", falha_auth=False)[1] == []
    assert calcular_score(atual=500, media=0, severidade="INFO", falha_auth=False)[1] != []


def test_ueba_volume_minimo():
    assert calcular_score(atual=5, media=0, severidade="INFO", falha_auth=False)[1] == []


def test_chave_entidade_prioridade():
    assert chave_entidade({"username": "a", "source_ip": "1.1.1.1"}) == ("usuario", "a")
    assert chave_entidade({"source_ip": "1.1.1.1", "hostname": "h"}) == ("ip", "1.1.1.1")
    assert chave_entidade({}) is None


def test_snmp_trap_dispara_regra_snmp():
    """Bug V8.1: source_type 'snmp_trap' (usado pelo Agent) nunca casava com a regra 'snmp'."""
    assert ("snmp_alert", 60) in regras_deterministicas({"source_type": "snmp_trap", "severity": "CRITICAL"})
