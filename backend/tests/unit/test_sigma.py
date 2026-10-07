# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Avaliador Sigma (siem/sigma.py) -- V8.2."""
import pytest

from sentinela.siem.sigma import SigmaErro, avaliar_sigma, compilar_regra

EV_WIN = {"source_type": "windows_event_log", "event_type": "4625", "username": "admin",
          "source_ip": "10.0.0.5", "hostname": "DC01", "message": "powershell.exe -enc AAAA", "severity": "WARNING"}


def _regra(detection, product=None):
    r = {"detection": detection}
    if product:
        r["logsource"] = {"product": product}
    return r


def test_selecao_simples_com_nome_de_campo_sigma():
    assert avaliar_sigma(_regra({"selection": {"EventID": 4625}}, "windows"), EV_WIN)


def test_filtro_de_exclusao_e_respeitado():
    """Bug V8.1: 'selection and not filter' era avaliado como só 'selection'."""
    r = _regra({"selection": {"EventID": 4625}, "filter": {"TargetUserName": "admin"},
                "condition": "selection and not filter"})
    assert avaliar_sigma(r, EV_WIN) is False
    assert avaliar_sigma(r, {**EV_WIN, "username": "outro"}) is True


@pytest.mark.parametrize("chave,valor,esperado", [
    ("message|contains", "powershell", True),
    ("message|startswith", "powershell", True),
    ("message|endswith", "AAAA", True),
    ("message|contains", "mimikatz", False),
    ("message|re", r"-enc\s+[A-Z]+", True),
    ("IpAddress|cidr", "10.0.0.0/8", True),
    ("IpAddress|cidr", "192.168.0.0/16", False),
])
def test_modificadores(chave, valor, esperado):
    assert avaliar_sigma(_regra({"selection": {chave: valor}}), EV_WIN) is esperado


def test_contains_all():
    assert avaliar_sigma(_regra({"sel": {"message|contains|all": ["powershell", "-enc"]}, "condition": "sel"}), EV_WIN)
    assert not avaliar_sigma(_regra({"sel": {"message|contains|all": ["powershell", "xyz"]}, "condition": "sel"}), EV_WIN)


def test_curinga_no_meio_e_case_insensitive():
    assert avaliar_sigma(_regra({"selection": {"message": "POWERSHELL*-enc*"}}), EV_WIN)


def test_lista_de_valores_e_or():
    assert avaliar_sigma(_regra({"selection": {"EventID": [4624, 4625]}}), EV_WIN)


def test_one_of_e_all_of_them():
    det = {"sel_a": {"EventID": 4625}, "sel_b": {"User": "ninguem"}}
    assert avaliar_sigma(_regra({**det, "condition": "1 of sel_*"}), EV_WIN)
    assert not avaliar_sigma(_regra({**det, "condition": "all of them"}), EV_WIN)


def test_parenteses_e_precedencia():
    det = {"a": {"EventID": 4625}, "b": {"User": "x"}, "c": {"Computer": "DC01"}}
    assert avaliar_sigma(_regra({**det, "condition": "a and (b or c)"}), EV_WIN)
    assert not avaliar_sigma(_regra({**det, "condition": "a and (b or not c)"}), EV_WIN)


def test_keywords():
    assert avaliar_sigma(_regra({"keywords": ["mimikatz", "-enc"], "condition": "keywords"}), EV_WIN)


def test_logsource_linux_casa_unix_log():
    """Bug V8.1: product=linux não casava com source_type=unix_log."""
    r = _regra({"selection": {"message|contains": "sudo"}}, "linux")
    assert avaliar_sigma(r, {"source_type": "unix_log", "message": "sudo: pam_unix"})
    assert not avaliar_sigma(r, {"source_type": "windows_event_log", "message": "sudo"})


def test_campo_null():
    assert avaliar_sigma(_regra({"selection": {"EventID": 4625, "DestinationIp": None}}), EV_WIN)


@pytest.mark.parametrize("detection", [
    {"selection": {"message|base64offset|contains": "x"}},
    {"selection": {"EventID": 1}, "condition": "selection | count() by User > 5"},
    {"selection": {"EventID": 1}, "condition": "selection and inexistente"},
    {"selection": {"EventID": 1}, "condition": "selection and"},
    {"selection": {"message|re": "("}},
    {"selection": {"EventID": 1}, "timeframe": "5m"},
    {},
])
def test_recursos_nao_suportados_sao_rejeitados(detection):
    with pytest.raises(SigmaErro):
        compilar_regra({"detection": detection})


def test_regra_invalida_nunca_casa():
    assert avaliar_sigma({"detection": {"selection": {"x|wide": "a"}}}, EV_WIN) is False


def test_mensagem_de_agregacao_e_explicita():
    with pytest.raises(SigmaErro, match="agregações"):
        compilar_regra({"detection": {"sel": {"EventID": 4625}, "condition": "sel | count() by User > 5"}})
