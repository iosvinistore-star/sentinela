# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Testes de core/metricas.py -- Fase E / E1, ver
ARQUITETURA_OBSERVABILIDADE.md §2.2/§2.3."""
from sentinela.core.metricas import (
    ROTA_DESCONHECIDA,
    definir_versao_aplicacao,
    gerar_metricas,
    registrar_requisicao,
    resolver_rota_para_metrica,
)


def test_registrar_requisicao_aparece_na_saida_prometheus():
    registrar_requisicao(metodo="GET", rota="/teste/unico-para-este-teste", status=200, duracao_segundos=0.01)
    saida = gerar_metricas().decode("utf-8")
    assert 'metodo="GET"' in saida
    assert 'rota="/teste/unico-para-este-teste"' in saida
    assert 'status="200"' in saida


def test_registrar_requisicao_incrementa_contador_a_cada_chamada():
    rota = "/teste/contagem-incremental"
    registrar_requisicao(metodo="POST", rota=rota, status=201, duracao_segundos=0.02)
    registrar_requisicao(metodo="POST", rota=rota, status=201, duracao_segundos=0.03)
    saida = gerar_metricas().decode("utf-8")
    linha_contador = next(
        linha for linha in saida.splitlines()
        if linha.startswith("sentinela_http_requisicoes_total") and rota in linha and 'status="201"' in linha
    )
    valor = float(linha_contador.rsplit(" ", 1)[-1])
    assert valor >= 2.0


class _RotaFalsa:
    def __init__(self, path):
        self.path = path


class _RequestFalso:
    def __init__(self, rota=None):
        self.scope = {"route": rota} if rota is not None else {}


def test_resolver_rota_para_metrica_usa_template_quando_rota_resolvida():
    request = _RequestFalso(rota=_RotaFalsa("/api/v1/agentes/{agente_id}"))
    assert resolver_rota_para_metrica(request) == "/api/v1/agentes/{agente_id}"


def test_resolver_rota_para_metrica_cai_para_desconhecida_sem_rota_resolvida():
    request = _RequestFalso(rota=None)
    assert resolver_rota_para_metrica(request) == ROTA_DESCONHECIDA


def test_definir_versao_aplicacao_aparece_na_saida():
    definir_versao_aplicacao("9.9.9-teste")
    saida = gerar_metricas().decode("utf-8")
    assert 'versao="9.9.9-teste"' in saida
