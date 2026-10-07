# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Testes de web/routes_auth.py:_destino_seguro -- proteção contra open
redirect via o parâmetro `proxima` do login (ver o docstring da função)."""
from sentinela.web.routes_auth import _destino_seguro


def test_aceita_caminho_local_absoluto():
    assert _destino_seguro("/incidentes") == "/incidentes"


def test_none_ou_vazio_vira_raiz():
    assert _destino_seguro(None) == "/"
    assert _destino_seguro("") == "/"


def test_caminho_relativo_sem_barra_vira_raiz():
    assert _destino_seguro("incidentes") == "/"


def test_rejeita_protocol_relative_com_barra_dupla():
    assert _destino_seguro("//evil.example") == "/"
    assert _destino_seguro("//evil.example/phishing") == "/"


def test_rejeita_variante_com_barra_invertida():
    """/\\evil.example: não começa com "//" literalmente, mas todo
    navegador normaliza "\\" pra "/" ao interpretar uma URL http(s) --
    então isso vira um redirect pra outro host igualzinho a //evil.example."""
    assert _destino_seguro("/\\evil.example") == "/"
    assert _destino_seguro("/\\\\evil.example") == "/"
    assert _destino_seguro("/\\/evil.example") == "/"
