# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""SENTINELA_COOKIE_SEGURO: produção sem HTTPS (acesso por IP) precisa de cookie sem Secure."""
import pytest

from sentinela.config import Settings


@pytest.mark.parametrize("env,forcado,esperado", [
    ("production", "", True),
    ("development", "", False),
    ("production", "false", False),
    ("development", "true", True),
    ("production", " FALSE ", False),
])
def test_cookie_seguro(monkeypatch, env, forcado, esperado):
    monkeypatch.setenv("ENV", env)
    monkeypatch.setenv("SENTINELA_COOKIE_SEGURO", forcado)
    assert Settings().cookie_seguro is esperado
