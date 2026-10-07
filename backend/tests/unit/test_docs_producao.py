# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Ponto 5 do review de hardening: /docs, /redoc e /openapi.json precisam
ficar DESLIGADOS quando ENV=production (ver criar_app() em main.py) --
reduz superfície de ataque e esvazia a exceção de CSP que essas rotas
exigiam. Chama `criar_app()` diretamente (não usa o singleton
`sentinela.main.app`, que outros testes já importaram com ENV=test) --
não precisa de Postgres: só o lifespan (nunca disparado aqui) toca o
banco.
"""

import pytest

from sentinela.main import criar_app

_ENV_OBRIGATORIAS = {
    "DATABASE_URL": "postgresql://user:pw@host/db",
    "JWT_SECRET": "segredo-de-teste-bem-longo",
}


@pytest.fixture
def env_producao(monkeypatch):
    for k, v in _ENV_OBRIGATORIAS.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("SENTINELA_URL_BASE_PUBLICA", "https://soc.exemplo.com")
    monkeypatch.setenv("SENTINELA_ALLOWED_HOSTS", "soc.exemplo.com")


@pytest.fixture
def env_dev(monkeypatch):
    for k, v in _ENV_OBRIGATORIAS.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("ENV", "development")
    monkeypatch.delenv("SENTINELA_URL_BASE_PUBLICA", raising=False)
    monkeypatch.delenv("SENTINELA_ALLOWED_HOSTS", raising=False)


def test_docs_desligadas_em_producao(env_producao):
    app = criar_app()
    assert app.docs_url is None
    assert app.redoc_url is None
    assert app.openapi_url is None
    caminhos = {getattr(r, "path", None) for r in app.routes}
    assert "/docs" not in caminhos
    assert "/redoc" not in caminhos
    assert "/openapi.json" not in caminhos


def test_docs_ligadas_fora_de_producao(env_dev):
    app = criar_app()
    assert app.docs_url == "/docs"
    assert app.redoc_url == "/redoc"
    assert app.openapi_url == "/openapi.json"
    caminhos = {getattr(r, "path", None) for r in app.routes}
    assert "/docs" in caminhos
    assert "/redoc" in caminhos
    assert "/openapi.json" in caminhos
