# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testes do middleware de cabeçalhos de segurança (web/security_headers.py)
-- item 18 do plano de endurecimento pós-auditoria. Roda contra uma app
Starlette minúscula e isolada (sem Postgres, sem lifespan) -- o objetivo
aqui é só o comportamento do middleware em si; a cobertura de que ele está
de fato registrado na app real vem de tests/api/test_security_headers_api.py.
"""
import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from sentinela.web.security_headers import CabecalhosDeSegurancaMiddleware


async def _rota_ok(request):
    return PlainTextResponse("ok")


def _montar_app(producao: bool) -> Starlette:
    app = Starlette(routes=[Route("/qualquer", _rota_ok), Route("/docs", _rota_ok)])
    app.add_middleware(CabecalhosDeSegurancaMiddleware, producao=producao)
    return app


@pytest.fixture
def cliente_dev():
    return TestClient(_montar_app(producao=False))


@pytest.fixture
def cliente_producao():
    return TestClient(_montar_app(producao=True))


def test_cabecalhos_basicos_presentes_em_toda_resposta(cliente_dev):
    resp = cliente_dev.get("/qualquer")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "geolocation=()" in resp.headers["Permissions-Policy"]


def test_csp_presente_e_restritiva(cliente_dev):
    resp = cliente_dev.get("/qualquer")
    csp = resp.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "'unsafe-inline'" not in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp


def test_csp_fica_de_fora_das_rotas_de_documentacao_da_api(cliente_dev):
    """/docs (Swagger UI) carrega assets de CDN -- ver comentário em
    security_headers.py._CAMINHOS_SEM_CSP. Os outros cabeçalhos continuam
    valendo mesmo lá."""
    resp = cliente_dev.get("/docs")
    assert "Content-Security-Policy" not in resp.headers
    assert resp.headers["X-Frame-Options"] == "DENY"


def test_hsts_ausente_fora_de_producao(cliente_dev):
    resp = cliente_dev.get("/qualquer")
    assert "Strict-Transport-Security" not in resp.headers


def test_hsts_presente_em_producao(cliente_producao):
    resp = cliente_producao.get("/qualquer")
    assert resp.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"
