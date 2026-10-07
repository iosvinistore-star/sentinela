# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Confere que o middleware de cabeçalhos de segurança (item 18 do plano de
endurecimento, ver web/security_headers.py) está de fato registrado na app
real -- tanto em respostas JSON da API quanto em respostas HTML/HTMX,
inclusive respostas de ERRO (401/404), que é onde é mais fácil esquecer de
aplicar um middleware "opcional" por engano."""
import pytest

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_cabecalhos_de_seguranca_presentes_em_resposta_json_da_api(client):
    resp = await client.get("/api/v1/incidentes")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in resp.headers


@pytest.mark.asyncio
async def test_cabecalhos_de_seguranca_presentes_em_resposta_401(client):
    """Uma rota que exige sessão e não tem uma -- o caso mais fácil de
    esquecer, já que respostas de erro às vezes tomam caminhos de código
    diferentes das de sucesso."""
    resp = await client.get("/api/v1/incidentes")
    assert resp.status_code == 401
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in resp.headers


@pytest.mark.asyncio
async def test_cabecalhos_de_seguranca_presentes_em_resposta_html(client):
    resp = await client.get("/login")
    assert resp.status_code == 200
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert "Content-Security-Policy" in resp.headers


@pytest.mark.asyncio
async def test_hsts_ausente_no_ambiente_de_teste(client):
    """ENV=test em conftest_api.py -> Settings.producao é False -- HSTS não
    deve aparecer (anunciar HSTS sem HTTPS de verdade seria enganoso)."""
    resp = await client.get("/login")
    assert "Strict-Transport-Security" not in resp.headers
