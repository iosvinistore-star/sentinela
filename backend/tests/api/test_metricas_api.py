# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""GET /metrics -- Fase E / E1, ver ARQUITETURA_OBSERVABILIDADE.md §2.4 e
docstring de web/routes_metricas.py."""
import pytest

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_metrics_retorna_404_quando_token_nao_configurado(client, app_instance):
    """Default (`SENTINELA_METRICS_TOKEN` vazio, ver config.py) -- a rota
    nem existe operacionalmente, mesmo padrão de feature-flag de
    agentes_endpoint_habilitado."""
    assert app_instance.state.settings.metrics_token == ""
    resp = await client.get("/metrics")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_metrics_retorna_401_sem_header_quando_token_configurado(client, app_instance):
    token_original = app_instance.state.settings.metrics_token
    app_instance.state.settings.metrics_token = "segredo-de-teste"
    try:
        resp = await client.get("/metrics")
        assert resp.status_code == 401
    finally:
        app_instance.state.settings.metrics_token = token_original


@pytest.mark.asyncio
async def test_metrics_retorna_401_com_header_errado(client, app_instance):
    token_original = app_instance.state.settings.metrics_token
    app_instance.state.settings.metrics_token = "segredo-de-teste"
    try:
        resp = await client.get("/metrics", headers={"X-Metrics-Token": "valor-errado"})
        assert resp.status_code == 401
    finally:
        app_instance.state.settings.metrics_token = token_original


@pytest.mark.asyncio
async def test_metrics_retorna_200_com_header_correto_e_formato_prometheus(client, app_instance):
    token_original = app_instance.state.settings.metrics_token
    app_instance.state.settings.metrics_token = "segredo-de-teste"
    try:
        # Gera pelo menos uma requisição anterior para garantir que a
        # métrica de contagem tenha uma série já registrada.
        await client.get("/health")
        resp = await client.get("/metrics", headers={"X-Metrics-Token": "segredo-de-teste"})
        assert resp.status_code == 200
        corpo = resp.text
        assert "sentinela_http_requisicoes_total" in corpo
        assert "sentinela_http_requisicao_duracao_segundos" in corpo
        assert "sentinela_app_info" in corpo
        # A rota /health tem template fixo (sem parâmetro), então o rótulo
        # deveria ser o path exato, não "desconhecida".
        assert 'rota="/health"' in corpo
    finally:
        app_instance.state.settings.metrics_token = token_original
