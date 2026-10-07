# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""GET /health e GET /ready -- ponto 8 do review de hardening (ver
docstring de web/routes_saude.py para o porquê de dois endpoints
separados: liveness não toca o Postgres, readiness toca)."""
import pytest

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_health_nao_exige_autenticacao(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_ready_com_banco_saudavel_retorna_ok(client):
    resp = await client.get("/ready")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_ready_com_banco_indisponivel_retorna_503(client, app_instance):
    """Simula o Postgres fora do ar (o motivo de existir de /ready, ao
    contrário de /health -- ver docstring do módulo): troca o pool por um
    objeto cujo `fetchval` sempre levanta, como aconteceria numa queda de
    conexão real."""
    class _PoolQuebrado:
        async def fetchval(self, *args, **kwargs):
            raise ConnectionRefusedError("simulado: Postgres fora do ar")

    pool_original = app_instance.state.pool
    app_instance.state.pool = _PoolQuebrado()
    try:
        resp = await client.get("/ready")
        assert resp.status_code == 503
        assert resp.json()["status"] == "not_ready"
    finally:
        app_instance.state.pool = pool_original


@pytest.mark.asyncio
async def test_ready_nao_e_afetado_por_falha_de_health(client, app_instance):
    """/health nunca toca o pool -- continua "ok" mesmo com o Postgres
    fora do ar, porque um liveness check que dependesse do banco faria um
    orquestrador reiniciar o processo em loop sem nenhum benefício (ver
    docstring do módulo)."""
    class _PoolQuebrado:
        async def fetchval(self, *args, **kwargs):
            raise ConnectionRefusedError("simulado: Postgres fora do ar")

    pool_original = app_instance.state.pool
    app_instance.state.pool = _PoolQuebrado()
    try:
        resp = await client.get("/health")
        assert resp.status_code == 200
    finally:
        app_instance.state.pool = pool_original
