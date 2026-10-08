# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Rotação do refresh token (POST /api/v1/auth/refresh): rotação normal, token desconhecido e, principalmente,
a detecção de REUSO -- a revogação da família e o aumento do token_version precisam ficar GRAVADOS mesmo que a
resposta seja um 401 (regressão: levantar a exceção de dentro da transação desfazia a revogação).
"""
import httpx
import pytest

from tests.api.conftest_api import logar

CSRF = {"X-Sentinela-CSRF": "1"}
NOME_REFRESH = "sentinela_refresh"


def _cliente_sem_jar(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def _refresh(app, token):
    async with _cliente_sem_jar(app) as c:
        return await c.post("/api/v1/auth/refresh", headers={**CSRF, "Cookie": f"{NOME_REFRESH}={token}"})


@pytest.mark.asyncio
async def test_refresh_rotaciona_e_devolve_nova_sessao(client, app_instance, usuario_de_teste):
    r = await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    assert r.status_code == 200
    token1 = client.cookies.get(NOME_REFRESH)
    assert token1

    r = await _refresh(app_instance, token1)
    assert r.status_code == 200, r.text
    corpo = r.json()
    assert corpo["ok"] is True and corpo["usuario"]["email"] == usuario_de_teste["email"]
    token2 = r.cookies.get(NOME_REFRESH)
    assert token2 and token2 != token1


@pytest.mark.asyncio
async def test_refresh_sem_cookie_ou_desconhecido_e_401(client, app_instance):
    async with _cliente_sem_jar(app_instance) as c:
        assert (await c.post("/api/v1/auth/refresh", headers=CSRF)).status_code == 401
    assert (await _refresh(app_instance, "token-que-nao-existe")).status_code == 401


@pytest.mark.asyncio
async def test_reuso_do_refresh_revoga_a_familia_e_derruba_a_sessao(client, app_instance, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    token1 = client.cookies.get(NOME_REFRESH)

    r = await _refresh(app_instance, token1)
    assert r.status_code == 200
    token2 = r.cookies.get(NOME_REFRESH)

    # reapresentar o token JÁ USADO = possível roubo
    assert (await _refresh(app_instance, token1)).status_code == 401

    # a revogação foi gravada: o token legítimo mais novo da MESMA família também deixou de valer ...
    assert (await _refresh(app_instance, token2)).status_code == 401

    # ... e o token_version da conta subiu, então o cookie de sessão que o cliente tinha não vale mais
    r = await client.get("/api/v1/dashboard")
    assert r.status_code == 401
