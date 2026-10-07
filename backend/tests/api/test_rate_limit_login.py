# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Testes do rate limiting aplicado a /api/v1/auth/login (ver auth/rate_limit.py
e sua fiação em api/v1/auth.py). O `_limitador_login_limpo` autouse em
tests/api/conftest.py garante que cada teste começa com um contador zerado."""
import pytest

from tests.api.conftest_api import logar

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_login_bloqueia_apos_tentativas_erradas_seguidas(client, usuario_de_teste):
    for _ in range(5):
        resp = await client.post(
            "/api/v1/auth/login", json={"email": usuario_de_teste["email"], "senha": "senha-errada"},
        )
        assert resp.status_code == 401

    resp_bloqueado = await client.post(
        "/api/v1/auth/login", json={"email": usuario_de_teste["email"], "senha": "senha-errada"},
    )
    assert resp_bloqueado.status_code == 429
    assert "Retry-After" in resp_bloqueado.headers

    # mesmo com a senha CERTA, continua bloqueado -- o bloqueio é por IP,
    # não sabe (nem pode saber) que dessa vez a senha bateria.
    resp_com_senha_certa = await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    assert resp_com_senha_certa.status_code == 429


@pytest.mark.asyncio
async def test_login_bem_sucedido_reseta_o_contador_de_falhas(client, usuario_de_teste):
    for _ in range(3):
        resp = await client.post(
            "/api/v1/auth/login", json={"email": usuario_de_teste["email"], "senha": "senha-errada"},
        )
        assert resp.status_code == 401

    assert (await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])).status_code == 200
    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})

    # contador zerado pelo login bem-sucedido -- mais 3 erros ainda não bloqueiam
    for _ in range(3):
        resp = await client.post(
            "/api/v1/auth/login", json={"email": usuario_de_teste["email"], "senha": "senha-errada"},
        )
        assert resp.status_code == 401
