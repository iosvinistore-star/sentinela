# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testes de /api/v1/auth/* contra a app FastAPI completa (httpx.AsyncClient +
ASGITransport), incluindo o cookie de sessão e o header CSRF.
"""
import pytest

from tests.api.conftest_api import logar

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_login_com_credenciais_corretas_seta_cookie_e_retorna_usuario(client, usuario_de_teste):
    resp = await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    assert resp.status_code == 200
    corpo = resp.json()
    assert corpo["usuario"]["email"] == usuario_de_teste["email"]
    assert corpo["usuario"]["papel"] == "admin"
    assert "sentinela_session" in resp.cookies


@pytest.mark.asyncio
async def test_login_com_senha_errada_e_401(client, usuario_de_teste):
    resp = await logar(client, usuario_de_teste["email"], "senha-errada")
    assert resp.status_code == 401
    assert "sentinela_session" not in resp.cookies


@pytest.mark.asyncio
async def test_login_com_email_inexistente_e_401(client):
    resp = await logar(client, "nao-existe@example.com", "qualquer")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_me_sem_sessao_e_401(client):
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_me_com_sessao_retorna_usuario(client, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code == 200
    assert resp.json()["usuario"]["email"] == usuario_de_teste["email"]


@pytest.mark.asyncio
async def test_logout_limpa_a_sessao(client, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    resp_logout = await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})
    assert resp_logout.status_code == 200

    resp_me = await client.get("/api/v1/auth/me")
    assert resp_me.status_code == 401


@pytest.mark.asyncio
async def test_logout_sem_header_csrf_e_recusado(client, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    resp = await client.post("/api/v1/auth/logout")  # sem X-Sentinela-CSRF
    assert resp.status_code == 403

    # sessão continua válida -- o logout não aconteceu
    resp_me = await client.get("/api/v1/auth/me")
    assert resp_me.status_code == 200


@pytest.mark.asyncio
async def test_superadmin_loga_e_me_reflete_papel_superadmin(client, superadmin_de_teste):
    resp = await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    assert resp.status_code == 200
    assert resp.json()["usuario"]["papel"] == "superadmin"
    assert resp.json()["usuario"]["empresa_id"] is None


@pytest.mark.asyncio
async def test_login_de_superadmin_inclui_tv_no_payload_de_sessao(client, superadmin_de_teste):
    """Ponto 6 do review de hardening -- "tv" (token_version) não pode mais
    ficar ausente para superadmin (ver migrations/0013_token_version_superadmin.sql);
    sem essa claim, auth/dependencies.py:conexao_superadmin derrubaria
    QUALQUER sessão de superadmin com 401, já que compara `linha["token_version"]`
    contra `su.get("tv")`, que seria sempre None."""
    resp = await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    assert resp.status_code == 200
    assert resp.json()["usuario"]["tv"] == 1
