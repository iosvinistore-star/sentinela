# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testes de regressão para a Crítica real nº 1 (a mais grave): antes desta
correção, `empresas.status` era gravado no banco mas não tinha NENHUM
efeito prático -- login funcionava e sessões abertas continuavam com
acesso total a uma empresa suspensa/cancelada até o JWT expirar sozinho.

Cobre os dois frontends (API JSON usada pelo React e rotas HTML/HTMX) e os
dois pontos de enforcement: no login (auth/login.py) e em tempo real, a
cada requisição tenant-scoped (auth/dependencies.py:conexao_tenant e
web/deps.py:conexao_tenant_web) -- inclusive o caso mais importante: uma
sessão já aberta ANTES da suspensão perde acesso na próxima requisição,
sem precisar de novo login.
"""
import httpx
import pytest

from tests.api.conftest_api import logar

pytestmark = pytest.mark.integration


async def _suspender(client, empresa_id):
    return await client.patch(
        f"/api/v1/admin/empresas/{empresa_id}", json={"status": "suspensa"}, headers={"X-Sentinela-CSRF": "1"},
    )


async def _reativar(client, empresa_id):
    return await client.patch(
        f"/api/v1/admin/empresas/{empresa_id}", json={"status": "ativa"}, headers={"X-Sentinela-CSRF": "1"},
    )


@pytest.mark.asyncio
async def test_status_invalido_e_rejeitado_com_422(client, superadmin_de_teste, usuario_de_teste):
    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    resp = await client.patch(
        f"/api/v1/admin/empresas/{usuario_de_teste['empresa_id']}",
        json={"status": "nao_existe"}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_empresa_suspensa_bloqueia_novo_login_via_api(client, superadmin_de_teste, usuario_de_teste):
    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    assert (await _suspender(client, usuario_de_teste["empresa_id"])).status_code == 200
    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})

    resp_login = await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    assert resp_login.status_code == 403
    assert "sentinela_session" not in resp_login.cookies


@pytest.mark.asyncio
async def test_empresa_suspensa_bloqueia_novo_login_via_web_form(client, superadmin_de_teste, usuario_de_teste):
    await client.post(
        "/login", data={"email": superadmin_de_teste["email"], "senha": superadmin_de_teste["senha"]},
    )
    assert (await _suspender(client, usuario_de_teste["empresa_id"])).status_code == 200
    await client.post("/logout", headers={"X-Sentinela-CSRF": "1"})

    resp_login = await client.post(
        "/login", data={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]},
    )
    assert resp_login.status_code == 403
    assert "suspensa" in resp_login.text
    assert "sentinela_session" not in resp_login.cookies


@pytest.mark.asyncio
async def test_suspensao_revoga_sessao_ja_aberta_em_tempo_real_via_api(app_instance, superadmin_de_teste, usuario_de_teste):
    """
    O caso mais importante: o usuário já está logado (cookie válido, JWT
    ainda dentro da validade) QUANDO o superadmin suspende a empresa. Sem
    a checagem em tempo real em `conexao_tenant`, essa sessão continuaria
    acessando tudo normalmente até o cookie expirar sozinho.
    """
    transport = httpx.ASGITransport(app=app_instance)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as cliente_usuario, \
            httpx.AsyncClient(transport=transport, base_url="http://test") as cliente_super:
        await logar(cliente_usuario, usuario_de_teste["email"], usuario_de_teste["senha"])
        resp_antes = await cliente_usuario.get("/api/v1/incidentes")
        assert resp_antes.status_code == 200

        await logar(cliente_super, superadmin_de_teste["email"], superadmin_de_teste["senha"])
        assert (await _suspender(cliente_super, usuario_de_teste["empresa_id"])).status_code == 200

        # mesmo cookie de antes -- nenhum novo login aconteceu.
        resp_depois = await cliente_usuario.get("/api/v1/incidentes")
        assert resp_depois.status_code == 403

        # reativar restaura o acesso na mesma sessão, sem precisar logar de novo.
        assert (await _reativar(cliente_super, usuario_de_teste["empresa_id"])).status_code == 200
        resp_reativado = await cliente_usuario.get("/api/v1/incidentes")
        assert resp_reativado.status_code == 200


@pytest.mark.asyncio
async def test_suspensao_revoga_sessao_ja_aberta_em_tempo_real_via_htmx(app_instance, superadmin_de_teste, usuario_de_teste):
    """Mesmo cenário acima, mas para o frontend HTML/HTMX -- deve redirecionar
    para /login (303) em vez de devolver um 403 JSON cru."""
    transport = httpx.ASGITransport(app=app_instance)
    async with httpx.AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as cliente_usuario, \
            httpx.AsyncClient(transport=transport, base_url="http://test") as cliente_super:
        await cliente_usuario.post(
            "/login", data={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]},
        )
        resp_antes = await cliente_usuario.get("/incidentes")
        assert resp_antes.status_code == 200

        await logar(cliente_super, superadmin_de_teste["email"], superadmin_de_teste["senha"])
        assert (await _suspender(cliente_super, usuario_de_teste["empresa_id"])).status_code == 200

        resp_depois = await cliente_usuario.get("/incidentes")
        assert resp_depois.status_code == 303
        assert resp_depois.headers["location"].startswith("/login?erro=empresa_suspensa")
        assert "sentinela_session" not in cliente_usuario.cookies


@pytest.mark.asyncio
async def test_superadmin_muda_status_via_botao_htmx(client, superadmin_de_teste, usuario_de_teste):
    """Fix 2: a UI (HTMX) agora tem um controle de verdade para mudar o status -- não existia antes."""
    await client.post(
        "/login", data={"email": superadmin_de_teste["email"], "senha": superadmin_de_teste["senha"]},
    )
    resp = await client.post(
        f"/admin/empresas/{usuario_de_teste['empresa_id']}/status",
        data={"status": "suspensa"}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 200
    assert 'id="tabela-empresas"' in resp.text
    assert "selected" in resp.text

    # devolve pro estado normal para não vazar efeito colateral entre testes
    resp2 = await client.post(
        f"/admin/empresas/{usuario_de_teste['empresa_id']}/status",
        data={"status": "ativa"}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp2.status_code == 200
