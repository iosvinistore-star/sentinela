# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testes das rotas HTML (HTMX) de autenticação: /login, /logout, /,
/esqueci-senha, /redefinir-senha, /minha-conta. Usa o mesmo client
httpx.AsyncClient das rotas de API (mesma app, mesmo Postgres de teste) --
só que aqui verificamos redirects e fragmentos de HTML em vez de JSON.
"""
from unittest.mock import patch

import pytest
from tests.sql_cru import executar


pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_raiz_sem_sessao_redireciona_para_login(client):
    resp = await client.get("/", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


@pytest.mark.asyncio
async def test_pagina_de_login_renderiza_formulario(client):
    resp = await client.get("/login")
    assert resp.status_code == 200
    assert "<form" in resp.text
    assert 'name="email"' in resp.text


@pytest.mark.asyncio
async def test_login_com_credenciais_corretas_redireciona_e_seta_cookie(client, usuario_de_teste):
    resp = await client.post(
        "/login", data={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"], "proxima": "/"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"
    assert "sentinela_session" in resp.cookies

    # "/" por sua vez redireciona pra /incidentes agora que há sessão --
    # confirma a cadeia completa de redirect, não só o primeiro salto.
    resp_raiz = await client.get("/", follow_redirects=False)
    assert resp_raiz.status_code == 303
    assert resp_raiz.headers["location"] == "/incidentes"


@pytest.mark.asyncio
async def test_login_com_senha_errada_rerenderiza_com_erro(client, usuario_de_teste):
    resp = await client.post("/login", data={"email": usuario_de_teste["email"], "senha": "errada"})
    assert resp.status_code == 401
    assert "inválid" in resp.text.lower()
    assert "sentinela_session" not in resp.cookies


@pytest.mark.asyncio
async def test_rota_protegida_sem_sessao_redireciona_para_login(client):
    resp = await client.get("/incidentes", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/login")


@pytest.mark.asyncio
async def test_logout_limpa_sessao_e_manda_hx_redirect(client, usuario_de_teste):
    await client.post("/login", data={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})
    resp = await client.post("/logout", headers={"X-Sentinela-CSRF": "1"}, follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers.get("hx-redirect") == "/login"

    resp_incidentes = await client.get("/incidentes", follow_redirects=False)
    assert resp_incidentes.status_code == 303


@pytest.mark.asyncio
async def test_logout_sem_csrf_e_recusado(client, usuario_de_teste):
    await client.post("/login", data={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})
    resp = await client.post("/logout")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_pagina_esqueci_senha_renderiza_formulario(client):
    resp = await client.get("/esqueci-senha")
    assert resp.status_code == 200
    assert 'name="email"' in resp.text


@pytest.mark.asyncio
async def test_submeter_esqueci_senha_mostra_mensagem_generica(client, usuario_de_teste):
    with patch("sentinela.services.redefinicao_senha.enviar_email", return_value=True):
        resp = await client.post(
            "/esqueci-senha", data={"email": usuario_de_teste["email"]}, headers={"X-Sentinela-CSRF": "1"},
        )
    assert resp.status_code == 200
    assert "enviamos um link" in resp.text.lower()


@pytest.mark.asyncio
async def test_submeter_esqueci_senha_sem_csrf_e_recusado(client, usuario_de_teste):
    """O form em esqueci_senha.html agora é hx-post com hx-headers estático
    (ver o template) -- alguém batendo direto na rota sem esse header (não
    passando por um navegador com JS) deve ser recusado, igual /logout."""
    resp = await client.post("/esqueci-senha", data={"email": usuario_de_teste["email"]})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_redefinir_senha_com_token_invalido_mostra_erro(client):
    # 200, não 400: a rota web (HTMX) agora sempre responde 200 em erro de
    # validação -- ver o comentário em routes_auth.py:submeter_redefinir_senha.
    # A API JSON (tests/api/test_esqueci_senha_api.py) continua exigindo 400.
    resp = await client.post(
        "/redefinir-senha", data={"token": "invalido", "senha_nova": "nova-senha-123"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 200
    assert "inválido" in resp.text.lower() or "expirado" in resp.text.lower()


@pytest.mark.asyncio
async def test_desativar_usuario_derruba_sessao_web_ja_aberta(client, usuario_de_teste, db):
    """Mesmo reforço em tempo real de test_usuarios_api.py, mas para o
    lado HTMX (SessaoInvalidaError, ver web/deps.py): rota protegida
    redireciona pro /login com a sessão encerrada, em vez de continuar
    servindo a página pra um usuário já desativado."""
    await client.post("/login", data={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})
    resp_antes = await client.get("/incidentes", follow_redirects=False)
    assert resp_antes.status_code == 200

    async with db.superadmin_session() as conn:
        await executar(conn, "UPDATE usuarios SET ativo = false WHERE id = $1", usuario_de_teste["id"])

    resp_depois = await client.get("/incidentes", follow_redirects=False)
    assert resp_depois.status_code == 303
    assert resp_depois.headers["location"] == "/login?erro=sessao_invalida"

    # a exclusão do cookie feita pelo handler de SessaoInvalidaError
    # (ver main.py) realmente colou -- a próxima requisição não se
    # autentica mais, igual depois de um /logout.
    resp_seguinte = await client.get("/incidentes", follow_redirects=False)
    assert resp_seguinte.status_code == 303
    assert resp_seguinte.headers["location"].startswith("/login")


@pytest.mark.asyncio
async def test_minha_conta_sem_sessao_redireciona_para_login(client):
    resp = await client.get("/minha-conta", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/login")


@pytest.mark.asyncio
async def test_desativar_usuario_derruba_get_minha_conta_ja_aberta(client, usuario_de_teste, db):
    """
    Correção de bug encontrado em revisão crítica (2026-09, achado 6):
    GET /minha-conta (só leitura) dependia SÓ de `exigir_login_web`
    (decodifica o JWT, sem tocar o banco) -- diferente de TODA outra rota
    protegida do sistema (ex.: GET /incidentes, coberto por
    `test_desativar_usuario_derruba_sessao_web_ja_aberta` acima), que
    sempre passa por `conexao_tenant_web`/`conexao_superadmin_web` (a
    re-checagem por requisição de `token_version`/flag `ativo`). Antes da
    correção, esta requisição continuava 200 mesmo depois do usuário ser
    desativado -- só o POST de troca de senha (que já usava
    `conexao_tenant_web`) via a sessão revogada."""
    await client.post("/login", data={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})
    resp_antes = await client.get("/minha-conta", follow_redirects=False)
    assert resp_antes.status_code == 200

    async with db.superadmin_session() as conn:
        await executar(conn, "UPDATE usuarios SET ativo = false WHERE id = $1", usuario_de_teste["id"])

    resp_depois = await client.get("/minha-conta", follow_redirects=False)
    assert resp_depois.status_code == 303
    assert resp_depois.headers["location"] == "/login?erro=sessao_invalida"


@pytest.mark.asyncio
async def test_trocar_minha_senha_com_senha_atual_certa_funciona(client, usuario_de_teste):
    await client.post("/login", data={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})
    resp = await client.post(
        "/minha-conta/senha",
        data={"senha_atual": usuario_de_teste["senha"], "senha_nova": "nova-senha-web-123"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 200
    assert "sucesso" in resp.text.lower()

    await client.post("/logout", headers={"X-Sentinela-CSRF": "1"})
    resp_login_nova = await client.post(
        "/login", data={"email": usuario_de_teste["email"], "senha": "nova-senha-web-123"}, follow_redirects=False,
    )
    assert resp_login_nova.status_code == 303


@pytest.mark.asyncio
async def test_trocar_minha_senha_com_senha_atual_errada_mostra_erro(client, usuario_de_teste):
    await client.post("/login", data={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})
    resp = await client.post(
        "/minha-conta/senha",
        data={"senha_atual": "senha-errada-de-proposito", "senha_nova": "outra-nova-senha-456"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 200
    assert "incorreta" in resp.text.lower()


# ---------------------------------------------------------------------------
# Fase C -- desafio de MFA no login HTMX (ver web/routes_auth.py:
# submeter_login/submeter_mfa_login). Espelha tests/api/test_mfa_api.py,
# só que pela superfície de formulário HTML em vez de JSON.
# ---------------------------------------------------------------------------

async def _habilitar_mfa_web(client, usuario) -> str:
    import pyotp

    await client.post("/login", data={"email": usuario["email"], "senha": usuario["senha"]})
    resp_setup = await client.post("/api/v1/usuarios/me/mfa/setup", headers={"X-Sentinela-CSRF": "1"})
    segredo = resp_setup.json()["segredo"]
    codigo = pyotp.TOTP(segredo).now()
    resp_confirmar = await client.post(
        "/api/v1/usuarios/me/mfa/confirmar", json={"codigo": codigo}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_confirmar.status_code == 200
    await client.post("/logout", headers={"X-Sentinela-CSRF": "1"})
    return segredo


@pytest.mark.asyncio
async def test_login_web_com_mfa_habilitado_mostra_formulario_de_verificacao(client, usuario_de_teste):
    await _habilitar_mfa_web(client, usuario_de_teste)
    resp = await client.post(
        "/login", data={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]},
    )
    assert resp.status_code == 200
    assert "sentinela_session" not in client.cookies
    assert 'name="pre_auth_token"' in resp.text
    assert 'name="codigo"' in resp.text


@pytest.mark.asyncio
async def test_login_web_mfa_com_codigo_correto_completa_o_login(client, usuario_de_teste):
    import re

    import pyotp

    segredo = await _habilitar_mfa_web(client, usuario_de_teste)
    resp_form = await client.post(
        "/login", data={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]},
    )
    pre_auth_token = re.search(r'name="pre_auth_token" value="([^"]+)"', resp_form.text).group(1)

    codigo = pyotp.TOTP(segredo).now()
    resp = await client.post(
        "/login/mfa",
        data={"pre_auth_token": pre_auth_token, "codigo": codigo, "proxima": "/"},
        headers={"X-Sentinela-CSRF": "1"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "sentinela_session" in resp.cookies


@pytest.mark.asyncio
async def test_login_web_mfa_com_codigo_errado_nao_completa_o_login(client, usuario_de_teste):
    import re

    segredo = await _habilitar_mfa_web(client, usuario_de_teste)  # noqa: F841 -- só para ativar MFA
    resp_form = await client.post(
        "/login", data={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]},
    )
    pre_auth_token = re.search(r'name="pre_auth_token" value="([^"]+)"', resp_form.text).group(1)

    resp = await client.post(
        "/login/mfa",
        data={"pre_auth_token": pre_auth_token, "codigo": "000000", "proxima": "/"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 401
    assert "sentinela_session" not in client.cookies
