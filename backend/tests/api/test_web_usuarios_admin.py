# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Testes das rotas HTML /usuarios (admin da própria empresa) e
/admin/empresas (superadmin)."""
import uuid

import pytest
from tests.sql_cru import buscar_um, executar


pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_analista_nao_acessa_pagina_de_usuarios(client, analista_de_teste):
    await client.post("/login", data={"email": analista_de_teste["email"], "senha": analista_de_teste["senha"]})
    resp = await client.get("/usuarios")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_admin_cria_usuario_via_formulario_htmx(client, usuario_de_teste):
    await client.post("/login", data={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})
    email_novo = f"novo-web-{uuid.uuid4()}@example.com"

    resp = await client.post(
        "/usuarios", data={"email": email_novo, "papel": "analista", "senha": "senha-forte-123"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 200
    assert email_novo in resp.text
    assert 'id="tabela-usuarios"' in resp.text


@pytest.mark.asyncio
async def test_admin_cria_usuario_duplicado_mostra_erro_inline(client, usuario_de_teste):
    await client.post("/login", data={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})
    resp = await client.post(
        "/usuarios", data={"email": usuario_de_teste["email"], "papel": "analista", "senha": "senha-forte-123"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    # 200 (não 409!) de propósito -- ver comentário em web/routes_usuarios.py:
    # htmx não faz swap em respostas fora de 2xx por padrão, então a
    # mensagem de erro só chega na tela se a resposta for 2xx.
    assert resp.status_code == 200
    assert "já existe" in resp.text


@pytest.mark.asyncio
async def test_superadmin_cria_empresa_e_usuario_via_htmx(client, superadmin_de_teste, db):
    await client.post("/login", data={"email": superadmin_de_teste["email"], "senha": superadmin_de_teste["senha"]})

    resp_empresa = await client.post(
        "/admin/empresas", data={"nome": "Empresa Web Admin", "plano": "padrao"}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_empresa.status_code == 200
    assert "Empresa Web Admin" in resp_empresa.text

    async with db.superadmin_session() as conn:
        row = await buscar_um(conn, "SELECT id FROM empresas WHERE nome = 'Empresa Web Admin'")
    empresa_id = str(row["id"])

    resp_pagina_usuarios = await client.get(f"/admin/empresas/{empresa_id}/usuarios")
    assert resp_pagina_usuarios.status_code == 200

    email_admin = f"admin-web-{uuid.uuid4()}@example.com"
    resp_criar = await client.post(
        f"/admin/empresas/{empresa_id}/usuarios",
        data={"email": email_admin, "papel": "admin", "senha": "senha-forte-456"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_criar.status_code == 200
    assert email_admin in resp_criar.text

    async with db.superadmin_session() as conn:
        await executar(conn, "DELETE FROM auditoria WHERE empresa_id = $1", empresa_id)
        await executar(conn, "DELETE FROM usuarios WHERE empresa_id = $1", empresa_id)
        await executar(conn, "DELETE FROM empresas WHERE id = $1", empresa_id)


@pytest.mark.asyncio
async def test_sessao_web_de_superadmin_revogada_redireciona_para_login(client, superadmin_de_teste, db):
    """Espelha tests/api/test_admin_api.py::test_sessao_de_superadmin_revogada_...
    -- mesmo reforço (web/deps.py:conexao_superadmin_web), só que aqui o
    efeito observável é um redirect para /login (ver web/deps.py:SessaoInvalidaError)
    em vez de um 401 JSON."""
    await client.post("/login", data={"email": superadmin_de_teste["email"], "senha": superadmin_de_teste["senha"]})

    resp_antes = await client.get("/admin/empresas")
    assert resp_antes.status_code == 200

    async with db.superadmin_session() as conn:
        await executar(conn, "UPDATE superadmins SET token_version = token_version + 1 WHERE id = $1",
            superadmin_de_teste["id"],
        )

    resp_depois = await client.get("/admin/empresas", follow_redirects=False)
    assert resp_depois.status_code == 303
    assert resp_depois.headers["location"].startswith("/login")
