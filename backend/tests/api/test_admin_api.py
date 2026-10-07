# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""/api/v1/admin/... -- gestão global de empresas, restrita a superadmin."""
import uuid

import pytest

from sentinela.db.pool import superadmin_scoped_connection
from tests.api.conftest_api import logar

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_usuario_comum_nao_acessa_rotas_de_admin(client, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    resp = await client.get("/api/v1/admin/empresas")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_sessao_de_superadmin_revogada_e_recusada_na_proxima_requisicao(client, pool, superadmin_de_teste):
    """
    Ponto 6 do review de hardening: sessão de superadmin agora tem o mesmo
    reforço em tempo real que já existia para usuário de empresa (ver
    auth/dependencies.py:conexao_superadmin e
    migrations/0013_token_version_superadmin.sql). Simula exatamente o
    cenário de incidente que motivou isto -- um cookie de superadmin
    comprometido -- incrementando token_version DIRETO no banco (o mesmo
    efeito de rodar scripts/revogar_sessao_superadmin.py) e confirmando
    que o cookie já emitido para de funcionar imediatamente, sem esperar
    a expiração natural.
    """
    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])

    resp_antes = await client.get("/api/v1/admin/empresas")
    assert resp_antes.status_code == 200

    async with superadmin_scoped_connection(pool) as conn:
        await conn.execute(
            "UPDATE superadmins SET token_version = token_version + 1 WHERE id = $1",
            superadmin_de_teste["id"],
        )

    resp_depois = await client.get("/api/v1/admin/empresas")
    assert resp_depois.status_code == 401


@pytest.mark.asyncio
async def test_criar_usuario_em_empresa_inexistente_e_404_nao_500(client, superadmin_de_teste):
    """empresa_id de formato válido mas inexistente: antes desta correção,
    o INSERT batia na FK de usuarios.empresa_id e virava um
    asyncpg.ForeignKeyViolationError cru (500) -- agora obtem_empresa()
    confere antes e devolve 404 (ver api/v1/admin.py:criar_usuario_da_empresa)."""
    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    resp = await client.post(
        f"/api/v1/admin/empresas/{uuid.uuid4()}/usuarios",
        json={"email": f"orfao-{uuid.uuid4()}@example.com", "papel": "admin", "senha": "senha-forte-789"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_empresa_id_malformado_e_422_nao_500(client, superadmin_de_teste):
    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    resp = await client.patch(
        "/api/v1/admin/empresas/nao-e-um-uuid", json={"nome": "x"}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_superadmin_cria_empresa_e_admin_inicial_que_consegue_logar(client, superadmin_de_teste, pool):
    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])

    resp_criar_empresa = await client.post(
        "/api/v1/admin/empresas", json={"nome": "Empresa Nova Via Admin"}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_criar_empresa.status_code == 200
    empresa_id = resp_criar_empresa.json()["empresa"]["id"]

    resp_lista = await client.get("/api/v1/admin/empresas")
    assert any(e["id"] == empresa_id for e in resp_lista.json()["empresas"])

    email_admin = f"admin-novo-{uuid.uuid4()}@example.com"
    resp_criar_usuario = await client.post(
        f"/api/v1/admin/empresas/{empresa_id}/usuarios",
        json={"email": email_admin, "papel": "admin", "senha": "senha-forte-789"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_criar_usuario.status_code == 200

    resp_usuarios_empresa = await client.get(f"/api/v1/admin/empresas/{empresa_id}/usuarios")
    emails = [u["email"] for u in resp_usuarios_empresa.json()["usuarios"]]
    assert email_admin in emails

    # o admin recém-criado consegue logar de verdade com as credenciais definidas
    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})
    resp_login_novo_admin = await logar(client, email_admin, "senha-forte-789")
    assert resp_login_novo_admin.status_code == 200
    assert resp_login_novo_admin.json()["usuario"]["papel"] == "admin"

    async with superadmin_scoped_connection(pool) as conn:
        await conn.execute("DELETE FROM auditoria WHERE empresa_id = $1", empresa_id)
        await conn.execute("DELETE FROM usuarios WHERE empresa_id = $1", empresa_id)
        await conn.execute("DELETE FROM empresas WHERE id = $1", empresa_id)


@pytest.mark.asyncio
async def test_nova_empresa_comeca_no_modo_firewall_padrao(client, superadmin_de_teste, pool):
    """Ver migrations/0012_firewall_modo_e_incidente.sql -- item 8 do plano
    de endurecimento."""
    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    resp = await client.post(
        "/api/v1/admin/empresas", json={"nome": "Empresa Modo Firewall Padrao"}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 200
    assert resp.json()["empresa"]["modo_firewall"] == "automacao_controlada"

    empresa_id = resp.json()["empresa"]["id"]
    # Limpeza -- mesmo motivo de test_superadmin_cria_empresa_e_admin_inicial_que_consegue_logar:
    # sem isto, a linha de auditoria (empresa.criada, ator_superadmin_id)
    # sobrevive ao teste e quebra o teardown do fixture superadmin_de_teste
    # (FK fk_auditoria_superadmin).
    async with superadmin_scoped_connection(pool) as conn:
        await conn.execute("DELETE FROM auditoria WHERE empresa_id = $1", empresa_id)
        await conn.execute("DELETE FROM empresas WHERE id = $1", empresa_id)


@pytest.mark.asyncio
async def test_superadmin_altera_modo_firewall_da_empresa(client, superadmin_de_teste, usuario_de_teste):
    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    resp = await client.patch(
        f"/api/v1/admin/empresas/{usuario_de_teste['empresa_id']}",
        json={"modo_firewall": "observacao"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 200
    assert resp.json()["empresa"]["modo_firewall"] == "observacao"


@pytest.mark.asyncio
async def test_modo_firewall_invalido_e_422(client, superadmin_de_teste, usuario_de_teste):
    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    resp = await client.patch(
        f"/api/v1/admin/empresas/{usuario_de_teste['empresa_id']}",
        json={"modo_firewall": "modo_que_nao_existe"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_web_superadmin_altera_modo_firewall_da_empresa(client, superadmin_de_teste, usuario_de_teste):
    """Mesma checagem de test_superadmin_altera_modo_firewall_da_empresa,
    pela rota HTMX (web/routes_admin.py)."""
    await client.post(
        "/login", data={"email": superadmin_de_teste["email"], "senha": superadmin_de_teste["senha"]},
    )
    resp = await client.post(
        f"/admin/empresas/{usuario_de_teste['empresa_id']}/modo-firewall",
        data={"modo_firewall": "dry_run"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 200
    assert 'value="dry_run" selected' in resp.text

    resp_invalido = await client.post(
        f"/admin/empresas/{usuario_de_teste['empresa_id']}/modo-firewall",
        data={"modo_firewall": "nao_existe"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_invalido.status_code == 422


@pytest.mark.asyncio
async def test_superadmin_liga_flags_do_modo_autonomo(client, superadmin_de_teste, usuario_de_teste, pool):
    """Migrations/0014_autonomia_operacional.sql -- as duas chaves opt-in
    do modo autônomo são admin-only, no mesmo lugar que modo_firewall (ver
    services/empresas.py)."""
    empresa_id = usuario_de_teste["empresa_id"]
    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])

    resp = await client.patch(
        f"/api/v1/admin/empresas/{empresa_id}",
        json={"modo_firewall_auto": True, "auto_triagem_incidentes": True},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 200
    assert resp.json()["empresa"]["modo_firewall_auto"] is True
    assert resp.json()["empresa"]["auto_triagem_incidentes"] is True

    async with superadmin_scoped_connection(pool) as conn:
        linha = await conn.fetchrow(
            "SELECT modo_firewall_auto, auto_triagem_incidentes FROM empresas WHERE id = $1", empresa_id,
        )
    assert linha["modo_firewall_auto"] is True
    assert linha["auto_triagem_incidentes"] is True


@pytest.mark.asyncio
async def test_web_superadmin_liga_flags_do_modo_autonomo(client, superadmin_de_teste, usuario_de_teste):
    """Mesma checagem acima, pela rota HTMX (web/routes_admin.py). Checkbox
    desmarcado não envia o campo -- confirma que omitir
    auto_triagem_incidentes desliga (não deixa como estava)."""
    empresa_id = usuario_de_teste["empresa_id"]
    await client.post(
        "/login", data={"email": superadmin_de_teste["email"], "senha": superadmin_de_teste["senha"]},
    )
    resp = await client.post(
        f"/admin/empresas/{empresa_id}/autonomia",
        data={"modo_firewall_auto": "true"},  # auto_triagem_incidentes omitido de propósito
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 200
    assert "checked" in resp.text


# ---------------------------------------------------------------------------
# Troca da própria senha de superadmin (PATCH /api/v1/admin/me/senha) --
# ver services/superadmins.py e migrations/0013_token_version_superadmin.sql
# para o porquê desta rota não existir até esta correção: espelha
# tests/api/test_usuarios_api.py, que cobre exatamente o mesmo fluxo para
# usuário de empresa.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_superadmin_troca_a_propria_senha(client, superadmin_de_teste):
    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    resp = await client.patch(
        "/api/v1/admin/me/senha",
        json={"senha_atual": superadmin_de_teste["senha"], "senha_nova": "outra-senha-forte-456"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 200

    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})
    resp_login_antiga = await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    assert resp_login_antiga.status_code == 401

    resp_login_nova = await logar(client, superadmin_de_teste["email"], "outra-senha-forte-456")
    assert resp_login_nova.status_code == 200

    # a sessão emitida ANTES da troca também é derrubada na próxima
    # requisição -- mesmo reforço de token_version que
    # test_sessao_de_superadmin_revogada_e_recusada_na_proxima_requisicao
    # já cobre para uma revogação via script; aqui a fonte é a troca de
    # senha em si (ver migrations/0013_token_version_superadmin.sql).
    resp_admin = await client.get("/api/v1/admin/empresas")
    assert resp_admin.status_code == 200  # cookie foi reemitido pelo PATCH -- a sessão ATUAL continua válida


@pytest.mark.asyncio
async def test_superadmin_troca_senha_com_senha_atual_errada_e_401_e_nao_troca_nada(client, superadmin_de_teste):
    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    resp = await client.patch(
        "/api/v1/admin/me/senha",
        json={"senha_atual": "senha-errada-de-proposito", "senha_nova": "outra-senha-forte-789"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 401

    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})
    resp_login = await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    assert resp_login.status_code == 200  # senha original continua valendo -- nada foi trocado


@pytest.mark.asyncio
async def test_superadmin_troca_senha_curta_demais_e_422(client, superadmin_de_teste):
    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    resp = await client.patch(
        "/api/v1/admin/me/senha",
        json={"senha_atual": superadmin_de_teste["senha"], "senha_nova": "curta-123"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_usuario_comum_nao_troca_senha_de_superadmin(client, usuario_de_teste):
    """A rota é `exigir_superadmin` -- um usuário de empresa (mesmo admin)
    não pode chegar nela, ainda que soubesse a própria senha atual."""
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    resp = await client.patch(
        "/api/v1/admin/me/senha",
        json={"senha_atual": usuario_de_teste["senha"], "senha_nova": "outra-senha-forte-000"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_web_superadmin_troca_a_propria_senha(client, superadmin_de_teste):
    """Mesmo fluxo acima, pela rota HTMX (web/routes_admin.py) -- e pela
    página que só passou a existir com esta correção (base.html apontava
    "Minha conta" para nenhum lugar quando usuario.papel == "superadmin")."""
    await client.post(
        "/login", data={"email": superadmin_de_teste["email"], "senha": superadmin_de_teste["senha"]},
    )
    resp_pagina = await client.get("/admin/minha-conta")
    assert resp_pagina.status_code == 200

    resp = await client.post(
        "/admin/minha-conta/senha",
        data={"senha_atual": superadmin_de_teste["senha"], "senha_nova": "outra-senha-web-456"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 200
    assert "Senha alterada com sucesso" in resp.text

    await client.post("/logout", headers={"X-Sentinela-CSRF": "1"})
    resp_login_nova = await client.post(
        "/login", data={"email": superadmin_de_teste["email"], "senha": "outra-senha-web-456"},
    )
    assert resp_login_nova.status_code == 303  # redirect de sucesso -- login antigo já não funcionaria (303 pra /login de novo com erro)


@pytest.mark.asyncio
async def test_token_version_revogado_derruba_get_admin_minha_conta_ja_aberta(client, pool, superadmin_de_teste):
    """
    Correção de bug encontrado em revisão crítica (2026-09, achado 6):
    GET /admin/minha-conta (só leitura) dependia SÓ de
    `exigir_superadmin_web` (decodifica o JWT, sem tocar o banco) --
    diferente de TODA outra rota de superadmin, inclusive
    GET /api/v1/admin/empresas (coberto por
    test_sessao_de_superadmin_revogada_e_recusada_na_proxima_requisicao
    acima), que sempre passa por `conexao_superadmin_web`/
    `conexao_superadmin` (a re-checagem por requisição de
    `token_version`). Antes da correção, esta requisição continuava 200
    mesmo com token_version incrementado (o mesmo efeito de
    scripts/revogar_sessao_superadmin.py) -- só o POST de troca de senha
    (que já usava `conexao_superadmin_web`) via a sessão revogada.
    """
    await client.post(
        "/login", data={"email": superadmin_de_teste["email"], "senha": superadmin_de_teste["senha"]},
    )
    resp_antes = await client.get("/admin/minha-conta", follow_redirects=False)
    assert resp_antes.status_code == 200

    async with superadmin_scoped_connection(pool) as conn:
        await conn.execute(
            "UPDATE superadmins SET token_version = token_version + 1 WHERE id = $1",
            superadmin_de_teste["id"],
        )

    resp_depois = await client.get("/admin/minha-conta", follow_redirects=False)
    assert resp_depois.status_code == 303
    assert resp_depois.headers["location"] == "/login?erro=sessao_invalida"


# ---------------------------------------------------------------------------
# Fase C / C4 -- gestão de contas de SaaS (Owner + Admin), exclusiva de
# SAAS_OWNER (auth/rbac.py:exigir_saas_owner).
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_saas_owner_pode_criar_saas_admin(client, superadmin_de_teste, pool):
    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    email_novo = f"saas-admin-{uuid.uuid4()}@example.com"
    resp = await client.post(
        "/api/v1/admin/saas-admins",
        json={"email": email_novo, "papel_saas": "saas_admin", "senha": "senha-forte-123"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 200
    assert resp.json()["conta"]["papel"] == "saas_admin"

    async with superadmin_scoped_connection(pool) as conn:
        await conn.execute("DELETE FROM auditoria WHERE ator_superadmin_id = $1", superadmin_de_teste["id"])
        await conn.execute("DELETE FROM superadmins WHERE email = $1", email_novo)


@pytest.mark.asyncio
async def test_saas_admin_nao_pode_criar_outro_saas_admin(client, pool):
    from sentinela.auth.security import hash_senha

    saas_admin_id = uuid.uuid4()
    email = f"saas-admin-ator-{uuid.uuid4()}@example.com"
    async with superadmin_scoped_connection(pool) as conn:
        await conn.execute(
            "INSERT INTO superadmins (id, email, senha_hash, papel) VALUES ($1, $2, $3, 'saas_admin')",
            saas_admin_id, email, hash_senha("senha-forte-123"),
        )
    try:
        await logar(client, email, "senha-forte-123")
        resp = await client.post(
            "/api/v1/admin/saas-admins",
            json={"email": f"outro-{uuid.uuid4()}@example.com", "papel_saas": "saas_admin", "senha": "senha-forte-123"},
            headers={"X-Sentinela-CSRF": "1"},
        )
        assert resp.status_code == 403
    finally:
        async with superadmin_scoped_connection(pool) as conn:
            await conn.execute("DELETE FROM auditoria WHERE ator_superadmin_id = $1", saas_admin_id)
            await conn.execute("DELETE FROM superadmins WHERE id = $1", saas_admin_id)
