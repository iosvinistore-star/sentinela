# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""/api/v1/usuarios -- gestão da própria empresa (admin-only, exceto troca da própria senha)."""
import uuid

import pytest

from tests.api.conftest_api import logar
from tests.sql_cru import executar

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_desativar_usuario_derruba_sessao_ja_aberta_na_proxima_requisicao(client, analista_de_teste, db):
    """Revogação em tempo real (conexao_tenant, ver auth/dependencies.py):
    um usuário desativado DEPOIS de logar não deveria continuar com acesso
    só porque o JWT ainda não expirou -- a próxima requisição precisa
    recusar, não só a próxima tentativa de login."""
    await logar(client, analista_de_teste["email"], analista_de_teste["senha"])
    resp_antes = await client.get("/api/v1/incidentes")
    assert resp_antes.status_code == 200

    async with db.superadmin_session() as conn:
        await executar(conn, "UPDATE usuarios SET ativo = false WHERE id = $1", analista_de_teste["id"])

    resp_depois = await client.get("/api/v1/incidentes")
    assert resp_depois.status_code == 401


@pytest.mark.asyncio
async def test_rebaixar_papel_derruba_sessao_ja_aberta_na_proxima_requisicao(client, usuario_de_teste, db):
    """Mesmo cenário, mas para troca de PAPEL em vez de desativação: um
    admin rebaixado a analista não pode continuar agindo como admin só
    porque o token antigo ainda diz "admin"."""
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    resp_antes = await client.get("/api/v1/usuarios")
    assert resp_antes.status_code == 200

    async with db.superadmin_session() as conn:
        await executar(conn, "UPDATE usuarios SET papel = 'analista' WHERE id = $1", usuario_de_teste["id"])

    resp_depois = await client.get("/api/v1/usuarios")
    assert resp_depois.status_code == 401


@pytest.mark.asyncio
async def test_analista_nao_pode_listar_nem_criar_usuarios(client, analista_de_teste):
    await logar(client, analista_de_teste["email"], analista_de_teste["senha"])

    resp_lista = await client.get("/api/v1/usuarios")
    assert resp_lista.status_code == 403

    resp_criar = await client.post(
        "/api/v1/usuarios",
        json={"email": f"novo-{uuid.uuid4()}@example.com", "papel": "analista", "senha": "senha-forte-123"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_criar.status_code == 403


@pytest.mark.asyncio
async def test_admin_cria_lista_e_atualiza_usuario(client, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    email_novo = f"novo-{uuid.uuid4()}@example.com"

    resp_criar = await client.post(
        "/api/v1/usuarios",
        json={"email": email_novo, "papel": "analista", "senha": "senha-forte-123"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_criar.status_code == 200
    novo_id = resp_criar.json()["usuario"]["id"]

    resp_lista = await client.get("/api/v1/usuarios")
    emails = [u["email"] for u in resp_lista.json()["usuarios"]]
    assert email_novo in emails

    resp_atualizar = await client.patch(
        f"/api/v1/usuarios/{novo_id}", json={"papel": "admin"}, headers={"X-Sentinela-CSRF": "1"}
    )
    assert resp_atualizar.status_code == 200
    assert resp_atualizar.json()["usuario"]["papel"] == "admin"


@pytest.mark.asyncio
async def test_atualizar_usuario_com_id_malformado_e_422_nao_500(client, usuario_de_teste):
    """usuario_id é tipado como uuid.UUID na rota (ver api/v1/usuarios.py)
    -- um valor que não é UUID precisa virar um 422 do FastAPI, não um
    asyncpg.DataError cru (500) ao chegar na query."""
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    resp = await client.patch(
        "/api/v1/usuarios/nao-e-um-uuid", json={"papel": "admin"}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_atualizar_usuario_inexistente_mas_uuid_valido_e_404(client, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    resp = await client.patch(
        f"/api/v1/usuarios/{uuid.uuid4()}", json={"papel": "admin"}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_criar_usuario_com_email_duplicado_e_409(client, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    resp = await client.post(
        "/api/v1/usuarios",
        json={"email": usuario_de_teste["email"], "papel": "analista", "senha": "senha-forte-123"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_usuario_troca_a_propria_senha(client, analista_de_teste):
    await logar(client, analista_de_teste["email"], analista_de_teste["senha"])
    resp = await client.patch(
        "/api/v1/usuarios/me/senha",
        json={"senha_atual": analista_de_teste["senha"], "senha_nova": "outra-senha-forte-456"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 200

    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})
    resp_login_antiga = await logar(client, analista_de_teste["email"], analista_de_teste["senha"])
    assert resp_login_antiga.status_code == 401

    resp_login_nova = await logar(client, analista_de_teste["email"], "outra-senha-forte-456")
    assert resp_login_nova.status_code == 200


@pytest.mark.asyncio
async def test_trocar_senha_curta_demais_e_422_sem_ecoar_a_senha_na_resposta(client, analista_de_teste):
    """Item 16 do plano de endurecimento -- o handler padrão do FastAPI
    ecoaria o valor bruto de `senha_nova` na chave "input" do erro de
    validação de min_length (ver main.py:_erro_de_validacao). Confere que
    isso está fechado: nem a senha nova nem a senha atual aparecem em
    lugar nenhum do corpo da resposta 422."""
    await logar(client, analista_de_teste["email"], analista_de_teste["senha"])
    senha_nova_curta = "curta-123"
    resp = await client.patch(
        "/api/v1/usuarios/me/senha",
        json={"senha_atual": analista_de_teste["senha"], "senha_nova": senha_nova_curta},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 422
    corpo_bruto = resp.text
    assert senha_nova_curta not in corpo_bruto
    assert analista_de_teste["senha"] not in corpo_bruto

    detalhe = resp.json()["detail"]
    erro_senha_nova = next(e for e in detalhe if e["loc"][-1] == "senha_nova")
    assert erro_senha_nova["input"] == "***REDACTED***"
    # o erro de validação em si (mensagem/tipo) continua íntegro -- só o
    # valor bruto ecoado é que muda.
    assert erro_senha_nova["type"] == "string_too_short"


@pytest.mark.asyncio
async def test_trocar_senha_com_senha_atual_errada_e_401_e_nao_troca_nada(client, analista_de_teste):
    await logar(client, analista_de_teste["email"], analista_de_teste["senha"])
    resp = await client.patch(
        "/api/v1/usuarios/me/senha",
        json={"senha_atual": "senha-errada-de-proposito", "senha_nova": "outra-senha-forte-789"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 401

    # a senha original continua valendo -- nada foi trocado
    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})
    resp_login = await logar(client, analista_de_teste["email"], analista_de_teste["senha"])
    assert resp_login.status_code == 200
