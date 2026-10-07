# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Chave de ativação: provedor gera, agente usa o token contido nela para se registrar."""
import pytest

from sentinela.services import chave_ativacao
from tests.api.conftest_api import logar

CSRF = {"X-Sentinela-CSRF": "1"}
HEADER_ENROLLMENT = "X-Sentinela-Enrollment-Token"


def test_formato_ida_e_volta_e_aviso_localhost():
    chave = chave_ativacao.gerar("https://soc.cliente.gov.br/", "enr_abcdef0123456789abcdef")
    assert chave.startswith("SNT1-") and "=" not in chave
    assert chave_ativacao.ler(chave[:15] + "\n " + chave[15:]) == {
        "backend_url": "https://soc.cliente.gov.br", "token": "enr_abcdef0123456789abcdef"}
    assert "NESTA máquina" in chave_ativacao.aviso_endereco("http://localhost:8000")
    assert "HTTP" in chave_ativacao.aviso_endereco("http://10.0.0.5:8000")
    assert chave_ativacao.aviso_endereco("https://soc.cliente.gov.br") is None


@pytest.mark.asyncio
async def test_provedor_gera_chave_e_agente_se_registra(client, superadmin_de_teste, usuario_de_teste, pool):
    from sentinela.db.pool import superadmin_scoped_connection
    empresa_id = usuario_de_teste["empresa_id"]
    async with superadmin_scoped_connection(pool) as conn:
        await conn.execute("UPDATE empresas SET agentes_endpoint_habilitado = false WHERE id = $1", empresa_id)

    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    r = await client.post(f"/api/v1/admin/empresas/{empresa_id}/chave-ativacao", headers=CSRF,
                          json={"validade_horas": 24, "max_instalacoes": 2})
    assert r.status_code == 200, r.text
    corpo = r.json()
    assert corpo["agentes_habilitados_agora"] is True and corpo["max_instalacoes"] == 2
    dados = chave_ativacao.ler(corpo["chave_ativacao"])
    assert dados["backend_url"] == corpo["backend_url"]

    # o que o agente faz com a chave: usa o token no enroll
    r = await client.post("/api/v1/agentes/enroll", json={"hostname": "cliente-pc-01"},
                          headers={HEADER_ENROLLMENT: dados["token"]})
    assert r.status_code == 200, r.text
    assert r.json()["token"].startswith("agt_")

    async with superadmin_scoped_connection(pool) as conn:
        hosts = await conn.fetch("SELECT hostname FROM agentes WHERE empresa_id = $1", empresa_id)
        acoes = await conn.fetch("SELECT acao, ator_superadmin_id FROM auditoria WHERE empresa_id = $1 AND acao IN "
                                 "('empresa.agentes_habilitados', 'agente.enrollment_criado')", empresa_id)
    assert [h["hostname"] for h in hosts] == ["cliente-pc-01"]
    assert {a["acao"] for a in acoes} == {"empresa.agentes_habilitados", "agente.enrollment_criado"}
    assert all(a["ator_superadmin_id"] is not None for a in acoes)


@pytest.mark.asyncio
async def test_chave_404_409_e_admin_da_empresa_nao_acessa(client, superadmin_de_teste, usuario_de_teste, pool):
    from sentinela.db.pool import superadmin_scoped_connection
    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    r = await client.post("/api/v1/admin/empresas/00000000-0000-0000-0000-000000000000/chave-ativacao", headers=CSRF, json={})
    assert r.status_code == 404
    async with superadmin_scoped_connection(pool) as conn:
        await conn.execute("UPDATE empresas SET status = 'suspensa' WHERE id = $1", usuario_de_teste["empresa_id"])
    r = await client.post(f"/api/v1/admin/empresas/{usuario_de_teste['empresa_id']}/chave-ativacao", headers=CSRF, json={})
    assert r.status_code == 409
    await client.post("/api/v1/auth/logout", headers=CSRF)
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    r = await client.post(f"/api/v1/admin/empresas/{usuario_de_teste['empresa_id']}/chave-ativacao", headers=CSRF, json={})
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_admin_da_empresa_recebe_chave_junto_do_token(client, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    r = await client.post("/api/v1/agentes/enrollment", headers=CSRF,
                          json={"expira_em": "2099-01-01T00:00:00Z", "max_usos": 1})
    assert r.status_code == 200, r.text
    corpo = r.json()
    assert chave_ativacao.ler(corpo["chave_ativacao"])["token"] == corpo["token"]
