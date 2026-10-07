# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Testes das rotas HTML /incidentes (HTMX)."""
import pytest
from tests.sql_cru import buscar_um, executar


pytestmark = pytest.mark.integration


async def _criar_incidente_direto(db, empresa_id, ip):
    async with db.superadmin_session() as conn:
        row = await buscar_um(conn, """
            INSERT INTO incidentes (empresa_id, incident_id, ip, severidade, pontuacao_risco, ataques)
            VALUES ($1, $2, $3, 'HIGH', 65, '["SQL Injection (SQLi)"]'::jsonb)
            RETURNING incident_id
            """,
            empresa_id, f"INC-WEB-{ip}", ip,
        )
    return row["incident_id"]


@pytest.mark.asyncio
async def test_lista_de_incidentes_mostra_incidente_da_empresa(client, usuario_de_teste, db):
    incident_id = await _criar_incidente_direto(db, usuario_de_teste["empresa_id"], "203.0.113.100")
    await client.post("/login", data={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})

    resp = await client.get("/incidentes")
    assert resp.status_code == 200
    assert incident_id in resp.text
    assert "203.0.113.100" in resp.text


@pytest.mark.asyncio
async def test_detalhe_e_atualizacao_de_status_via_htmx(client, usuario_de_teste, db):
    incident_id = await _criar_incidente_direto(db, usuario_de_teste["empresa_id"], "203.0.113.101")
    await client.post("/login", data={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})

    resp_detalhe = await client.get(f"/incidentes/{incident_id}")
    assert resp_detalhe.status_code == 200
    assert "OPEN" in resp_detalhe.text

    resp_atualizar = await client.post(
        f"/incidentes/{incident_id}/status",
        data={"status": "RESOLVIDO", "observacoes": "tratado"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_atualizar.status_code == 200
    assert "RESOLVIDO" in resp_atualizar.text
    assert 'id="detalhe-incidente"' in resp_atualizar.text


@pytest.mark.asyncio
async def test_outra_empresa_nao_ve_o_incidente(client, usuario_de_teste, analista_de_teste, db):
    incident_id = await _criar_incidente_direto(db, usuario_de_teste["empresa_id"], "203.0.113.102")
    await client.post("/login", data={"email": analista_de_teste["email"], "senha": analista_de_teste["senha"]})

    resp = await client.get(f"/incidentes/{incident_id}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_xss_em_incidente_e_escapado_no_html(client, usuario_de_teste, db):
    async with db.superadmin_session() as conn:
        incident_id = f"INC-XSS-{usuario_de_teste['id']}"
        await executar(conn, """INSERT INTO incidentes (empresa_id, incident_id, ip, severidade, pontuacao_risco, ataques, observacoes)
               VALUES ($1, $2, $3, 'HIGH', 65, $4::jsonb, $5)""",
            usuario_de_teste['empresa_id'], incident_id, '203.0.113.110', '["<script>alert(1)</script>"]', '<img src=x onerror=alert(1)>',
        )
    await client.post('/login', data={'email': usuario_de_teste['email'], 'senha': usuario_de_teste['senha']})
    resp = await client.get(f'/incidentes/{incident_id}')
    assert resp.status_code == 200
    assert '<script>alert(1)</script>' not in resp.text
    assert '&lt;script&gt;alert(1)&lt;/script&gt;' in resp.text
    assert '<img src=x onerror=alert(1)>' not in resp.text
