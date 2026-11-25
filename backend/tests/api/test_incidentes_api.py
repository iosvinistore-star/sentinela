# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""GET/PATCH /api/v1/incidentes/..."""
import pytest

from tests.api.conftest_api import logar
from tests.sql_cru import buscar_um

pytestmark = pytest.mark.integration


async def _criar_incidente_direto(db, empresa_id, ip="203.0.113.70"):
    async with db.superadmin_session() as conn:
        row = await buscar_um(conn, """
            INSERT INTO incidentes (empresa_id, incident_id, ip, severidade, pontuacao_risco, ataques)
            VALUES ($1, $2, $3, 'HIGH', 70, '["SQL Injection (SQLi)"]'::jsonb)
            RETURNING incident_id
            """,
            empresa_id, f"INC-TESTE-{ip}", ip,
        )
    return row["incident_id"]


@pytest.mark.asyncio
async def test_listar_e_obter_incidente(client, usuario_de_teste, db):
    incident_id = await _criar_incidente_direto(db, usuario_de_teste["empresa_id"])
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])

    resp_lista = await client.get("/api/v1/incidentes")
    assert resp_lista.status_code == 200
    assert any(i["incident_id"] == incident_id for i in resp_lista.json()["incidentes"])

    resp_detalhe = await client.get(f"/api/v1/incidentes/{incident_id}")
    assert resp_detalhe.status_code == 200
    assert resp_detalhe.json()["incidente"]["incident_id"] == incident_id


@pytest.mark.asyncio
async def test_obter_incidente_inexistente_e_404(client, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    resp = await client.get("/api/v1/incidentes/INC-NAO-EXISTE")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_atualizar_status_com_sucesso(client, usuario_de_teste, db):
    incident_id = await _criar_incidente_direto(db, usuario_de_teste["empresa_id"], ip="203.0.113.71")
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])

    resp = await client.patch(
        f"/api/v1/incidentes/{incident_id}/status",
        json={"status": "RESOLVIDO", "observacoes": "falso positivo, IP interno"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 200
    assert resp.json()["incidente"]["status"] == "RESOLVIDO"


@pytest.mark.asyncio
async def test_atualizar_status_invalido_e_422(client, usuario_de_teste, db):
    incident_id = await _criar_incidente_direto(db, usuario_de_teste["empresa_id"], ip="203.0.113.72")
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])

    resp = await client.patch(
        f"/api/v1/incidentes/{incident_id}/status",
        json={"status": "NAO_EXISTE"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_analista_tambem_pode_triar_incidente(client, analista_de_teste, db):
    incident_id = await _criar_incidente_direto(db, analista_de_teste["empresa_id"], ip="203.0.113.73")
    await logar(client, analista_de_teste["email"], analista_de_teste["senha"])

    resp = await client.patch(
        f"/api/v1/incidentes/{incident_id}/status",
        json={"status": "EM_ANDAMENTO"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 200
