# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
/api/v1/agentes/enrollment (gestão, sessão humana) e /api/v1/agentes/enroll
(troca, token de máquina) -- Fase D / D3, ver ARQUITETURA_LICENCIAMENTO.md
§12.

Segue as convenções de tests/api/test_agentes_api.py: fixtures de
conftest_api.py, toggle de `agentes_endpoint_habilitado` por superadmin
antes de exercitar as rotas tenant.
"""
from datetime import datetime, timedelta, timezone

import pytest

from tests.api.conftest_api import logar

pytestmark = pytest.mark.integration

HEADER_ENROLLMENT = "X-Sentinela-Enrollment-Token"


async def _habilitar_agentes_endpoint(client, superadmin, empresa_id):
    await logar(client, superadmin["email"], superadmin["senha"])
    resp = await client.patch(
        f"/api/v1/admin/empresas/{empresa_id}",
        json={"agentes_endpoint_habilitado": True},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 200
    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})


def _iso(dt):
    return dt.isoformat()


async def _criar_token_enrollment(client, usuario, minutos=30, max_usos=None):
    await logar(client, usuario["email"], usuario["senha"])
    payload = {"expira_em": _iso(datetime.now(timezone.utc) + timedelta(minutes=minutos))}
    if max_usos is not None:
        payload["max_usos"] = max_usos
    resp = await client.post("/api/v1/agentes/enrollment", json=payload, headers={"X-Sentinela-CSRF": "1"})
    assert resp.status_code == 200
    corpo = resp.json()
    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})
    return corpo["enrollment"], corpo["token"]


# ---------------------------------------------------------------------------
# Gestão de tokens de enrollment -- sessão humana (cookie + CSRF)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sem_login_nao_acessa_gestao_de_enrollment(client):
    resp = await client.get("/api/v1/agentes/enrollment")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_admin_cria_lista_e_revoga_token_de_enrollment(client, superadmin_de_teste, usuario_de_teste):
    empresa_id = usuario_de_teste["empresa_id"]
    await _habilitar_agentes_endpoint(client, superadmin_de_teste, empresa_id)

    enrollment, token = await _criar_token_enrollment(client, usuario_de_teste)
    assert token.startswith("enr_")
    assert enrollment["status"] == "ativo"
    assert "token_hash" not in enrollment

    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    resp_lista = await client.get("/api/v1/agentes/enrollment")
    assert resp_lista.status_code == 200
    assert any(e["id"] == enrollment["id"] for e in resp_lista.json()["tokens"])
    assert all("token" not in e for e in resp_lista.json()["tokens"])

    resp_revogar = await client.post(
        f"/api/v1/agentes/enrollment/{enrollment['id']}/revogar", headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_revogar.status_code == 200
    assert resp_revogar.json()["enrollment"]["status"] == "revogado"


@pytest.mark.asyncio
async def test_analista_nao_cria_token_de_enrollment_mas_pode_listar(client, superadmin_de_teste, analista_de_teste):
    empresa_id = analista_de_teste["empresa_id"]
    await _habilitar_agentes_endpoint(client, superadmin_de_teste, empresa_id)
    await logar(client, analista_de_teste["email"], analista_de_teste["senha"])

    resp_criar = await client.post(
        "/api/v1/agentes/enrollment",
        json={"expira_em": _iso(datetime.now(timezone.utc) + timedelta(minutes=30))},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_criar.status_code == 403

    resp_lista = await client.get("/api/v1/agentes/enrollment")
    assert resp_lista.status_code == 200


@pytest.mark.asyncio
async def test_revogar_token_de_enrollment_inexistente_e_404(client, superadmin_de_teste, usuario_de_teste):
    empresa_id = usuario_de_teste["empresa_id"]
    await _habilitar_agentes_endpoint(client, superadmin_de_teste, empresa_id)
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    resp = await client.post(
        "/api/v1/agentes/enrollment/00000000-0000-0000-0000-000000000000/revogar",
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Troca (enroll) -- token de máquina, sem cookie/CSRF
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_enroll_sem_header_e_422(client):
    resp = await client.post("/api/v1/agentes/enroll", json={"hostname": "x"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_enroll_com_token_invalido_e_401(client):
    resp = await client.post(
        "/api/v1/agentes/enroll", json={"hostname": "x"},
        headers={HEADER_ENROLLMENT: "enr_000000000000_forjado"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_enroll_com_token_invalido_repetido_e_rate_limitado_com_429(client):
    """Confirma que os limitadores dedicados (`limitador_enrollment`/
    `limitador_enrollment_ip`, ver main.py) estão de fato conectados --
    mesmo padrão de test_agentes_api.py:
    test_heartbeat_com_token_invalido_repetido_e_rate_limitado_com_429."""
    for _ in range(5):
        resp = await client.post(
            "/api/v1/agentes/enroll", json={"hostname": "x"},
            headers={HEADER_ENROLLMENT: "enr_000000000000_forjado"},
        )
        assert resp.status_code == 401

    resp_bloqueado = await client.post(
        "/api/v1/agentes/enroll", json={"hostname": "x"},
        headers={HEADER_ENROLLMENT: "enr_000000000000_forjado"},
    )
    assert resp_bloqueado.status_code == 429
    assert "Retry-After" in resp_bloqueado.headers


@pytest.mark.asyncio
async def test_enroll_com_sucesso_cria_agente_permanente(client, superadmin_de_teste, usuario_de_teste):
    empresa_id = usuario_de_teste["empresa_id"]
    await _habilitar_agentes_endpoint(client, superadmin_de_teste, empresa_id)
    _, token = await _criar_token_enrollment(client, usuario_de_teste)

    resp = await client.post(
        "/api/v1/agentes/enroll", json={"hostname": "host-enroll-api"}, headers={HEADER_ENROLLMENT: token},
    )
    assert resp.status_code == 200
    corpo = resp.json()
    assert corpo["agente"]["hostname"] == "host-enroll-api"
    assert corpo["agente"]["status"] == "ativo"
    assert corpo["token"].startswith("agt_")

    # o agente novo aparece na listagem normal de agentes da empresa
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    resp_lista = await client.get("/api/v1/agentes")
    assert any(a["id"] == corpo["agente"]["id"] for a in resp_lista.json()["agentes"])


@pytest.mark.asyncio
async def test_enroll_e_multi_uso_para_hostnames_diferentes(client, superadmin_de_teste, usuario_de_teste):
    empresa_id = usuario_de_teste["empresa_id"]
    await _habilitar_agentes_endpoint(client, superadmin_de_teste, empresa_id)
    _, token = await _criar_token_enrollment(client, usuario_de_teste)

    resp_1 = await client.post(
        "/api/v1/agentes/enroll", json={"hostname": "host-multi-api-1"}, headers={HEADER_ENROLLMENT: token},
    )
    resp_2 = await client.post(
        "/api/v1/agentes/enroll", json={"hostname": "host-multi-api-2"}, headers={HEADER_ENROLLMENT: token},
    )
    assert resp_1.status_code == 200
    assert resp_2.status_code == 200
    assert resp_1.json()["agente"]["id"] != resp_2.json()["agente"]["id"]


@pytest.mark.asyncio
async def test_enroll_com_hostname_duplicado_e_409(client, superadmin_de_teste, usuario_de_teste):
    empresa_id = usuario_de_teste["empresa_id"]
    await _habilitar_agentes_endpoint(client, superadmin_de_teste, empresa_id)
    _, token = await _criar_token_enrollment(client, usuario_de_teste)

    resp_1 = await client.post(
        "/api/v1/agentes/enroll", json={"hostname": "host-enroll-duplicado"}, headers={HEADER_ENROLLMENT: token},
    )
    assert resp_1.status_code == 200
    resp_2 = await client.post(
        "/api/v1/agentes/enroll", json={"hostname": "host-enroll-duplicado"}, headers={HEADER_ENROLLMENT: token},
    )
    assert resp_2.status_code == 409


@pytest.mark.asyncio
async def test_enroll_com_token_revogado_e_403(client, superadmin_de_teste, usuario_de_teste):
    empresa_id = usuario_de_teste["empresa_id"]
    await _habilitar_agentes_endpoint(client, superadmin_de_teste, empresa_id)
    enrollment, token = await _criar_token_enrollment(client, usuario_de_teste)

    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    resp_revogar = await client.post(
        f"/api/v1/agentes/enrollment/{enrollment['id']}/revogar", headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_revogar.status_code == 200
    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})

    resp = await client.post(
        "/api/v1/agentes/enroll", json={"hostname": "host-enroll-revogado"}, headers={HEADER_ENROLLMENT: token},
    )
    assert resp.status_code == 403
    assert "revogado" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_enroll_com_token_expirado_e_403(client, superadmin_de_teste, usuario_de_teste):
    empresa_id = usuario_de_teste["empresa_id"]
    await _habilitar_agentes_endpoint(client, superadmin_de_teste, empresa_id)
    _, token = await _criar_token_enrollment(client, usuario_de_teste, minutos=-5)

    resp = await client.post(
        "/api/v1/agentes/enroll", json={"hostname": "host-enroll-expirado"}, headers={HEADER_ENROLLMENT: token},
    )
    assert resp.status_code == 403
    assert "expirado" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_enroll_apos_esgotar_max_usos_e_403(client, superadmin_de_teste, usuario_de_teste):
    empresa_id = usuario_de_teste["empresa_id"]
    await _habilitar_agentes_endpoint(client, superadmin_de_teste, empresa_id)
    _, token = await _criar_token_enrollment(client, usuario_de_teste, max_usos=1)

    resp_1 = await client.post(
        "/api/v1/agentes/enroll", json={"hostname": "host-enroll-esgota-1"}, headers={HEADER_ENROLLMENT: token},
    )
    assert resp_1.status_code == 200

    resp_2 = await client.post(
        "/api/v1/agentes/enroll", json={"hostname": "host-enroll-esgota-2"}, headers={HEADER_ENROLLMENT: token},
    )
    assert resp_2.status_code == 403
    assert "esgotou" in resp_2.json()["detail"]


@pytest.mark.asyncio
async def test_enroll_falha_quando_capacidade_desligada_para_a_empresa(client, superadmin_de_teste, usuario_de_teste):
    """Token de enrollment válido, mas a empresa nunca teve
    agentes_endpoint_habilitado -- mesmo raciocínio de
    test_agentes_api.py:test_heartbeat_falha_quando_capacidade_desligada_para_a_empresa."""
    empresa_id = usuario_de_teste["empresa_id"]
    await _habilitar_agentes_endpoint(client, superadmin_de_teste, empresa_id)
    _, token = await _criar_token_enrollment(client, usuario_de_teste)

    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    resp_desligar = await client.patch(
        f"/api/v1/admin/empresas/{empresa_id}",
        json={"agentes_endpoint_habilitado": False},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_desligar.status_code == 200
    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})

    resp = await client.post(
        "/api/v1/agentes/enroll", json={"hostname": "host-enroll-capacidade-desligada"},
        headers={HEADER_ENROLLMENT: token},
    )
    assert resp.status_code == 403
