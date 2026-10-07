# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
/api/v1/licencas (agent-facing) e /api/v1/admin/... (superadmin) --
Sentinela SaaS licenciamento. Ver ARQUITETURA_LICENCIAMENTO.md.

Segue as convenções de tests/api/test_agentes_api.py: fixtures de
conftest_api.py, sessão de superadmin via `logar` + cookie, header
`X-Sentinela-CSRF: 1` em toda rota mutável de sessão humana.
"""
import time
import uuid

import pytest

from tests.api.conftest_api import logar

pytestmark = pytest.mark.integration

HEADER_TOKEN = "X-Sentinela-License-Token"
# Fase D / D6 -- headers de anti-replay, obrigatórios em toda chamada
# autenticada por token de licença (ver ARQUITETURA_LICENCIAMENTO.md §11 e
# auth/dependencies.py:licenca_atual).
HEADER_TIMESTAMP = "X-Sentinela-License-Timestamp"
HEADER_NONCE = "X-Sentinela-License-Nonce"


def _headers_licenca(token, nonce=None, timestamp=None):
    """Monta os 3 headers exigidos por `licenca_atual` -- um nonce NOVO a
    cada chamada por padrão (`uuid4`), exatamente como um Agent de verdade
    (D4, ainda não construído) precisaria gerar. Testes que querem
    exercitar replay/timestamp inválido passam `nonce`/`timestamp`
    explicitamente."""
    return {
        HEADER_TOKEN: token,
        HEADER_TIMESTAMP: str(timestamp if timestamp is not None else time.time()),
        HEADER_NONCE: nonce if nonce is not None else uuid.uuid4().hex,
    }


async def _obter_plano_id(client, superadmin, codigo="starter"):
    await logar(client, superadmin["email"], superadmin["senha"])
    resp = await client.get("/api/v1/admin/planos")
    assert resp.status_code == 200
    planos = {p["codigo"]: p["id"] for p in resp.json()["planos"]}
    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})
    return planos[codigo]


async def _criar_licenca(client, superadmin, empresa_id, codigo_plano="starter"):
    plano_id = await _obter_plano_id(client, superadmin, codigo_plano)
    await logar(client, superadmin["email"], superadmin["senha"])
    resp = await client.post(
        f"/api/v1/admin/empresas/{empresa_id}/licencas",
        json={"plano_id": plano_id},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 200
    corpo = resp.json()
    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})
    return corpo["licenca"], corpo["token"]


# ---------------------------------------------------------------------------
# Rotas do Agent (token de licença, sem cookie/CSRF)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_activate_com_token_invalido_e_401(client):
    resp = await client.post(
        "/api/v1/licencas/activate",
        headers=_headers_licenca("lic_000000000000_forjado"),
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_status_sem_header_de_token_e_422(client):
    """Header obrigatório ausente -- FastAPI valida antes de qualquer
    dependência de autenticação rodar."""
    resp = await client.get(
        "/api/v1/licencas/status",
        headers={HEADER_TIMESTAMP: str(time.time()), HEADER_NONCE: uuid.uuid4().hex},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_fluxo_completo_activate_validate_status_deactivate(client, superadmin_de_teste, usuario_de_teste):
    empresa_id = usuario_de_teste["empresa_id"]
    licenca, token = await _criar_licenca(client, superadmin_de_teste, empresa_id)
    assert token.startswith("lic_")
    assert licenca["ativada_em"] is None

    resp_activate = await client.post("/api/v1/licencas/activate", headers=_headers_licenca(token))
    assert resp_activate.status_code == 200
    assert resp_activate.json()["licenca"]["ativada_em"] is not None

    resp_validate = await client.post("/api/v1/licencas/validate", headers=_headers_licenca(token))
    assert resp_validate.status_code == 200
    corpo_validate = resp_validate.json()["licenca"]
    assert corpo_validate["status"] == "ativa"
    assert corpo_validate["plano"]["codigo"] == "starter"
    assert "grace_period_dias" in corpo_validate["plano"]["recursos"]

    resp_status = await client.get("/api/v1/licencas/status", headers=_headers_licenca(token))
    assert resp_status.status_code == 200
    assert resp_status.json()["licenca"]["status"] == "ativa"

    resp_deactivate = await client.post("/api/v1/licencas/deactivate", headers=_headers_licenca(token))
    assert resp_deactivate.status_code == 200
    # desinstalar o Agent não cancela a licença -- continua 'ativa'
    assert resp_deactivate.json()["licenca"]["status"] == "ativa"


@pytest.mark.asyncio
async def test_licenca_suspensa_activate_e_validate_retornam_403_mas_status_nao(
    client, superadmin_de_teste, usuario_de_teste,
):
    empresa_id = usuario_de_teste["empresa_id"]
    licenca, token = await _criar_licenca(client, superadmin_de_teste, empresa_id)

    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    resp_suspender = await client.post(
        f"/api/v1/admin/licencas/{licenca['id']}/suspender", headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_suspender.status_code == 200
    assert resp_suspender.json()["licenca"]["status"] == "suspensa"
    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})

    resp_activate = await client.post("/api/v1/licencas/activate", headers=_headers_licenca(token))
    assert resp_activate.status_code == 403

    resp_validate = await client.post("/api/v1/licencas/validate", headers=_headers_licenca(token))
    assert resp_validate.status_code == 403

    # /status nunca levanta por causa do status da licença -- é inspeção pontual
    resp_status = await client.get("/api/v1/licencas/status", headers=_headers_licenca(token))
    assert resp_status.status_code == 200
    assert resp_status.json()["licenca"]["status"] == "suspensa"

    # /deactivate também é best-effort, aceita mesmo suspensa
    resp_deactivate = await client.post("/api/v1/licencas/deactivate", headers=_headers_licenca(token))
    assert resp_deactivate.status_code == 200


@pytest.mark.asyncio
async def test_empresa_suspensa_bloqueia_todas_as_rotas_de_licenca(client, superadmin_de_teste, usuario_de_teste):
    empresa_id = usuario_de_teste["empresa_id"]
    _, token = await _criar_licenca(client, superadmin_de_teste, empresa_id)

    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    resp_empresa = await client.patch(
        f"/api/v1/admin/empresas/{empresa_id}", json={"status": "suspensa"}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_empresa.status_code == 200
    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})

    resp = await client.post("/api/v1/licencas/validate", headers=_headers_licenca(token))
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Anti-replay (Fase D / D6 -- ver ARQUITETURA_LICENCIAMENTO.md §11 e o
# docstring de auth/dependencies.py:licenca_atual para o desenho completo).
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sem_header_de_timestamp_ou_nonce_e_422(client, superadmin_de_teste, usuario_de_teste):
    """Headers obrigatórios ausentes -- FastAPI valida antes de qualquer
    dependência de autenticação rodar (mesmo padrão do token em si)."""
    empresa_id = usuario_de_teste["empresa_id"]
    _, token = await _criar_licenca(client, superadmin_de_teste, empresa_id)

    resp_sem_timestamp = await client.post(
        "/api/v1/licencas/validate", headers={HEADER_TOKEN: token, HEADER_NONCE: uuid.uuid4().hex},
    )
    assert resp_sem_timestamp.status_code == 422

    resp_sem_nonce = await client.post(
        "/api/v1/licencas/validate", headers={HEADER_TOKEN: token, HEADER_TIMESTAMP: str(time.time())},
    )
    assert resp_sem_nonce.status_code == 422


@pytest.mark.asyncio
async def test_timestamp_nao_numerico_e_401(client, superadmin_de_teste, usuario_de_teste):
    empresa_id = usuario_de_teste["empresa_id"]
    _, token = await _criar_licenca(client, superadmin_de_teste, empresa_id)

    resp = await client.post(
        "/api/v1/licencas/validate",
        headers={HEADER_TOKEN: token, HEADER_TIMESTAMP: "isto-nao-e-um-numero", HEADER_NONCE: uuid.uuid4().hex},
    )
    assert resp.status_code == 401
    assert "timestamp" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_timestamp_muito_antigo_e_401(client, superadmin_de_teste, usuario_de_teste):
    """Fora da janela de replay (JANELA_REPLAY_SEGUNDOS=300s) -- simula uma
    requisição capturada e reapresentada bem depois."""
    empresa_id = usuario_de_teste["empresa_id"]
    _, token = await _criar_licenca(client, superadmin_de_teste, empresa_id)

    resp = await client.post(
        "/api/v1/licencas/validate", headers=_headers_licenca(token, timestamp=time.time() - 3600),
    )
    assert resp.status_code == 401
    assert "timestamp" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_timestamp_muito_no_futuro_e_401(client, superadmin_de_teste, usuario_de_teste):
    """A janela é simétrica -- um clock do Agent adiantado demais também é
    recusado, não só um atrasado (proteção contra um relógio manipulado de
    propósito para estender a janela de replay)."""
    empresa_id = usuario_de_teste["empresa_id"]
    _, token = await _criar_licenca(client, superadmin_de_teste, empresa_id)

    resp = await client.post(
        "/api/v1/licencas/validate", headers=_headers_licenca(token, timestamp=time.time() + 3600),
    )
    assert resp.status_code == 401
    assert "timestamp" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_nonce_vazio_e_401(client, superadmin_de_teste, usuario_de_teste):
    empresa_id = usuario_de_teste["empresa_id"]
    _, token = await _criar_licenca(client, superadmin_de_teste, empresa_id)

    resp = await client.post("/api/v1/licencas/validate", headers=_headers_licenca(token, nonce=""))
    assert resp.status_code == 401
    assert "nonce" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_reapresentar_o_mesmo_nonce_e_recusado_como_replay(client, superadmin_de_teste, usuario_de_teste):
    """O caso central que D6 existe para cobrir: a MESMA requisição (mesmo
    token, mesmo timestamp, mesmo nonce) sendo reapresentada -- a primeira
    vez passa, a segunda (idêntica) é recusada como replay, mesmo dentro da
    janela de tempo válida e com o token continuando perfeitamente válido."""
    empresa_id = usuario_de_teste["empresa_id"]
    _, token = await _criar_licenca(client, superadmin_de_teste, empresa_id)
    headers = _headers_licenca(token)

    resp_1 = await client.post("/api/v1/licencas/validate", headers=headers)
    assert resp_1.status_code == 200

    resp_2 = await client.post("/api/v1/licencas/validate", headers=headers)
    assert resp_2.status_code == 401
    assert "replay" in resp_2.json()["detail"]


@pytest.mark.asyncio
async def test_nonce_diferente_apos_replay_recusado_continua_funcionando(client, superadmin_de_teste, usuario_de_teste):
    """Um nonce recusado por replay não "queima" a licença nem o token --
    a PRÓXIMA chamada, com um nonce novo, funciona normalmente (mesmo
    raciocínio de `test_heartbeat_com_token_valido_nao_e_afetado_pelo_rate_limit...`
    em test_agentes_api.py: uma falha não deveria derrubar o cliente
    legítimo)."""
    empresa_id = usuario_de_teste["empresa_id"]
    _, token = await _criar_licenca(client, superadmin_de_teste, empresa_id)
    headers_repetidos = _headers_licenca(token)

    await client.post("/api/v1/licencas/validate", headers=headers_repetidos)
    resp_replay = await client.post("/api/v1/licencas/validate", headers=headers_repetidos)
    assert resp_replay.status_code == 401

    resp_novo = await client.post("/api/v1/licencas/validate", headers=_headers_licenca(token))
    assert resp_novo.status_code == 200


@pytest.mark.asyncio
async def test_mesmo_nonce_em_licencas_diferentes_nao_colide(client, superadmin_de_teste, usuario_de_teste, analista_de_teste):
    """O nonce é escopado POR LICENÇA (ver ARQUITETURA_LICENCIAMENTO.md
    §11) -- duas licenças de empresas diferentes usando o mesmo valor de
    nonce (coincidência plausível: cada Agent gera o seu independentemente)
    não devem colidir entre si."""
    empresa_a = usuario_de_teste["empresa_id"]
    empresa_b = analista_de_teste["empresa_id"]
    _, token_a = await _criar_licenca(client, superadmin_de_teste, empresa_a)
    _, token_b = await _criar_licenca(client, superadmin_de_teste, empresa_b)

    nonce_compartilhado = uuid.uuid4().hex
    resp_a = await client.post(
        "/api/v1/licencas/validate", headers=_headers_licenca(token_a, nonce=nonce_compartilhado),
    )
    resp_b = await client.post(
        "/api/v1/licencas/validate", headers=_headers_licenca(token_b, nonce=nonce_compartilhado),
    )
    assert resp_a.status_code == 200
    assert resp_b.status_code == 200


# ---------------------------------------------------------------------------
# Rotas administrativas (superadmin)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sem_login_nao_acessa_rotas_admin_de_licenca(client):
    resp = await client.get("/api/v1/admin/planos")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_listar_planos_inclui_os_quatro_planos_padrao(client, superadmin_de_teste):
    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    resp = await client.get("/api/v1/admin/planos")
    assert resp.status_code == 200
    codigos = {p["codigo"] for p in resp.json()["planos"]}
    # subset, não igualdade -- outros testes de integração podem ter
    # inserido planos extras de teste no mesmo banco compartilhado.
    assert {"starter", "professional", "business", "enterprise"}.issubset(codigos)


@pytest.mark.asyncio
async def test_criar_licenca_com_plano_invalido_e_422(client, superadmin_de_teste, usuario_de_teste):
    empresa_id = usuario_de_teste["empresa_id"]
    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    resp = await client.post(
        f"/api/v1/admin/empresas/{empresa_id}/licencas",
        json={"plano_id": "00000000-0000-0000-0000-000000000000"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_criar_licenca_para_empresa_inexistente_e_404(client, superadmin_de_teste):
    plano_id = await _obter_plano_id(client, superadmin_de_teste)
    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    resp = await client.post(
        "/api/v1/admin/empresas/00000000-0000-0000-0000-000000000000/licencas",
        json={"plano_id": plano_id},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_superadmin_lista_licencas_de_uma_empresa(client, superadmin_de_teste, usuario_de_teste):
    empresa_id = usuario_de_teste["empresa_id"]
    licenca, _ = await _criar_licenca(client, superadmin_de_teste, empresa_id)

    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    resp = await client.get(f"/api/v1/admin/empresas/{empresa_id}/licencas")
    assert resp.status_code == 200
    assert any(item["id"] == licenca["id"] for item in resp.json()["licencas"])


@pytest.mark.asyncio
async def test_revogar_licenca_e_definitiva_renovar_depois_e_422(client, superadmin_de_teste, usuario_de_teste):
    empresa_id = usuario_de_teste["empresa_id"]
    licenca, _ = await _criar_licenca(client, superadmin_de_teste, empresa_id)

    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    resp_revogar = await client.post(
        f"/api/v1/admin/licencas/{licenca['id']}/revogar", headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_revogar.status_code == 200
    assert resp_revogar.json()["licenca"]["status"] == "revogada"

    resp_renovar = await client.post(
        f"/api/v1/admin/licencas/{licenca['id']}/renovar", json={}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_renovar.status_code == 422


@pytest.mark.asyncio
async def test_licenca_de_uma_empresa_nao_e_visivel_para_admin_de_outra_empresa(
    client, superadmin_de_teste, usuario_de_teste, analista_de_teste,
):
    """A rota admin é a única que gerencia licenças (superadmin, BYPASSRLS
    escopado à empresa via WHERE explícito) -- confirma que um admin
    comum (sessão humana normal, não superadmin) nunca acessa a rota
    administrativa de licenças."""
    empresa_id = usuario_de_teste["empresa_id"]
    await _criar_licenca(client, superadmin_de_teste, empresa_id)

    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    resp = await client.get(f"/api/v1/admin/empresas/{empresa_id}/licencas")
    assert resp.status_code == 401  # exigir_superadmin rejeita sessão de usuário comum
