# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
/api/v1/agentes -- gestão de agentes (sessão humana normal) e heartbeat
(token de máquina, sem cookie/CSRF) do Sentinela Endpoint.

Segue as convenções de tests/api/test_admin_api.py (fixtures de
conftest_api.py) e tests/api/test_firewall_api.py (toggle de capacidade
opt-in por superadmin antes de exercitar a rota tenant).
"""
from datetime import datetime, timedelta, timezone

import pytest

from sentinela.db.pool import superadmin_scoped_connection
from tests.api.conftest_api import logar

pytestmark = pytest.mark.integration


async def _habilitar_agentes_endpoint(client, superadmin, empresa_id):
    await logar(client, superadmin["email"], superadmin["senha"])
    resp = await client.patch(
        f"/api/v1/admin/empresas/{empresa_id}",
        json={"agentes_endpoint_habilitado": True},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 200
    assert resp.json()["empresa"]["agentes_endpoint_habilitado"] is True
    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})


async def _criar_licenca_para_empresa(client, superadmin, empresa_id, codigo_plano="starter", expira_em=None):
    """Espelha tests/api/test_licencas_api.py:_criar_licenca -- duplicado
    localmente (mesmo padrão já usado neste arquivo para
    `_habilitar_agentes_endpoint`/`_criar_agente_e_obter_token`) porque este
    módulo testa o efeito da licença sobre o HEARTBEAT do agente (Fase D /
    D2), não o ciclo de vida da licença em si (isso já é
    test_licencas_api.py)."""
    await logar(client, superadmin["email"], superadmin["senha"])
    resp_planos = await client.get("/api/v1/admin/planos")
    assert resp_planos.status_code == 200
    plano_id = {p["codigo"]: p["id"] for p in resp_planos.json()["planos"]}[codigo_plano]
    payload = {"plano_id": plano_id}
    if expira_em is not None:
        payload["expira_em"] = expira_em
    resp = await client.post(
        f"/api/v1/admin/empresas/{empresa_id}/licencas", json=payload, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 200
    licenca = resp.json()["licenca"]
    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})
    return licenca


# ---------------------------------------------------------------------------
# Gestão de agentes -- sessão humana (cookie + CSRF)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sem_login_nao_acessa_gestao_de_agentes(client):
    resp = await client.get("/api/v1/agentes")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_admin_cria_lista_e_revoga_agente(client, superadmin_de_teste, usuario_de_teste):
    empresa_id = usuario_de_teste["empresa_id"]
    await _habilitar_agentes_endpoint(client, superadmin_de_teste, empresa_id)

    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])

    resp_criar = await client.post(
        "/api/v1/agentes", json={"hostname": "servidor-cliente-01"}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_criar.status_code == 200
    corpo = resp_criar.json()
    assert corpo["agente"]["hostname"] == "servidor-cliente-01"
    assert corpo["agente"]["status"] == "ativo"
    assert "token_hash" not in corpo["agente"]
    token = corpo["token"]
    assert token.startswith("agt_")
    agente_id = corpo["agente"]["id"]

    resp_lista = await client.get("/api/v1/agentes")
    assert resp_lista.status_code == 200
    assert any(a["id"] == agente_id for a in resp_lista.json()["agentes"])
    # o token em claro nunca aparece de novo -- só na resposta de criação
    assert all("token" not in a for a in resp_lista.json()["agentes"])

    resp_revogar = await client.post(f"/api/v1/agentes/{agente_id}/revogar", headers={"X-Sentinela-CSRF": "1"})
    assert resp_revogar.status_code == 200
    assert resp_revogar.json()["agente"]["status"] == "revogado"


@pytest.mark.asyncio
async def test_analista_nao_cria_agente_mas_pode_listar(client, superadmin_de_teste, analista_de_teste):
    empresa_id = analista_de_teste["empresa_id"]
    await _habilitar_agentes_endpoint(client, superadmin_de_teste, empresa_id)

    await logar(client, analista_de_teste["email"], analista_de_teste["senha"])

    resp_criar = await client.post(
        "/api/v1/agentes", json={"hostname": "servidor-negado"}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_criar.status_code == 403

    resp_lista = await client.get("/api/v1/agentes")
    assert resp_lista.status_code == 200


@pytest.mark.asyncio
async def test_criar_agente_hostname_duplicado_e_409(client, superadmin_de_teste, usuario_de_teste):
    empresa_id = usuario_de_teste["empresa_id"]
    await _habilitar_agentes_endpoint(client, superadmin_de_teste, empresa_id)
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])

    payload = {"hostname": "servidor-duplicado-api"}
    resp_1 = await client.post("/api/v1/agentes", json=payload, headers={"X-Sentinela-CSRF": "1"})
    assert resp_1.status_code == 200
    resp_2 = await client.post("/api/v1/agentes", json=payload, headers={"X-Sentinela-CSRF": "1"})
    assert resp_2.status_code == 409


@pytest.mark.asyncio
async def test_revogar_agente_inexistente_e_404(client, superadmin_de_teste, usuario_de_teste):
    empresa_id = usuario_de_teste["empresa_id"]
    await _habilitar_agentes_endpoint(client, superadmin_de_teste, empresa_id)
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])

    resp = await client.post(
        "/api/v1/agentes/00000000-0000-0000-0000-000000000000/revogar", headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_agente_de_uma_empresa_nao_aparece_para_admin_de_outra(client, superadmin_de_teste, usuario_de_teste, analista_de_teste):
    """usuario_de_teste e analista_de_teste vêm de empresas DIFERENTES (ver
    conftest_api.py) -- reaproveita isso para uma checagem cross-tenant
    rápida pela API, em cima do isolamento que test_agentes_service.py já
    confirma na camada de serviço."""
    empresa_a = usuario_de_teste["empresa_id"]
    await _habilitar_agentes_endpoint(client, superadmin_de_teste, empresa_a)
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    resp_criar = await client.post(
        "/api/v1/agentes", json={"hostname": "servidor-so-da-empresa-a"}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_criar.status_code == 200
    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})

    empresa_b = analista_de_teste["empresa_id"]
    await _habilitar_agentes_endpoint(client, superadmin_de_teste, empresa_b)
    await logar(client, analista_de_teste["email"], analista_de_teste["senha"])
    resp_lista_b = await client.get("/api/v1/agentes")
    assert resp_lista_b.json()["agentes"] == []


# ---------------------------------------------------------------------------
# Heartbeat -- token de máquina, sem cookie/CSRF
# ---------------------------------------------------------------------------

async def _criar_agente_e_obter_token(client, superadmin, usuario, hostname="host-heartbeat-api"):
    empresa_id = usuario["empresa_id"]
    await _habilitar_agentes_endpoint(client, superadmin, empresa_id)
    await logar(client, usuario["email"], usuario["senha"])
    resp = await client.post("/api/v1/agentes", json={"hostname": hostname}, headers={"X-Sentinela-CSRF": "1"})
    assert resp.status_code == 200
    token = resp.json()["token"]
    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})
    return token


@pytest.mark.asyncio
async def test_heartbeat_sem_token_e_422(client):
    """Header ausente é pego pela validação de request do FastAPI (Header(...)
    obrigatório) ANTES de qualquer dependência de autenticação rodar -- 422,
    não 401. Um token presente porém inválido/revogado é o 401 (ver o teste
    seguinte)."""
    resp = await client.post("/api/v1/agentes/heartbeat", json={"hostname": "x"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_heartbeat_com_token_invalido_e_401(client):
    resp = await client.post(
        "/api/v1/agentes/heartbeat", json={"hostname": "x"},
        headers={"X-Sentinela-Agent-Token": "agt_000000000000_forjado"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_heartbeat_com_token_invalido_repetido_e_rate_limitado_com_429(client):
    """
    Correção de bug de revisão crítica (2026-09): sem rate limiting, cada
    tentativa (token válido ou não) roda bcrypt.checkpw na threadpool
    compartilhada da aplicação (ver auth/dependencies.py:agente_atual) --
    um atacante batendo neste endpoint sem token nenhum conseguia esgotar
    essa threadpool. Usa o MESMO limitador compartilhado do login
    (LimitadorTentativasCompartilhado, max_tentativas=5 por padrão),
    chaveado por (ip, prefixo do token) -- o MESMO prefixo forjado
    repetido 5 vezes acumula falha na MESMA chave, e a 6a tentativa recebe
    429 ANTES de qualquer bcrypt rodar.
    """
    for _ in range(5):
        resp = await client.post(
            "/api/v1/agentes/heartbeat", json={"hostname": "x"},
            headers={"X-Sentinela-Agent-Token": "agt_000000000000_forjado"},
        )
        assert resp.status_code == 401

    resp_bloqueado = await client.post(
        "/api/v1/agentes/heartbeat", json={"hostname": "x"},
        headers={"X-Sentinela-Agent-Token": "agt_000000000000_forjado"},
    )
    assert resp_bloqueado.status_code == 429
    assert "Retry-After" in resp_bloqueado.headers


@pytest.mark.asyncio
async def test_heartbeat_com_token_valido_nao_e_afetado_pelo_rate_limit_apos_falhas_de_outro_token(
    client, superadmin_de_teste, usuario_de_teste,
):
    """Um heartbeat bem-sucedido zera o contador de falhas do IP (mesmo
    padrão do /api/v1/auth/login) -- algumas tentativas inválidas seguidas
    de uma válida não devem bloquear o agente legítimo."""
    token = await _criar_agente_e_obter_token(client, superadmin_de_teste, usuario_de_teste, "host-hb-rate-limit-sucesso")

    for _ in range(3):
        resp = await client.post(
            "/api/v1/agentes/heartbeat", json={"hostname": "x"},
            headers={"X-Sentinela-Agent-Token": "agt_000000000000_forjado"},
        )
        assert resp.status_code == 401

    resp_valido = await client.post(
        "/api/v1/agentes/heartbeat",
        json={"hostname": "host-hb-rate-limit-sucesso", "sistema_operacional": "linux", "versao_agente": "0.1.0", "total_processos": 5},
        headers={"X-Sentinela-Agent-Token": token},
    )
    assert resp_valido.status_code == 200


@pytest.mark.asyncio
async def test_heartbeat_agente_valido_nao_e_bloqueado_por_prefixo_diferente_ja_bloqueado(
    client, superadmin_de_teste, usuario_de_teste,
):
    """
    Correção de bug de revisão crítica (2026-09), segunda rodada: a
    primeira versão do rate limiter chaveava só por IP -- 5 falhas de
    QUALQUER token bloqueavam TODOS os agentes atrás do mesmo IP por 5
    minutos. Como agentes EDR tipicamente saem pela mesma NAT/proxy
    corporativo, isso é o caso comum, não uma exceção -- um único agente
    revogado retentando (ou um atacante) conseguia cegar o monitoramento
    de toda a frota. Agora a chave inclui o PREFIXO do token: bloquear um
    prefixo (um token específico, sempre errado) nunca afeta um agente
    com um prefixo DIFERENTE atrás do mesmo IP/cliente.
    """
    token = await _criar_agente_e_obter_token(client, superadmin_de_teste, usuario_de_teste, "host-hb-prefixo-isolado")

    # 5 falhas de um token com prefixo hex válido, mas DIFERENTE do agente real.
    for _ in range(5):
        resp = await client.post(
            "/api/v1/agentes/heartbeat", json={"hostname": "x"},
            headers={"X-Sentinela-Agent-Token": "agt_aaaaaaaaaaaa_forjado"},
        )
        assert resp.status_code == 401

    resp_prefixo_bloqueado = await client.post(
        "/api/v1/agentes/heartbeat", json={"hostname": "x"},
        headers={"X-Sentinela-Agent-Token": "agt_aaaaaaaaaaaa_forjado"},
    )
    assert resp_prefixo_bloqueado.status_code == 429  # aquele prefixo específico está bloqueado

    # o agente de VERDADE (prefixo diferente) nunca falhou -- não deveria ser afetado.
    resp_valido = await client.post(
        "/api/v1/agentes/heartbeat",
        json={"hostname": "host-hb-prefixo-isolado", "sistema_operacional": "linux", "versao_agente": "0.1.0", "total_processos": 5},
        headers={"X-Sentinela-Agent-Token": token},
    )
    assert resp_valido.status_code == 200


@pytest.mark.asyncio
async def test_heartbeat_backstop_por_ip_bloqueia_flood_com_prefixos_forjados_diferentes(client):
    """
    O chaveamento por prefixo (teste acima) abre uma via nova: nada impede
    um atacante de inventar um prefixo hex de 12 chars DIFERENTE a cada
    tentativa (só precisa ter o FORMATO certo, não existir de verdade) e
    nunca acumular falha na mesma chave especifica, driblando aquele
    limite por completo. `app.state.limitador_agente_ip` é o backstop:
    olha só o IP, teto bem mais folgado (40 falhas/60s por padrão), mas
    dispara mesmo quando cada tentativa usa um prefixo novo.
    """
    for i in range(40):
        resp = await client.post(
            "/api/v1/agentes/heartbeat", json={"hostname": "x"},
            headers={"X-Sentinela-Agent-Token": f"agt_{i:012x}_forjado"},
        )
        assert resp.status_code == 401

    resp_bloqueado = await client.post(
        "/api/v1/agentes/heartbeat", json={"hostname": "x"},
        headers={"X-Sentinela-Agent-Token": "agt_ffffffffffff_forjado"},
    )
    assert resp_bloqueado.status_code == 429


@pytest.mark.asyncio
async def test_heartbeat_com_token_valido_sem_processo_suspeito_nao_abre_incidente(client, superadmin_de_teste, usuario_de_teste):
    token = await _criar_agente_e_obter_token(client, superadmin_de_teste, usuario_de_teste, "host-hb-limpo-api")

    resp = await client.post(
        "/api/v1/agentes/heartbeat",
        json={"hostname": "host-hb-limpo-api", "sistema_operacional": "linux", "versao_agente": "0.1.0", "total_processos": 80},
        headers={"X-Sentinela-Agent-Token": token},
    )
    assert resp.status_code == 200
    corpo = resp.json()
    assert corpo["status"] == "ok"
    assert corpo["incidente_criado"] is False
    assert corpo["incidente"] is None


@pytest.mark.asyncio
async def test_heartbeat_com_hostname_divergente_do_registrado_e_409(client, superadmin_de_teste, usuario_de_teste):
    """
    Item "should fix" (6) da revisão crítica (2026-09): um token válido só
    pode reportar heartbeat para o hostname com o qual foi emitido -- não
    pode se autodeclarar como qualquer outro hostname arbitrário no corpo
    da requisição (ver AgenteHostnameDivergenteError em services/agentes.py).
    """
    token = await _criar_agente_e_obter_token(client, superadmin_de_teste, usuario_de_teste, "host-hb-hostname-real-api")

    resp = await client.post(
        "/api/v1/agentes/heartbeat",
        json={"hostname": "host-hb-hostname-fingido-api", "sistema_operacional": "linux", "versao_agente": "0.1.0", "total_processos": 10},
        headers={"X-Sentinela-Agent-Token": token},
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_heartbeat_com_processo_suspeito_abre_incidente_endpoint(client, superadmin_de_teste, usuario_de_teste, pool):
    token = await _criar_agente_e_obter_token(client, superadmin_de_teste, usuario_de_teste, "host-hb-suspeito-api")

    resp = await client.post(
        "/api/v1/agentes/heartbeat",
        json={
            "hostname": "host-hb-suspeito-api", "sistema_operacional": "windows", "versao_agente": "0.1.0",
            "total_processos": 90,
            "processos_suspeitos": [{"pid": 4321, "nome": "mimikatz", "usuario": "SYSTEM", "linha_de_comando": "mimikatz.exe"}],
        },
        headers={"X-Sentinela-Agent-Token": token},
    )
    assert resp.status_code == 200
    corpo = resp.json()
    assert corpo["incidente_criado"] is True
    assert corpo["incidente"]["origem"] == "endpoint"
    # "mimikatz" é um indicador de ferramenta de ataque conhecida
    # (_INDICADORES_CRITICOS em services/agentes.py) -- correção de bug de
    # revisão crítica (2026-09): força CRITICAL mesmo com um único
    # processo, nunca MEDIUM (que cairia no auto-triage depois de 72h sem
    # revisão humana -- ver tests/integration/test_automacao_service.py).
    assert corpo["incidente"]["severidade"] == "CRITICAL"

    async with superadmin_scoped_connection(pool) as conn:
        linha = await conn.fetchrow(
            "SELECT origem FROM incidentes WHERE incident_id = $1", corpo["incidente"]["incident_id"],
        )
    assert linha["origem"] == "endpoint"


@pytest.mark.asyncio
async def test_heartbeat_falha_quando_capacidade_desligada_para_a_empresa(client, superadmin_de_teste, usuario_de_teste):
    """Token válido, mas a empresa NUNCA teve agentes_endpoint_habilitado --
    conexao_tenant_agente (auth/dependencies.py) barra antes de chegar ao
    serviço."""
    empresa_id = usuario_de_teste["empresa_id"]
    # habilita só para poder criar o agente e pegar um token válido...
    await _habilitar_agentes_endpoint(client, superadmin_de_teste, empresa_id)
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    resp_criar = await client.post(
        "/api/v1/agentes", json={"hostname": "host-capacidade-desligada"}, headers={"X-Sentinela-CSRF": "1"},
    )
    token = resp_criar.json()["token"]
    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})

    # ...e então desliga de novo -- o token já emitido não deveria continuar
    # funcionando (mesmo raciocínio de conexao_tenant_agente: revogação
    # imediata, sem esperar o token expirar sozinho -- ele nunca expira).
    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    resp_desligar = await client.patch(
        f"/api/v1/admin/empresas/{empresa_id}",
        json={"agentes_endpoint_habilitado": False},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_desligar.status_code == 200
    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})

    resp_heartbeat = await client.post(
        "/api/v1/agentes/heartbeat",
        json={"hostname": "host-capacidade-desligada"},
        headers={"X-Sentinela-Agent-Token": token},
    )
    assert resp_heartbeat.status_code == 403


@pytest.mark.asyncio
async def test_heartbeat_com_token_de_agente_revogado_e_401(client, superadmin_de_teste, usuario_de_teste):
    empresa_id = usuario_de_teste["empresa_id"]
    await _habilitar_agentes_endpoint(client, superadmin_de_teste, empresa_id)
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])

    resp_criar = await client.post(
        "/api/v1/agentes", json={"hostname": "host-a-revogar-api"}, headers={"X-Sentinela-CSRF": "1"},
    )
    agente_id = resp_criar.json()["agente"]["id"]
    token = resp_criar.json()["token"]

    resp_revogar = await client.post(f"/api/v1/agentes/{agente_id}/revogar", headers={"X-Sentinela-CSRF": "1"})
    assert resp_revogar.status_code == 200

    resp_heartbeat = await client.post(
        "/api/v1/agentes/heartbeat", json={"hostname": "host-a-revogar-api"},
        headers={"X-Sentinela-Agent-Token": token},
    )
    assert resp_heartbeat.status_code == 401


# ---------------------------------------------------------------------------
# Heartbeat <-> status da licença vinculada (Fase D / D2 -- ver
# ARQUITETURA_LICENCIAMENTO.md §10 e o docstring de
# auth/dependencies.py:conexao_tenant_agente para o raciocínio completo).
# Em todos estes testes, a licença é criada ANTES do agente -- é assim que
# o vínculo automático de D1 acontece (ver test_agentes_service.py).
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_heartbeat_bloqueado_quando_licenca_vinculada_e_suspensa(client, superadmin_de_teste, usuario_de_teste):
    empresa_id = usuario_de_teste["empresa_id"]
    licenca = await _criar_licenca_para_empresa(client, superadmin_de_teste, empresa_id)
    token = await _criar_agente_e_obter_token(client, superadmin_de_teste, usuario_de_teste, "host-d2-suspensa")

    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    resp_suspender = await client.post(
        f"/api/v1/admin/licencas/{licenca['id']}/suspender", headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_suspender.status_code == 200
    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})

    resp_heartbeat = await client.post(
        "/api/v1/agentes/heartbeat", json={"hostname": "host-d2-suspensa"},
        headers={"X-Sentinela-Agent-Token": token},
    )
    assert resp_heartbeat.status_code == 403
    assert "licença suspensa" in resp_heartbeat.json()["detail"]


@pytest.mark.asyncio
async def test_heartbeat_bloqueado_quando_licenca_vinculada_e_revogada(client, superadmin_de_teste, usuario_de_teste):
    empresa_id = usuario_de_teste["empresa_id"]
    licenca = await _criar_licenca_para_empresa(client, superadmin_de_teste, empresa_id)
    token = await _criar_agente_e_obter_token(client, superadmin_de_teste, usuario_de_teste, "host-d2-revogada")

    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    resp_revogar = await client.post(
        f"/api/v1/admin/licencas/{licenca['id']}/revogar", headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_revogar.status_code == 200
    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})

    resp_heartbeat = await client.post(
        "/api/v1/agentes/heartbeat", json={"hostname": "host-d2-revogada"},
        headers={"X-Sentinela-Agent-Token": token},
    )
    assert resp_heartbeat.status_code == 403
    assert "licença revogada" in resp_heartbeat.json()["detail"]


@pytest.mark.asyncio
async def test_heartbeat_bloqueado_quando_licenca_vinculada_ja_expirou(client, superadmin_de_teste, usuario_de_teste):
    """Licença formalmente 'ativa' (nunca revogada/suspensa manualmente),
    mas com `expira_em` no passado -- `conexao_tenant_agente` trata isso
    como 'expirada' para efeito do heartbeat (ver docstring), mesmo sem
    nenhum job de expiração automática rodando."""
    empresa_id = usuario_de_teste["empresa_id"]
    ontem = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    await _criar_licenca_para_empresa(client, superadmin_de_teste, empresa_id, expira_em=ontem)
    token = await _criar_agente_e_obter_token(client, superadmin_de_teste, usuario_de_teste, "host-d2-expirada")

    resp_heartbeat = await client.post(
        "/api/v1/agentes/heartbeat", json={"hostname": "host-d2-expirada"},
        headers={"X-Sentinela-Agent-Token": token},
    )
    assert resp_heartbeat.status_code == 403
    assert "licença expirada" in resp_heartbeat.json()["detail"]


@pytest.mark.asyncio
async def test_heartbeat_funciona_normalmente_quando_licenca_vinculada_continua_ativa(client, superadmin_de_teste, usuario_de_teste):
    empresa_id = usuario_de_teste["empresa_id"]
    await _criar_licenca_para_empresa(client, superadmin_de_teste, empresa_id)
    token = await _criar_agente_e_obter_token(client, superadmin_de_teste, usuario_de_teste, "host-d2-ativa")

    resp = await client.post(
        "/api/v1/agentes/heartbeat",
        json={"hostname": "host-d2-ativa", "sistema_operacional": "linux", "versao_agente": "0.1.0", "total_processos": 5},
        headers={"X-Sentinela-Agent-Token": token},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_heartbeat_sem_nenhuma_licenca_vinculada_continua_funcionando(client, superadmin_de_teste, usuario_de_teste):
    """Empresa que nunca provisionou licença nenhuma -- zero regressão para
    o comportamento que já existia antes da Fase D (licenciamento continua
    opcional, ver docstring de services/agentes.py:criar_agente)."""
    token = await _criar_agente_e_obter_token(client, superadmin_de_teste, usuario_de_teste, "host-d2-sem-licenca")

    resp = await client.post(
        "/api/v1/agentes/heartbeat",
        json={"hostname": "host-d2-sem-licenca", "sistema_operacional": "linux", "versao_agente": "0.1.0", "total_processos": 5},
        headers={"X-Sentinela-Agent-Token": token},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_heartbeat_hostname_vazio_e_422(client, superadmin_de_teste, usuario_de_teste):
    token = await _criar_agente_e_obter_token(client, superadmin_de_teste, usuario_de_teste, "host-422-api")
    resp = await client.post(
        "/api/v1/agentes/heartbeat", json={"hostname": ""}, headers={"X-Sentinela-Agent-Token": token},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_heartbeat_ip_local_invalido_e_422(client, superadmin_de_teste, usuario_de_teste):
    """
    Correção de bug de revisão crítica (2026-09), segunda rodada:
    `ip_local` era o único ponto de entrada de IP do sistema sem validação
    -- um valor sem forma de IP estourava `asyncpg.exceptions.DataError`
    (não é `ValueError`, não é pego pelo handler genérico) dentro do
    INSERT do incidente, virando 500 e, pior, derrubando o ROLLBACK de
    TUDO que já tinha sido gravado nesta mesma transação (o evento bruto
    de heartbeat, o `ultimo_heartbeat_em`) -- perdendo até o rastro de
    auditoria de um heartbeat com processo suspeito de verdade. Agora
    valida com `util.ip_valido` (mesmo padrão de todo outro endpoint que
    aceita IP) e rejeita com 422 antes de tocar o banco.
    """
    token = await _criar_agente_e_obter_token(client, superadmin_de_teste, usuario_de_teste, "host-ip-local-invalido-api")
    resp = await client.post(
        "/api/v1/agentes/heartbeat",
        json={
            "hostname": "host-ip-local-invalido-api",
            "processos_suspeitos": [{"pid": 1, "nome": "processo_desconhecido.exe"}],
            "ip_local": "isto-nao-e-um-ip",
        },
        headers={"X-Sentinela-Agent-Token": token},
    )
    assert resp.status_code == 422

    # o heartbeat rejeitado não deve deixar rastro nenhum -- nem o evento
    # bruto, nem o timestamp de heartbeat (a rejeição acontece na
    # validação do Pydantic, ANTES de qualquer escrita no banco).
    resp_status = await client.post(
        "/api/v1/agentes/heartbeat",
        json={"hostname": "host-ip-local-invalido-api", "total_processos": 1},
        headers={"X-Sentinela-Agent-Token": token},
    )
    assert resp_status.status_code == 200  # confirma que o token/agente continuam saudáveis
