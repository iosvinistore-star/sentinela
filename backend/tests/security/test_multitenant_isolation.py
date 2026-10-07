# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Suíte DEDICADA de isolamento multi-tenant -- item 2 do plano de
endurecimento pós-auditoria ("a validação de segurança mais importante do
projeto").

Não substitui tests/integration/test_rls_isolation.py (que prova o
isolamento na camada de banco, RLS pura) nem os testes de cross-tenant já
espalhados em alguns arquivos de tests/api/*.py -- esta suíte ataca a
aplicação pela borda HTTP, como um ATACANTE AUTENTICADO (um usuário real
de uma empresa, ou alguém com um JWT de assinatura válida mas claims
adulteradas) tentaria: IDOR por ID conhecido/adivinhado contra CADA
recurso do sistema (incidentes, usuários, firewall, auditoria, reputação,
dashboard, upload de log), pelas DUAS superfícies (API JSON e HTMX web), e
adulteração direta das claims `empresa_id`/`papel`/`sub` de um JWT --
cenário que nenhum teste de nível de rota cobria até agora, e que expôs
uma lacuna real (ver o comentário longo em auth/dependencies.py:
conexao_tenant sobre o `AND empresa_id = $2`, corrigido junto com esta
suíte).

Convenção: `tenant_a`/`tenant_b` são duas empresas completas e totalmente
independentes (cada uma com seu próprio admin e analista) -- todo teste
tenta cruzar B -> A (B tentando ver/mexer em algo de A), nunca o
contrário, só para manter a leitura consistente.
"""
import io
import os
import uuid

import pytest
import pytest_asyncio

from sentinela.auth.dependencies import NOME_COOKIE_SESSAO
from sentinela.auth.security import emitir_token_sessao, hash_senha
from sentinela.db.pool import superadmin_scoped_connection
from tests.api.conftest_api import logar

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Fixtures: dois tenants completos e independentes.
# ---------------------------------------------------------------------------

async def _criar_usuario(pool, empresa_id, papel, senha="senha-forte-123"):
    email = f"{papel}-{uuid.uuid4()}@example.com"
    usuario_id = uuid.uuid4()
    async with superadmin_scoped_connection(pool) as conn:
        await conn.execute(
            "INSERT INTO usuarios (id, empresa_id, email, papel, senha_hash) VALUES ($1, $2, $3, $4, $5)",
            usuario_id, empresa_id, email, papel, hash_senha(senha),
        )
    return {"id": usuario_id, "empresa_id": empresa_id, "email": email, "senha": senha, "papel": papel}


@pytest_asyncio.fixture
async def tenant_a(pool, empresa_factory):
    empresa_id = await empresa_factory("Tenant A -- Isolamento")
    return {
        "empresa_id": empresa_id,
        "admin": await _criar_usuario(pool, empresa_id, "admin"),
        "analista": await _criar_usuario(pool, empresa_id, "analista"),
        # Fase C -- RBAC de 5 papéis (ver auth/rbac.py).
        "viewer": await _criar_usuario(pool, empresa_id, "viewer"),
    }


@pytest_asyncio.fixture
async def tenant_b(pool, empresa_factory):
    empresa_id = await empresa_factory("Tenant B -- Isolamento")
    return {
        "empresa_id": empresa_id,
        "admin": await _criar_usuario(pool, empresa_id, "admin"),
        "analista": await _criar_usuario(pool, empresa_id, "analista"),
        "viewer": await _criar_usuario(pool, empresa_id, "viewer"),
    }


async def _criar_incidente(pool, empresa_id, ip, incident_id=None):
    incident_id = incident_id or f"INC-ISOL-{uuid.uuid4().hex[:12]}"
    async with superadmin_scoped_connection(pool) as conn:
        await conn.execute(
            """
            INSERT INTO incidentes (empresa_id, incident_id, ip, severidade, pontuacao_risco, ataques)
            VALUES ($1, $2, $3, 'HIGH', 75, '["SQL Injection (SQLi)"]'::jsonb)
            """,
            empresa_id, incident_id, ip,
        )
    return incident_id


async def _criar_bloqueio_direto(pool, empresa_id, ip, usuario_id=None):
    """Insere direto na tabela -- sem passar por core.firewall/ipset (ver
    services/firewall.py:registrar_bloqueio) -- porque o que este arquivo
    testa é isolamento de DADOS por tenant, não o kernel de firewall em si
    (isso já é coberto por tests/unit/test_firewall_kernel.py e
    tests/api/test_firewall_api.py)."""
    async with superadmin_scoped_connection(pool) as conn:
        await conn.execute(
            """
            INSERT INTO bloqueios_firewall (empresa_id, ip, motivo, origem, status, criado_por_usuario_id)
            VALUES ($1, $2, 'teste de isolamento', 'api', 'ativo', $3)
            """,
            empresa_id, ip, usuario_id,
        )


async def _status_bloqueio(pool, empresa_id, ip):
    async with superadmin_scoped_connection(pool) as conn:
        return await conn.fetchval(
            "SELECT status FROM bloqueios_firewall WHERE empresa_id = $1 AND ip = $2", empresa_id, ip,
        )


async def _papel_e_ativo(pool, usuario_id):
    async with superadmin_scoped_connection(pool) as conn:
        row = await conn.fetchrow("SELECT papel, ativo FROM usuarios WHERE id = $1", usuario_id)
    return dict(row)


def _forjar_cookie_sessao(payload: dict) -> str:
    """Assina um JWT de sessão com o MESMO segredo que a app de teste usa
    (JWT_SECRET, setado por tests/api/conftest_api.py:app_instance) --
    simula tanto um segredo vazado quanto (mais realisticamente) um bug de
    emissão que gravasse uma claim errada num token por outro lado
    legítimo. O que se testa aqui é se a APLICAÇÃO detecta a claim
    adulterada, não a força criptográfica da assinatura em si."""
    return emitir_token_sessao(payload, os.environ["JWT_SECRET"], horas_validade=1)


# ---------------------------------------------------------------------------
# Incidentes -- API JSON
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_listar_incidentes_nao_vaza_de_outra_empresa(client, tenant_a, tenant_b, pool):
    incident_id_a = await _criar_incidente(pool, tenant_a["empresa_id"], "203.0.113.201")
    await logar(client, tenant_b["admin"]["email"], tenant_b["admin"]["senha"])

    resp = await client.get("/api/v1/incidentes")
    assert resp.status_code == 200
    assert incident_id_a not in {i["incident_id"] for i in resp.json()["incidentes"]}


@pytest.mark.asyncio
async def test_api_obter_incidente_de_outra_empresa_e_404(client, tenant_a, tenant_b, pool):
    incident_id_a = await _criar_incidente(pool, tenant_a["empresa_id"], "203.0.113.202")
    await logar(client, tenant_b["admin"]["email"], tenant_b["admin"]["senha"])

    resp = await client.get(f"/api/v1/incidentes/{incident_id_a}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_api_triar_incidente_de_outra_empresa_e_404_e_nao_altera_nada(client, tenant_a, tenant_b, pool):
    incident_id_a = await _criar_incidente(pool, tenant_a["empresa_id"], "203.0.113.203")
    await logar(client, tenant_b["admin"]["email"], tenant_b["admin"]["senha"])

    resp = await client.patch(
        f"/api/v1/incidentes/{incident_id_a}/status",
        json={"status": "RESOLVIDO", "observacoes": "tentativa cross-tenant"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 404

    async with superadmin_scoped_connection(pool) as conn:
        status = await conn.fetchval(
            "SELECT status FROM incidentes WHERE empresa_id = $1 AND incident_id = $2",
            tenant_a["empresa_id"], incident_id_a,
        )
    assert status == "OPEN"


# ---------------------------------------------------------------------------
# Incidentes -- HTMX web
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_web_detalhe_incidente_de_outra_empresa_e_404(client, tenant_a, tenant_b, pool):
    incident_id_a = await _criar_incidente(pool, tenant_a["empresa_id"], "203.0.113.204")
    await client.post("/login", data={"email": tenant_b["admin"]["email"], "senha": tenant_b["admin"]["senha"]})

    resp = await client.get(f"/incidentes/{incident_id_a}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_web_triar_incidente_de_outra_empresa_e_404_e_nao_altera_nada(client, tenant_a, tenant_b, pool):
    incident_id_a = await _criar_incidente(pool, tenant_a["empresa_id"], "203.0.113.205")
    await client.post("/login", data={"email": tenant_b["admin"]["email"], "senha": tenant_b["admin"]["senha"]})

    resp = await client.post(
        f"/incidentes/{incident_id_a}/status",
        data={"status": "RESOLVIDO", "observacoes": "tentativa cross-tenant via htmx"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 404

    async with superadmin_scoped_connection(pool) as conn:
        status = await conn.fetchval(
            "SELECT status FROM incidentes WHERE empresa_id = $1 AND incident_id = $2",
            tenant_a["empresa_id"], incident_id_a,
        )
    assert status == "OPEN"


# ---------------------------------------------------------------------------
# Usuários -- API JSON e web
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_listar_usuarios_nao_vaza_de_outra_empresa(client, tenant_a, tenant_b):
    await logar(client, tenant_b["admin"]["email"], tenant_b["admin"]["senha"])
    resp = await client.get("/api/v1/usuarios")
    assert resp.status_code == 200
    emails_visiveis = {u["email"] for u in resp.json()["usuarios"]}
    assert tenant_a["admin"]["email"] not in emails_visiveis
    assert tenant_a["analista"]["email"] not in emails_visiveis


@pytest.mark.asyncio
async def test_api_atualizar_usuario_de_outra_empresa_e_404_e_nao_altera_nada(client, tenant_a, tenant_b, pool):
    alvo = tenant_a["analista"]
    await logar(client, tenant_b["admin"]["email"], tenant_b["admin"]["senha"])

    resp = await client.patch(
        f"/api/v1/usuarios/{alvo['id']}",
        json={"papel": "admin", "ativo": False},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 404

    estado = await _papel_e_ativo(pool, alvo["id"])
    assert estado == {"papel": "analista", "ativo": True}


@pytest.mark.asyncio
async def test_web_atualizar_usuario_de_outra_empresa_nao_altera_nada(client, tenant_a, tenant_b, pool):
    alvo = tenant_a["analista"]
    await client.post("/login", data={"email": tenant_b["admin"]["email"], "senha": tenant_b["admin"]["senha"]})

    resp = await client.patch(
        f"/usuarios/{alvo['id']}",
        data={"papel": "admin", "ativo": "false"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    # A rota web devolve 200 com a listagem (própria, sem o alvo) mesmo em
    # "não encontrado" (mesmo padrão de UX HTMX do resto do projeto) -- o
    # que importa é que o estado real do usuário-alvo, em OUTRA empresa,
    # nunca muda.
    assert resp.status_code == 200
    assert alvo["email"] not in resp.text

    estado = await _papel_e_ativo(pool, alvo["id"])
    assert estado == {"papel": "analista", "ativo": True}


# ---------------------------------------------------------------------------
# Firewall -- API JSON e web
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_listar_bloqueios_nao_vaza_de_outra_empresa(client, tenant_a, tenant_b, pool):
    await _criar_bloqueio_direto(pool, tenant_a["empresa_id"], "203.0.113.211")
    await logar(client, tenant_b["admin"]["email"], tenant_b["admin"]["senha"])

    resp = await client.get("/api/v1/firewall/bloqueios")
    assert resp.status_code == 200
    assert "203.0.113.211" not in {b["ip"] for b in resp.json()["bloqueios"]}


@pytest.mark.asyncio
async def test_api_remover_bloqueio_de_outra_empresa_nao_altera_registro_da_dona(client, tenant_a, tenant_b, pool, monkeypatch):
    from sentinela.core import firewall as core_firewall

    ip = "203.0.113.212"
    await _criar_bloqueio_direto(pool, tenant_a["empresa_id"], ip)
    monkeypatch.setattr(core_firewall, "_tem_privilegios_root", lambda: True)
    monkeypatch.setattr(
        core_firewall.subprocess, "run",
        lambda cmd, **kw: type("R", (), {"returncode": 0, "stdout": ""})(),
    )
    await logar(client, tenant_b["admin"]["email"], tenant_b["admin"]["senha"])

    resp = await client.delete(f"/api/v1/firewall/bloqueios/{ip}", headers={"X-Sentinela-CSRF": "1"})
    assert resp.status_code == 200

    # Desde a correção do cenário cross-tenant, `remover_bloqueio` recusa a
    # ação ANTES de tocar em qualquer coisa -- tenant_b não tem nenhuma
    # linha PRÓPRIA 'ativo' para este IP (só tenant_a tem), então nem chega
    # a chamar `core_firewall.desbloquear_ip` (host-wide) nem a mexer no
    # Postgres. Ver tests/integration/test_firewall_service.py para a
    # cobertura direta de serviço deste comportamento (incluindo o caso em
    # que as DUAS empresas têm bloqueio próprio do mesmo IP).
    assert resp.json()["resultado"]["status"] == "erro"
    assert await _status_bloqueio(pool, tenant_a["empresa_id"], ip) == "ativo"


@pytest.mark.asyncio
async def test_web_listar_bloqueios_nao_vaza_de_outra_empresa(client, tenant_a, tenant_b, pool):
    await _criar_bloqueio_direto(pool, tenant_a["empresa_id"], "203.0.113.213")
    await client.post("/login", data={"email": tenant_b["admin"]["email"], "senha": tenant_b["admin"]["senha"]})

    resp = await client.get("/firewall")
    assert resp.status_code == 200
    assert "203.0.113.213" not in resp.text


# ---------------------------------------------------------------------------
# Auditoria -- API JSON
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_listar_auditoria_nao_vaza_de_outra_empresa(client, tenant_a, tenant_b, pool):
    from sentinela.services import auditoria as servico_auditoria

    async with superadmin_scoped_connection(pool) as conn:
        await servico_auditoria.registrar_evento(
            conn, tenant_a["empresa_id"], "teste.evento_sigiloso_tenant_a", {"segredo": "nao deveria vazar"},
        )
    await logar(client, tenant_b["admin"]["email"], tenant_b["admin"]["senha"])

    resp = await client.get("/api/v1/auditoria")
    assert resp.status_code == 200
    acoes = {e["acao"] for e in resp.json()["auditoria"]}
    assert "teste.evento_sigiloso_tenant_a" not in acoes


# ---------------------------------------------------------------------------
# Reputação -- API JSON (cache tenant-scoped)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_cache_de_reputacao_e_isolado_por_empresa(client, tenant_a, tenant_b):
    from unittest.mock import patch

    from sentinela.core import reputacao as core_reputacao

    ip = "203.0.113.214"
    await logar(client, tenant_a["admin"]["email"], tenant_a["admin"]["senha"])
    with patch.object(core_reputacao, "consultar_abuseipdb", return_value={"score_abuso": 95}), \
         patch.object(core_reputacao, "consultar_virustotal", return_value={"maliciosos": 10}):
        resp_a = await client.get(f"/api/v1/reputacao/{ip}")
    assert resp_a.status_code == 200
    assert resp_a.json()["classificacao"] == "ALTO RISCO"

    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})
    await logar(client, tenant_b["admin"]["email"], tenant_b["admin"]["senha"])

    # Se o cache de A vazasse para B, esta chamada devolveria "ALTO RISCO"
    # sem nunca tocar as funções mockadas abaixo (que devolvem "sem
    # risco") -- provando que B lê o cache (inexistente) da SUA empresa,
    # não o de A, e dispara uma consulta nova.
    with patch.object(core_reputacao, "consultar_abuseipdb", return_value={"score_abuso": 0}), \
         patch.object(core_reputacao, "consultar_virustotal", return_value={"maliciosos": 0}):
        resp_b = await client.get(f"/api/v1/reputacao/{ip}")
    assert resp_b.status_code == 200
    assert resp_b.json()["classificacao"] != "ALTO RISCO"


# ---------------------------------------------------------------------------
# Dashboard -- API JSON
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_dashboard_nao_conta_incidentes_de_outra_empresa(client, tenant_a, tenant_b, pool):
    for i in range(3):
        await _criar_incidente(pool, tenant_a["empresa_id"], f"203.0.113.22{i}")
    await logar(client, tenant_b["admin"]["email"], tenant_b["admin"]["senha"])

    resp = await client.get("/api/v1/dashboard")
    assert resp.status_code == 200
    corpo = resp.json()
    assert corpo["metricas"]["total"] == 0
    assert corpo["recentes"] == []
    assert corpo["top_ips"] == []


# ---------------------------------------------------------------------------
# Upload de log -- API JSON e web (o incidente criado é tenant-scoped)
# ---------------------------------------------------------------------------

_LOG_ALTO_RISCO = (
    "203.0.113.230 - - [01/Sep/2026:10:00:00] "
    "\"GET /vulneravel.php?id=1' UNION SELECT null,username,password FROM users HTTP/1.1\" 200 100\n"
    "203.0.113.230 - - [01/Sep/2026:10:00:01] \"GET /exec?cmd=;cat /etc/passwd HTTP/1.1\" 200 100\n"
)


@pytest.mark.asyncio
async def test_api_incidente_criado_via_upload_nao_e_visivel_para_outra_empresa(client, tenant_a, tenant_b):
    from unittest.mock import patch

    from sentinela.core import reputacao as core_reputacao

    await logar(client, tenant_a["admin"]["email"], tenant_a["admin"]["senha"])
    with patch.object(core_reputacao, "consultar_abuseipdb", return_value={"score_abuso": 90}), \
         patch.object(core_reputacao, "consultar_virustotal", return_value={"maliciosos": 8}):
        resp_upload = await client.post(
            "/api/v1/logs/analisar",
            files={"arquivo": ("servidor.log", io.BytesIO(_LOG_ALTO_RISCO.encode()), "text/plain")},
            data={"limite": "1"},
            headers={"X-Sentinela-CSRF": "1"},
        )
    assert resp_upload.status_code == 200
    incident_id = resp_upload.json()["respostas_incidentes"][0]["incident_id"]

    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})
    await logar(client, tenant_b["admin"]["email"], tenant_b["admin"]["senha"])

    resp = await client.get(f"/api/v1/incidentes/{incident_id}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_web_incidente_criado_via_upload_nao_e_visivel_para_outra_empresa(client, tenant_a, tenant_b):
    from unittest.mock import patch

    from sentinela.core import reputacao as core_reputacao

    await client.post("/login", data={"email": tenant_a["admin"]["email"], "senha": tenant_a["admin"]["senha"]})
    with patch.object(core_reputacao, "consultar_abuseipdb", return_value={"score_abuso": 90}), \
         patch.object(core_reputacao, "consultar_virustotal", return_value={"maliciosos": 8}):
        resp_upload = await client.post(
            "/logs/upload",
            files={"arquivo": ("servidor.log", io.BytesIO(_LOG_ALTO_RISCO.encode()), "text/plain")},
            data={"limite": "1"},
            headers={"X-Sentinela-CSRF": "1"},
        )
    assert resp_upload.status_code == 200
    assert "203.0.113.230" in resp_upload.text

    await client.post("/logout", headers={"X-Sentinela-CSRF": "1"})
    await client.post("/login", data={"email": tenant_b["admin"]["email"], "senha": tenant_b["admin"]["senha"]})

    resp = await client.get("/incidentes")
    assert "203.0.113.230" not in resp.text


# ---------------------------------------------------------------------------
# Adulteração de claims do JWT (empresa_id / papel / sub) -- ataque que não
# depende de IDOR nenhum: o token TEM assinatura válida, só as claims que
# mentem. Ver o comentário longo em auth/dependencies.py:conexao_tenant.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_empresa_id_adulterada_no_jwt_e_recusada(client, tenant_a, tenant_b):
    admin_b = tenant_b["admin"]
    token = _forjar_cookie_sessao({
        "sub": str(admin_b["id"]), "empresa_id": str(tenant_a["empresa_id"]),
        "papel": "admin", "email": admin_b["email"], "tv": 1,
    })
    client.cookies.set(NOME_COOKIE_SESSAO, token)

    resp = await client.get("/api/v1/incidentes")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_web_empresa_id_adulterada_no_jwt_e_recusada(client, tenant_a, tenant_b):
    admin_b = tenant_b["admin"]
    token = _forjar_cookie_sessao({
        "sub": str(admin_b["id"]), "empresa_id": str(tenant_a["empresa_id"]),
        "papel": "admin", "email": admin_b["email"], "tv": 1,
    })
    client.cookies.set(NOME_COOKIE_SESSAO, token)

    resp = await client.get("/incidentes")
    assert resp.status_code == 303
    assert "erro=sessao_invalida" in resp.headers["location"]


@pytest.mark.asyncio
async def test_api_papel_adulterado_no_jwt_e_recusado(client, tenant_a):
    analista = tenant_a["analista"]
    token = _forjar_cookie_sessao({
        "sub": str(analista["id"]), "empresa_id": str(tenant_a["empresa_id"]),
        "papel": "admin", "email": analista["email"], "tv": 1,
    })
    client.cookies.set(NOME_COOKIE_SESSAO, token)

    # /api/v1/usuarios é admin-only -- um analista com a claim "papel"
    # adulterada para "admin" não deveria conseguir passar nem por
    # `exigir_papel("admin")` nem pelo recheque em tempo real de
    # conexao_tenant (que compara contra o papel de VERDADE no banco).
    resp = await client.get("/api/v1/usuarios")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_api_sub_inexistente_no_jwt_e_recusado(client, tenant_a):
    token = _forjar_cookie_sessao({
        "sub": str(uuid.uuid4()), "empresa_id": str(tenant_a["empresa_id"]),
        "papel": "admin", "email": "fantasma@example.com", "tv": 1,
    })
    client.cookies.set(NOME_COOKIE_SESSAO, token)

    resp = await client.get("/api/v1/incidentes")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Fase C / C1 -- VIEWER é estritamente somente leitura. Ver auth/rbac.py e
# os retrofits em api/v1/incidentes.py, web/routes_incidentes.py,
# api/v1/logs.py, web/routes_logs.py.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_viewer_pode_listar_incidentes_mas_nao_pode_triar(client, tenant_a, pool):
    incident_id = await _criar_incidente(pool, tenant_a["empresa_id"], "203.0.113.240")
    await logar(client, tenant_a["viewer"]["email"], tenant_a["viewer"]["senha"])

    resp_leitura = await client.get("/api/v1/incidentes")
    assert resp_leitura.status_code == 200

    resp_escrita = await client.patch(
        f"/api/v1/incidentes/{incident_id}/status",
        json={"status": "RESOLVIDO"}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_escrita.status_code == 403


@pytest.mark.asyncio
async def test_viewer_nao_pode_fazer_upload_de_log(client, tenant_a):
    await logar(client, tenant_a["viewer"]["email"], tenant_a["viewer"]["senha"])
    resp = await client.post(
        "/api/v1/logs/analisar",
        files={"arquivo": ("servidor.log", io.BytesIO(b"linha de log qualquer\n"), "text/plain")},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_viewer_nao_pode_criar_usuario(client, tenant_a):
    await logar(client, tenant_a["viewer"]["email"], tenant_a["viewer"]["senha"])
    resp = await client.post(
        "/api/v1/usuarios",
        json={"email": f"novo-{uuid.uuid4()}@example.com", "papel": "analista", "senha": "senha-forte-123"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Fase C / C11 -- proteção contra escalação de privilégio: um usuário NUNCA
# pode alterar o PRÓPRIO papel para obter privilégios maiores, mesmo sendo
# admin da própria empresa.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_admin_nao_pode_alterar_o_proprio_papel(client, tenant_a, pool):
    admin = tenant_a["admin"]
    await logar(client, admin["email"], admin["senha"])

    resp = await client.patch(
        f"/api/v1/usuarios/{admin['id']}", json={"papel": "analista"}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 403
    estado = await _papel_e_ativo(pool, admin["id"])
    assert estado["papel"] == "admin"


@pytest.mark.asyncio
async def test_admin_pode_alterar_papel_de_outro_usuario_da_mesma_empresa(client, tenant_a):
    admin = tenant_a["admin"]
    analista = tenant_a["analista"]
    await logar(client, admin["email"], admin["senha"])

    resp = await client.patch(
        f"/api/v1/usuarios/{analista['id']}", json={"papel": "viewer"}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 200
    assert resp.json()["usuario"]["papel"] == "viewer"


# ---------------------------------------------------------------------------
# Fase C / C11 -- escalação entre papéis de TENANT: analista/viewer não
# conseguem agir como admin (criar/editar usuários), mesmo autenticados de
# verdade (não é um teste de JWT adulterado -- é RBAC comum).
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_analista_nao_pode_criar_usuario(client, tenant_a):
    """SECURITY_ANALYST não tem users.create -- ver ROLE_PERMISSIONS."""
    await logar(client, tenant_a["analista"]["email"], tenant_a["analista"]["senha"])
    resp = await client.post(
        "/api/v1/usuarios",
        json={"email": f"novo-{uuid.uuid4()}@example.com", "papel": "viewer", "senha": "senha-forte-123"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_analista_nao_pode_alterar_papel_de_outro_usuario(client, tenant_a):
    await logar(client, tenant_a["analista"]["email"], tenant_a["analista"]["senha"])
    resp = await client.patch(
        f"/api/v1/usuarios/{tenant_a['viewer']['id']}", json={"papel": "admin"}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Fase C / C11 -- escalação SaaS: COMPANY_ADMIN/SECURITY_ANALYST/VIEWER
# jamais alcançam rotas de superadmin só por terem um JWT com assinatura
# válida (sem `papel: "superadmin"`, `exigir_superadmin` já barra de cara --
# isso já era verdade antes da Fase C). O caso NOVO da Fase C é
# SAAS_ADMIN -> SAAS_OWNER: um superadmin comum não pode alcançar uma
# operação EXCLUSIVA de Owner nem adulterando a claim `papel_saas` sem
# reautenticar (o recheque em tempo real contra o banco -- ver
# conexao_superadmin -- pega isso).
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def saas_admin_de_teste(pool):
    from sentinela.auth.security import hash_senha

    email = f"saas-admin-{uuid.uuid4()}@example.com"
    senha = "senha-forte-123"
    superadmin_id = uuid.uuid4()
    async with superadmin_scoped_connection(pool) as conn:
        await conn.execute(
            "INSERT INTO superadmins (id, email, senha_hash, papel) VALUES ($1, $2, $3, 'saas_admin')",
            superadmin_id, email, hash_senha(senha),
        )
    yield {"id": superadmin_id, "email": email, "senha": senha}
    async with superadmin_scoped_connection(pool) as conn:
        await conn.execute("DELETE FROM auditoria WHERE ator_superadmin_id = $1", superadmin_id)
        await conn.execute("DELETE FROM superadmins WHERE id = $1", superadmin_id)


@pytest.mark.asyncio
async def test_saas_admin_nao_pode_revogar_licenca(client, saas_admin_de_teste, tenant_a, pool):
    """C4 -- revogar licença é EXCLUSIVO de SAAS_OWNER (ver auth/rbac.py:exigir_saas_owner)."""
    from sentinela.services import licenciamento as servico_licenciamento

    async with superadmin_scoped_connection(pool) as conn:
        plano_id = await conn.fetchval("SELECT id FROM planos LIMIT 1")
        licenca, _token = await servico_licenciamento.criar_licenca(conn, tenant_a["empresa_id"], str(plano_id))

    await logar(client, saas_admin_de_teste["email"], saas_admin_de_teste["senha"])
    resp = await client.post(
        f"/api/v1/admin/licencas/{licenca['id']}/revogar", headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_saas_admin_com_claim_papel_saas_adulterada_para_owner_e_recusado(client, saas_admin_de_teste, tenant_a, pool):
    """Ataque: um SaaS Admin forja/edita a claim `papel_saas` no próprio
    cookie (ex.: JWT_SECRET vazado) para "saas_owner". O recheque em tempo
    real em `conexao_superadmin` (que compara contra `superadmins.papel`
    de VERDADE no banco) tem que recusar -- mesmo padrão de proteção que já
    existia para `empresa_id`/`papel` adulterados."""
    from sentinela.services import licenciamento as servico_licenciamento

    async with superadmin_scoped_connection(pool) as conn:
        plano_id = await conn.fetchval("SELECT id FROM planos LIMIT 1")
        licenca, _token = await servico_licenciamento.criar_licenca(conn, tenant_a["empresa_id"], str(plano_id))

    token = _forjar_cookie_sessao({
        "sub": str(saas_admin_de_teste["id"]), "empresa_id": None, "papel": "superadmin",
        "email": saas_admin_de_teste["email"], "tv": 0, "papel_saas": "saas_owner",
    })
    client.cookies.set(NOME_COOKIE_SESSAO, token)

    resp = await client.post(
        f"/api/v1/admin/licencas/{licenca['id']}/revogar", headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 401  # sessão inválida -- conexao_superadmin recusa antes de chegar em exigir_saas_owner
