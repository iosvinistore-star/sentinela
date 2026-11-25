# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Fase C -- MFA/TOTP ponta a ponta, contra Postgres real: setup, confirmação,
o desafio de MFA no login, código errado, rate limiting, desativação,
recovery codes (uso único), reset administrativo e trilha de auditoria
(C6/C7/C8/C9/C10).
"""
import json

import pyotp
import pytest

from tests.api.conftest_api import logar
from tests.sql_cru import buscar, buscar_um, executar

pytestmark = pytest.mark.integration


async def _auditoria_da_empresa(db, empresa_id):
    """asyncpg devolve `jsonb` como string crua (nenhum codec jsonb é
    registrado no pool, ver db/pool.py) -- por isso `json.loads` aqui, ao
    contrário de `services/auditoria.py:_publico`, que expõe `detalhes` tal
    como veio (a API HTTP serializa de volta para JSON de qualquer jeito)."""
    async with db.superadmin_session() as conn:
        linhas = await buscar(conn, "SELECT acao, detalhes FROM auditoria WHERE empresa_id = $1 ORDER BY criado_em", empresa_id,
        )
    return [{"acao": linha["acao"], "detalhes": json.loads(linha["detalhes"]) if linha["detalhes"] else {}} for linha in linhas]


async def _habilitar_mfa(client, usuario) -> tuple[str, list[str]]:
    """Fluxo completo de setup -- devolve (segredo, recovery_codes) já com MFA ativo."""
    await logar(client, usuario["email"], usuario["senha"])
    resp_setup = await client.post("/api/v1/usuarios/me/mfa/setup", headers={"X-Sentinela-CSRF": "1"})
    assert resp_setup.status_code == 200
    segredo = resp_setup.json()["segredo"]

    codigo = pyotp.TOTP(segredo).now()
    resp_confirmar = await client.post(
        "/api/v1/usuarios/me/mfa/confirmar", json={"codigo": codigo}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_confirmar.status_code == 200
    recovery_codes = resp_confirmar.json()["recovery_codes"]
    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})
    return segredo, recovery_codes


# ---------------------------------------------------------------------------
# Setup e confirmação (C6).
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_setup_gera_uri_de_provisionamento_mas_nao_ativa_mfa_ainda(client, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    resp = await client.post("/api/v1/usuarios/me/mfa/setup", headers={"X-Sentinela-CSRF": "1"})
    assert resp.status_code == 200
    assert "provisioning_uri" in resp.json()
    assert "segredo" in resp.json()

    status = await client.get("/api/v1/usuarios/me/mfa/status")
    assert status.json()["mfa_habilitado"] is False


@pytest.mark.asyncio
async def test_confirmar_com_codigo_correto_ativa_mfa_e_devolve_recovery_codes(client, usuario_de_teste, db):
    segredo, recovery_codes = await _habilitar_mfa(client, usuario_de_teste)
    assert len(recovery_codes) == 10

    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    # Login sem MFA ativado deveria ter setado cookie direto -- mas agora
    # que está ativo, `logar()` (que só manda email/senha) deve devolver o
    # desafio de MFA em vez de autenticar de uma vez.
    resp = await client.post("/api/v1/auth/login", json={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})
    assert resp.json()["mfa_necessario"] is True

    eventos = await _auditoria_da_empresa(db, usuario_de_teste["empresa_id"])
    assert "MFA_ENABLED" in {e["acao"] for e in eventos}


@pytest.mark.asyncio
async def test_confirmar_com_codigo_errado_nao_ativa_mfa(client, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    await client.post("/api/v1/usuarios/me/mfa/setup", headers={"X-Sentinela-CSRF": "1"})

    resp = await client.post(
        "/api/v1/usuarios/me/mfa/confirmar", json={"codigo": "000000"}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 401
    status = await client.get("/api/v1/usuarios/me/mfa/status")
    assert status.json()["mfa_habilitado"] is False


@pytest.mark.asyncio
async def test_confirmar_sem_setup_pendente_e_400(client, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    resp = await client.post(
        "/api/v1/usuarios/me/mfa/confirmar", json={"codigo": "123456"}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Desafio de MFA no login (C6).
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_login_com_mfa_habilitado_exige_segundo_passo(client, usuario_de_teste):
    segredo, _ = await _habilitar_mfa(client, usuario_de_teste)

    resp_login = await client.post("/api/v1/auth/login", json={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})
    assert resp_login.status_code == 200
    assert resp_login.json()["mfa_necessario"] is True
    pre_auth_token = resp_login.json()["pre_auth_token"]
    assert "sentinela_session" not in client.cookies

    codigo = pyotp.TOTP(segredo).now()
    resp_verify = await client.post("/api/v1/auth/mfa/verificar", json={"pre_auth_token": pre_auth_token, "codigo": codigo})
    assert resp_verify.status_code == 200
    assert "sentinela_session" in client.cookies


@pytest.mark.asyncio
async def test_login_mfa_verificar_com_codigo_errado_e_401_e_nao_autentica(client, usuario_de_teste):
    await _habilitar_mfa(client, usuario_de_teste)
    resp_login = await client.post("/api/v1/auth/login", json={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})
    pre_auth_token = resp_login.json()["pre_auth_token"]

    resp_verify = await client.post("/api/v1/auth/mfa/verificar", json={"pre_auth_token": pre_auth_token, "codigo": "000000"})
    assert resp_verify.status_code == 401
    assert "sentinela_session" not in client.cookies


@pytest.mark.asyncio
async def test_pre_auth_token_nao_pode_ser_usado_como_cookie_de_sessao(client, usuario_de_teste):
    """Ver auth/dependencies.py:usuario_atual -- um token com a claim
    "purpose" nunca deve autenticar nenhuma rota, mesmo carregando
    sub/papel/empresa_id/tv válidos."""
    await _habilitar_mfa(client, usuario_de_teste)
    resp_login = await client.post("/api/v1/auth/login", json={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})
    pre_auth_token = resp_login.json()["pre_auth_token"]

    client.cookies.set("sentinela_session", pre_auth_token)
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_mfa_verificar_rate_limitado_por_usuario(client, usuario_de_teste):
    await _habilitar_mfa(client, usuario_de_teste)
    resp_login = await client.post("/api/v1/auth/login", json={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})
    pre_auth_token = resp_login.json()["pre_auth_token"]

    ultima = None
    for _ in range(6):
        ultima = await client.post("/api/v1/auth/mfa/verificar", json={"pre_auth_token": pre_auth_token, "codigo": "000000"})
    assert ultima.status_code == 429


@pytest.mark.asyncio
async def test_recovery_code_autentica_login_e_e_de_uso_unico(client, usuario_de_teste, db):
    segredo, recovery_codes = await _habilitar_mfa(client, usuario_de_teste)
    codigo_recovery = recovery_codes[0]

    resp_login = await client.post("/api/v1/auth/login", json={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})
    pre_auth_token = resp_login.json()["pre_auth_token"]
    resp_verify = await client.post(
        "/api/v1/auth/mfa/verificar", json={"pre_auth_token": pre_auth_token, "recovery_code": codigo_recovery},
    )
    assert resp_verify.status_code == 200
    eventos = await _auditoria_da_empresa(db, usuario_de_teste["empresa_id"])
    assert "RECOVERY_CODE_USED" in {e["acao"] for e in eventos}

    # Reusar o MESMO recovery code numa segunda tentativa de login -- recusado.
    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})
    resp_login_2 = await client.post("/api/v1/auth/login", json={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})
    pre_auth_token_2 = resp_login_2.json()["pre_auth_token"]
    resp_verify_2 = await client.post(
        "/api/v1/auth/mfa/verificar", json={"pre_auth_token": pre_auth_token_2, "recovery_code": codigo_recovery},
    )
    assert resp_verify_2.status_code == 401


@pytest.mark.asyncio
async def test_recovery_code_invalido_e_recusado(client, usuario_de_teste):
    await _habilitar_mfa(client, usuario_de_teste)
    resp_login = await client.post("/api/v1/auth/login", json={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})
    pre_auth_token = resp_login.json()["pre_auth_token"]
    resp_verify = await client.post(
        "/api/v1/auth/mfa/verificar", json={"pre_auth_token": pre_auth_token, "recovery_code": "ZZZZ-ZZZZ-ZZZZ"},
    )
    assert resp_verify.status_code == 401


# ---------------------------------------------------------------------------
# Desativação self-service (C6) e regeneração de recovery codes (C7).
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_desativar_mfa_exige_codigo_valido(client, usuario_de_teste, db):
    segredo, _ = await _habilitar_mfa(client, usuario_de_teste)
    resp_login = await client.post("/api/v1/auth/login", json={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})
    pre_auth_token = resp_login.json()["pre_auth_token"]
    codigo = pyotp.TOTP(segredo).now()
    await client.post("/api/v1/auth/mfa/verificar", json={"pre_auth_token": pre_auth_token, "codigo": codigo})

    # Código já usado no login -- gera um novo, dentro da mesma janela de 30s
    # (poderia colidir por acaso; se colidir, o teste ainda passa pois o
    # código seria idêntico e igualmente válido).
    codigo_novo = pyotp.TOTP(segredo).now()
    resp_desativar = await client.post(
        "/api/v1/usuarios/me/mfa/desativar", json={"codigo": codigo_novo}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_desativar.status_code == 200

    status = await client.get("/api/v1/usuarios/me/mfa/status")
    assert status.json()["mfa_habilitado"] is False
    eventos = await _auditoria_da_empresa(db, usuario_de_teste["empresa_id"])
    assert "MFA_DISABLED" in {e["acao"] for e in eventos}


@pytest.mark.asyncio
async def test_desativar_mfa_sem_codigo_valido_e_recusado(client, usuario_de_teste):
    segredo, _ = await _habilitar_mfa(client, usuario_de_teste)
    resp_login = await client.post("/api/v1/auth/login", json={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})
    pre_auth_token = resp_login.json()["pre_auth_token"]
    codigo = pyotp.TOTP(segredo).now()
    await client.post("/api/v1/auth/mfa/verificar", json={"pre_auth_token": pre_auth_token, "codigo": codigo})

    resp_desativar = await client.post(
        "/api/v1/usuarios/me/mfa/desativar", json={"codigo": "000000"}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_desativar.status_code == 401
    status = await client.get("/api/v1/usuarios/me/mfa/status")
    assert status.json()["mfa_habilitado"] is True


@pytest.mark.asyncio
async def test_regenerar_recovery_codes_invalida_os_antigos(client, usuario_de_teste, db):
    segredo, recovery_codes_antigos = await _habilitar_mfa(client, usuario_de_teste)
    resp_login = await client.post("/api/v1/auth/login", json={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})
    pre_auth_token = resp_login.json()["pre_auth_token"]
    codigo = pyotp.TOTP(segredo).now()
    await client.post("/api/v1/auth/mfa/verificar", json={"pre_auth_token": pre_auth_token, "codigo": codigo})

    codigo_novo = pyotp.TOTP(segredo).now()
    resp_regen = await client.post(
        "/api/v1/usuarios/me/mfa/recovery-codes/regenerar", json={"codigo": codigo_novo}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_regen.status_code == 200
    novos = resp_regen.json()["recovery_codes"]
    assert set(novos) != set(recovery_codes_antigos)

    eventos = await _auditoria_da_empresa(db, usuario_de_teste["empresa_id"])
    assert "RECOVERY_CODES_REGENERATED" in {e["acao"] for e in eventos}

    # Um recovery code ANTIGO não deve mais funcionar num login.
    await client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})
    resp_login_2 = await client.post("/api/v1/auth/login", json={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})
    pre_auth_token_2 = resp_login_2.json()["pre_auth_token"]
    resp_verify = await client.post(
        "/api/v1/auth/mfa/verificar",
        json={"pre_auth_token": pre_auth_token_2, "recovery_code": recovery_codes_antigos[0]},
    )
    assert resp_verify.status_code == 401


# ---------------------------------------------------------------------------
# Reset administrativo de MFA (C8).
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_admin_pode_resetar_mfa_de_usuario_da_propria_empresa(client, db, empresa_factory):
    from sentinela.auth.security import hash_senha
    import uuid

    empresa_id = await empresa_factory("Empresa MFA Reset")
    async with db.superadmin_session() as conn:
        admin_id = uuid.uuid4()
        analista_id = uuid.uuid4()
        await executar(conn, "INSERT INTO usuarios (id, empresa_id, email, papel, senha_hash) VALUES ($1, $2, $3, 'admin', $4)",
            admin_id, empresa_id, f"admin-{uuid.uuid4()}@example.com", hash_senha("senha-forte-123"),
        )
        await executar(conn, "INSERT INTO usuarios (id, empresa_id, email, papel, senha_hash) VALUES ($1, $2, $3, 'analista', $4)",
            analista_id, empresa_id, f"analista-{uuid.uuid4()}@example.com", hash_senha("senha-forte-123"),
        )
        admin = dict(await buscar_um(conn, "SELECT id, email FROM usuarios WHERE id = $1", admin_id))
        analista = dict(await buscar_um(conn, "SELECT id, email FROM usuarios WHERE id = $1", analista_id))

    await _habilitar_mfa(client, {"email": analista["email"], "senha": "senha-forte-123"})
    await logar(client, admin["email"], "senha-forte-123")

    resp_reset = await client.post(f"/api/v1/usuarios/{analista_id}/mfa/reset", headers={"X-Sentinela-CSRF": "1"})
    assert resp_reset.status_code == 200

    eventos = await _auditoria_da_empresa(db, empresa_id)
    evento_reset = next(e for e in eventos if e["acao"] == "MFA_RESET")
    assert evento_reset["detalhes"]["usuario_alvo_id"] == str(analista_id)
    assert evento_reset["detalhes"]["ator_usuario_id"] == str(admin_id)


@pytest.mark.asyncio
async def test_analista_nao_pode_resetar_mfa_de_outro_usuario(client, db, empresa_factory):
    """C1/C2 -- 'mfa.reset_others' não está na matriz de SECURITY_ANALYST."""
    import uuid

    from sentinela.auth.security import hash_senha

    empresa_id = await empresa_factory("Empresa MFA Reset Negado")
    async with db.superadmin_session() as conn:
        analista_ator_id = uuid.uuid4()
        alvo_id = uuid.uuid4()
        await executar(conn, "INSERT INTO usuarios (id, empresa_id, email, papel, senha_hash) VALUES ($1, $2, $3, 'analista', $4)",
            analista_ator_id, empresa_id, f"analista-ator-{uuid.uuid4()}@example.com", hash_senha("senha-forte-123"),
        )
        await executar(conn, "INSERT INTO usuarios (id, empresa_id, email, papel, senha_hash) VALUES ($1, $2, $3, 'viewer', $4)",
            alvo_id, empresa_id, f"viewer-alvo-{uuid.uuid4()}@example.com", hash_senha("senha-forte-123"),
        )
        analista_ator = dict(await buscar_um(conn, "SELECT email FROM usuarios WHERE id = $1", analista_ator_id))

    await logar(client, analista_ator["email"], "senha-forte-123")
    resp = await client.post(f"/api/v1/usuarios/{alvo_id}/mfa/reset", headers={"X-Sentinela-CSRF": "1"})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_admin_nao_pode_resetar_o_proprio_mfa_via_rota_administrativa(client, usuario_de_teste):
    """Ver api/v1/usuarios.py:resetar_mfa -- evita que uma sessão comprometida
    se auto-conceda a remoção do segundo fator só por também ter a permissão administrativa."""
    segredo, _ = await _habilitar_mfa(client, usuario_de_teste)
    resp_login = await client.post(
        "/api/v1/auth/login", json={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]},
    )
    pre_auth_token = resp_login.json()["pre_auth_token"]
    codigo = pyotp.TOTP(segredo).now()
    resp_verify = await client.post("/api/v1/auth/mfa/verificar", json={"pre_auth_token": pre_auth_token, "codigo": codigo})
    assert resp_verify.status_code == 200

    resp_reset = await client.post(
        f"/api/v1/usuarios/{usuario_de_teste['id']}/mfa/reset", headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_reset.status_code == 403
