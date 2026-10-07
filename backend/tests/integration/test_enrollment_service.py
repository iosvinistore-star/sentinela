# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
services.enrollment: geração/revogação de tokens de enrollment e a troca
desse token pela identidade permanente de um agente (Fase D / D3) -- ver
ARQUITETURA_LICENCIAMENTO.md §12 e migrations/0022_agentes_enrollment.sql.

Segue a mesma convenção de tests/integration/test_licenciamento_service.py:
conexão tenant-scoped de verdade (RLS real), sem mockar nada do Postgres.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from sentinela.auth.enrollment import autenticar_enrollment
from sentinela.db.pool import superadmin_scoped_connection, tenant_scoped_connection
from sentinela.services import agentes as servico_agentes
from sentinela.services import enrollment as servico
from sentinela.services import licenciamento as servico_licenciamento

pytestmark = pytest.mark.integration


def _expira_em(minutos=30):
    return datetime.now(timezone.utc) + timedelta(minutes=minutos)


# ---------------------------------------------------------------------------
# criar_token_enrollment / listar_tokens_enrollment / revogar_token_enrollment
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_criar_token_enrollment_devolve_token_em_claro_uma_unica_vez(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Enrollment Criar")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        enrollment, token = await servico.criar_token_enrollment(conn, empresa_id, _expira_em())

    assert enrollment["empresa_id"] == str(empresa_id)
    assert enrollment["status"] == "ativo"
    assert enrollment["usos"] == 0
    assert enrollment["max_usos"] is None
    assert "token_hash" not in enrollment
    assert token.startswith("enr_")


@pytest.mark.asyncio
async def test_criar_token_enrollment_com_max_usos(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Enrollment Max Usos")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        enrollment, _ = await servico.criar_token_enrollment(conn, empresa_id, _expira_em(), max_usos=3)
    assert enrollment["max_usos"] == 3


@pytest.mark.asyncio
async def test_criar_token_enrollment_grava_auditoria(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Enrollment Auditoria")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        enrollment, _ = await servico.criar_token_enrollment(conn, empresa_id, _expira_em())
        auditoria = await conn.fetchrow(
            "SELECT acao FROM auditoria WHERE empresa_id = $1 AND acao = 'agente.enrollment_criado'", empresa_id,
        )
    assert auditoria is not None


@pytest.mark.asyncio
async def test_listar_tokens_enrollment_de_uma_empresa_nao_mostra_de_outra(pool, empresa_factory):
    empresa_a = await empresa_factory("Empresa Enrollment Listar A")
    empresa_b = await empresa_factory("Empresa Enrollment Listar B")

    async with tenant_scoped_connection(pool, empresa_a) as conn_a:
        await servico.criar_token_enrollment(conn_a, empresa_a, _expira_em())

    async with tenant_scoped_connection(pool, empresa_b) as conn_b:
        await servico.criar_token_enrollment(conn_b, empresa_b, _expira_em())
        listados_b = await servico.listar_tokens_enrollment(conn_b)

    assert len(listados_b) == 1
    assert listados_b[0]["empresa_id"] == str(empresa_b)


@pytest.mark.asyncio
async def test_revogar_token_enrollment_e_idempotente_e_preserva_a_linha(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Enrollment Revogar")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        enrollment, _ = await servico.criar_token_enrollment(conn, empresa_id, _expira_em())

        revogado_1 = await servico.revogar_token_enrollment(conn, empresa_id, enrollment["id"])
        assert revogado_1["status"] == "revogado"

        revogado_2 = await servico.revogar_token_enrollment(conn, empresa_id, enrollment["id"])
        assert revogado_2["status"] == "revogado"


@pytest.mark.asyncio
async def test_revogar_token_enrollment_inexistente_retorna_none(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Enrollment Revogar Inexistente")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        assert await servico.revogar_token_enrollment(conn, empresa_id, str(uuid.uuid4())) is None


@pytest.mark.asyncio
async def test_revogar_token_enrollment_de_outra_empresa_nao_afeta_nada(pool, empresa_factory):
    empresa_a = await empresa_factory("Empresa Enrollment Revogar Cross A")
    empresa_b = await empresa_factory("Empresa Enrollment Revogar Cross B")

    async with tenant_scoped_connection(pool, empresa_a) as conn_a:
        enrollment_a, _ = await servico.criar_token_enrollment(conn_a, empresa_a, _expira_em())

    async with tenant_scoped_connection(pool, empresa_b) as conn_b:
        resultado = await servico.revogar_token_enrollment(conn_b, empresa_b, enrollment_a["id"])
    assert resultado is None

    async with tenant_scoped_connection(pool, empresa_a) as conn_a:
        linha = await conn_a.fetchrow("SELECT status FROM agentes_enrollment_tokens WHERE id = $1", enrollment_a["id"])
    assert linha["status"] == "ativo"


# ---------------------------------------------------------------------------
# trocar_por_agente
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_trocar_por_agente_cria_o_agente_e_incrementa_usos(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Enrollment Trocar")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        _, token = await servico.criar_token_enrollment(conn, empresa_id, _expira_em())
    resolvido = await autenticar_enrollment(pool, token)

    async with tenant_scoped_connection(pool, empresa_id) as conn:
        agente, token_agente = await servico.trocar_por_agente(conn, resolvido, "host-enrollment-1")
        linha = await conn.fetchrow(
            "SELECT usos FROM agentes_enrollment_tokens WHERE id = $1", resolvido["enrollment_id"],
        )

    assert agente["hostname"] == "host-enrollment-1"
    assert agente["status"] == "ativo"
    assert token_agente.startswith("agt_")
    assert linha["usos"] == 1


@pytest.mark.asyncio
async def test_trocar_por_agente_grava_evento_de_auditoria_ligando_agente_ao_enrollment(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Enrollment Auditoria Troca")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        enrollment, token = await servico.criar_token_enrollment(conn, empresa_id, _expira_em())
    resolvido = await autenticar_enrollment(pool, token)

    async with tenant_scoped_connection(pool, empresa_id) as conn:
        agente, _ = await servico.trocar_por_agente(conn, resolvido, "host-enrollment-auditoria")
        auditoria = await conn.fetchrow(
            "SELECT detalhes FROM auditoria WHERE empresa_id = $1 AND acao = 'agente.criado_via_enrollment'", empresa_id,
        )
    assert auditoria is not None


@pytest.mark.asyncio
async def test_trocar_por_agente_e_multi_uso_para_maquinas_diferentes(pool, empresa_factory):
    """O mesmo token de enrollment aceita várias trocas (uma por máquina) --
    é o caso de uso central do D3 (um script de instalação, uma frota
    inteira)."""
    empresa_id = await empresa_factory("Empresa Enrollment Multi Uso")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        _, token = await servico.criar_token_enrollment(conn, empresa_id, _expira_em())
    resolvido = await autenticar_enrollment(pool, token)

    async with tenant_scoped_connection(pool, empresa_id) as conn:
        agente_1, _ = await servico.trocar_por_agente(conn, resolvido, "host-multi-1")
        agente_2, _ = await servico.trocar_por_agente(conn, resolvido, "host-multi-2")
        linha = await conn.fetchrow(
            "SELECT usos FROM agentes_enrollment_tokens WHERE id = $1", resolvido["enrollment_id"],
        )

    assert agente_1["id"] != agente_2["id"]
    assert linha["usos"] == 2


@pytest.mark.asyncio
async def test_trocar_por_agente_com_hostname_duplicado_retorna_none_mas_consome_um_uso(pool, empresa_factory):
    """Trade-off consciente documentado em ARQUITETURA_LICENCIAMENTO.md §12:
    a reserva de uso é atômica e acontece ANTES de tentar criar o agente --
    uma falha de criação (hostname já em uso) não devolve o uso reservado."""
    empresa_id = await empresa_factory("Empresa Enrollment Hostname Duplicado")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        await servico_agentes.criar_agente(conn, empresa_id, "host-ja-existe")
        _, token = await servico.criar_token_enrollment(conn, empresa_id, _expira_em())
    resolvido = await autenticar_enrollment(pool, token)

    async with tenant_scoped_connection(pool, empresa_id) as conn:
        agente, token_agente = await servico.trocar_por_agente(conn, resolvido, "host-ja-existe")
        linha = await conn.fetchrow(
            "SELECT usos FROM agentes_enrollment_tokens WHERE id = $1", resolvido["enrollment_id"],
        )

    assert agente is None
    assert token_agente is None
    assert linha["usos"] == 1


@pytest.mark.asyncio
async def test_trocar_por_agente_com_token_revogado_falha(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Enrollment Revogado Trocar")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        enrollment, token = await servico.criar_token_enrollment(conn, empresa_id, _expira_em())
        await servico.revogar_token_enrollment(conn, empresa_id, enrollment["id"])
    resolvido = await autenticar_enrollment(pool, token)

    async with tenant_scoped_connection(pool, empresa_id) as conn:
        with pytest.raises(servico.TokenEnrollmentInvalidoError, match="revogado"):
            await servico.trocar_por_agente(conn, resolvido, "host-nunca-criado")


@pytest.mark.asyncio
async def test_trocar_por_agente_com_token_expirado_falha(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Enrollment Expirado Trocar")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        _, token = await servico.criar_token_enrollment(conn, empresa_id, _expira_em(minutos=-5))
    resolvido = await autenticar_enrollment(pool, token)

    async with tenant_scoped_connection(pool, empresa_id) as conn:
        with pytest.raises(servico.TokenEnrollmentInvalidoError, match="expirado"):
            await servico.trocar_por_agente(conn, resolvido, "host-nunca-criado")


@pytest.mark.asyncio
async def test_trocar_por_agente_apos_esgotar_max_usos_falha(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Enrollment Esgotado Trocar")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        _, token = await servico.criar_token_enrollment(conn, empresa_id, _expira_em(), max_usos=1)
    resolvido = await autenticar_enrollment(pool, token)

    async with tenant_scoped_connection(pool, empresa_id) as conn:
        agente_1, _ = await servico.trocar_por_agente(conn, resolvido, "host-esgota-1")
        assert agente_1 is not None

        with pytest.raises(servico.TokenEnrollmentInvalidoError, match="esgotou"):
            await servico.trocar_por_agente(conn, resolvido, "host-esgota-2")


@pytest.mark.asyncio
async def test_trocar_por_agente_inexistente_falha(pool, empresa_factory):
    """Um `enrollment_id` que nunca existiu (não um caso realista via API --
    a dependência já teria devolvido 401 antes -- mas cobre a função de
    serviço isoladamente)."""
    empresa_id = await empresa_factory("Empresa Enrollment Inexistente Trocar")
    fake = {"enrollment_id": uuid.uuid4(), "empresa_id": empresa_id}
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        with pytest.raises(servico.TokenEnrollmentInvalidoError, match="não encontrado"):
            await servico.trocar_por_agente(conn, fake, "host-nunca-criado")


@pytest.mark.asyncio
async def test_trocar_por_agente_vincula_automaticamente_a_licenca_ativa_da_empresa(pool, empresa_factory):
    """D3 reaproveita o mesmo caminho de criar_agente -- o auto-bind à
    licença ativa (D1, ver ARQUITETURA_LICENCIAMENTO.md §10) também
    acontece para um agente provisionado via enrollment."""
    empresa_id = await empresa_factory("Empresa Enrollment Autobind Licenca")
    async with superadmin_scoped_connection(pool) as conn_admin:
        plano_id = await conn_admin.fetchval("SELECT id FROM planos WHERE codigo = 'starter'")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        await servico_licenciamento.criar_licenca(conn, empresa_id, plano_id)
        _, token = await servico.criar_token_enrollment(conn, empresa_id, _expira_em())
    resolvido = await autenticar_enrollment(pool, token)

    async with tenant_scoped_connection(pool, empresa_id) as conn:
        agente, _ = await servico.trocar_por_agente(conn, resolvido, "host-enrollment-licenca")
        vaga = await conn.fetchrow("SELECT id FROM licencas_endpoints WHERE agente_id = $1", agente["id"])
    assert vaga is not None


@pytest.mark.asyncio
async def test_trocar_por_agente_alem_do_limite_da_licenca_propaga_erro(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Enrollment Limite Licenca")
    async with superadmin_scoped_connection(pool) as conn_admin:
        plano_id = await conn_admin.fetchval(
            "INSERT INTO planos (codigo, nome_exibicao, max_endpoints) VALUES ($1, $2, 1) RETURNING id",
            f"teste-enrollment-limite-{uuid.uuid4().hex[:8]}", "Plano De Teste Enrollment Limite",
        )
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        await servico_licenciamento.criar_licenca(conn, empresa_id, plano_id)
        await servico_agentes.criar_agente(conn, empresa_id, "host-ocupa-a-vaga-unica")  # auto-bind (D1) ocupa a vaga
        _, token = await servico.criar_token_enrollment(conn, empresa_id, _expira_em())
    resolvido = await autenticar_enrollment(pool, token)

    async with tenant_scoped_connection(pool, empresa_id) as conn:
        with pytest.raises(servico_licenciamento.LimiteEndpointsExcedidoError):
            await servico.trocar_por_agente(conn, resolvido, "host-enrollment-sem-vaga")
