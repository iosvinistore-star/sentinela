# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
services.licenciamento: ciclo de vida de licenças (criação, ativação,
validação, suspensão/revogação/renovação) e ocupação de vagas de endpoint
contra o limite do plano -- ver migrations/0019_licenciamento.sql e
ARQUITETURA_LICENCIAMENTO.md.

Segue a mesma convenção de tests/integration/test_agentes_service.py:
conexão tenant-scoped de verdade (RLS real), sem mockar nada do Postgres.
"""
import uuid

import pytest

from sentinela.auth.licencas import autenticar_licenca
from sentinela.db.pool import superadmin_scoped_connection, tenant_scoped_connection
from sentinela.services import agentes as servico_agentes
from sentinela.services import licenciamento as servico

pytestmark = pytest.mark.integration


async def _plano_id(pool, codigo="starter"):
    async with superadmin_scoped_connection(pool) as conn:
        return await conn.fetchval("SELECT id FROM planos WHERE codigo = $1", codigo)


# ---------------------------------------------------------------------------
# criar_licenca / listar_licencas
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_criar_licenca_devolve_token_em_claro_uma_unica_vez(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Licenca Criar")
    plano_id = await _plano_id(pool, "starter")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        licenca, token = await servico.criar_licenca(conn, empresa_id, plano_id)

    assert licenca["status"] == "ativa"
    assert licenca["empresa_id"] == str(empresa_id)
    assert licenca["plano_id"] == str(plano_id)
    assert "token_hash" not in licenca
    assert token.startswith("lic_")


@pytest.mark.asyncio
async def test_criar_licenca_com_plano_inexistente_falha(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Licenca Plano Inexistente")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        with pytest.raises(servico.PlanoInvalidoError):
            await servico.criar_licenca(conn, empresa_id, uuid.uuid4())


@pytest.mark.asyncio
async def test_criar_licenca_grava_auditoria_e_evento_proprio(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Licenca Auditoria")
    plano_id = await _plano_id(pool, "starter")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        licenca, _ = await servico.criar_licenca(conn, empresa_id, plano_id)

        auditoria = await conn.fetchrow(
            "SELECT acao FROM auditoria WHERE empresa_id = $1 AND acao = 'licenca.criada'", empresa_id,
        )
        evento = await conn.fetchrow(
            "SELECT tipo FROM licencas_eventos WHERE licenca_id = $1 AND tipo = 'licenca.criada'", licenca["id"],
        )
    assert auditoria is not None
    assert evento is not None


@pytest.mark.asyncio
async def test_listar_licencas_de_uma_empresa_nao_mostra_licenca_de_outra(pool, empresa_factory):
    empresa_a = await empresa_factory("Empresa Licenca Listar A")
    empresa_b = await empresa_factory("Empresa Licenca Listar B")
    plano_id = await _plano_id(pool, "starter")

    async with tenant_scoped_connection(pool, empresa_a) as conn_a:
        await servico.criar_licenca(conn_a, empresa_a, plano_id)

    async with tenant_scoped_connection(pool, empresa_b) as conn_b:
        await servico.criar_licenca(conn_b, empresa_b, plano_id)
        listadas_b = await servico.listar_licencas(conn_b)

    assert len(listadas_b) == 1
    assert listadas_b[0]["empresa_id"] == str(empresa_b)


# ---------------------------------------------------------------------------
# autenticar_licenca (auth/licencas.py) contra dados reais
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_autenticar_licenca_com_token_valido(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Licenca Autenticar")
    plano_id = await _plano_id(pool, "starter")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        licenca, token = await servico.criar_licenca(conn, empresa_id, plano_id)

    resultado = await autenticar_licenca(pool, token)
    assert resultado["licenca_id"] == uuid.UUID(licenca["id"])
    assert resultado["empresa_id"] == empresa_id
    assert resultado["status"] == "ativa"


@pytest.mark.asyncio
async def test_autenticar_licenca_com_token_errado_falha(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Licenca Autenticar Errado")
    plano_id = await _plano_id(pool, "starter")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        await servico.criar_licenca(conn, empresa_id, plano_id)

    assert await autenticar_licenca(pool, "lic_000000000000_token-forjado-qualquer") is None
    assert await autenticar_licenca(pool, "token-sem-formato-nenhum") is None


@pytest.mark.asyncio
async def test_autenticar_licenca_resolve_mesmo_quando_status_nao_e_ativa(pool, empresa_factory):
    """Ao contrário de autenticar_agente (que já filtra status='ativo' na
    query), autenticar_licenca resolve o token independentemente do status
    -- é a ROTA que decide o HTTPException, não o lookup (ver docstring de
    auth/licencas.py:autenticar_licenca)."""
    empresa_id = await empresa_factory("Empresa Licenca Autenticar Suspensa")
    plano_id = await _plano_id(pool, "starter")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        licenca, token = await servico.criar_licenca(conn, empresa_id, plano_id)
        await servico.suspender_licenca(conn, empresa_id, licenca["id"])

    resultado = await autenticar_licenca(pool, token)
    assert resultado is not None
    assert resultado["status"] == "suspensa"


# ---------------------------------------------------------------------------
# ativar_licenca / validar_licenca / obter_status_licenca / desativar_licenca
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ativar_licenca_preenche_ativada_em_uma_unica_vez(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Licenca Ativar")
    plano_id = await _plano_id(pool, "starter")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        licenca, token = await servico.criar_licenca(conn, empresa_id, plano_id)
        assert licenca["ativada_em"] is None
    # autenticar_licenca abre sua PRÓPRIA conexão (superadmin_scoped_connection,
    # ver auth/licencas.py) -- precisa rodar DEPOIS que a transação de
    # criação acima já commitou (fim do `async with`), senão o SELECT dela
    # roda numa transação diferente que ainda não enxerga a linha recém-
    # inserida (isolamento read-committed padrão do Postgres).
    resultado = await autenticar_licenca(pool, token)

    async with tenant_scoped_connection(pool, empresa_id) as conn:
        ativada_1 = await servico.ativar_licenca(conn, resultado)
        assert ativada_1["ativada_em"] is not None

        primeira_data = ativada_1["ativada_em"]
        # ativar de novo (idempotente) não deveria sobrescrever ativada_em
        ativada_2 = await servico.ativar_licenca(conn, resultado)
        assert ativada_2["ativada_em"] == primeira_data


@pytest.mark.asyncio
async def test_validar_licenca_atualiza_ultima_validacao_e_devolve_plano(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Licenca Validar")
    plano_id = await _plano_id(pool, "professional")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        licenca, token = await servico.criar_licenca(conn, empresa_id, plano_id)
    resultado = await autenticar_licenca(pool, token)

    async with tenant_scoped_connection(pool, empresa_id) as conn:
        validada = await servico.validar_licenca(conn, resultado)
        assert validada["status"] == "ativa"
        assert validada["plano"]["codigo"] == "professional"
        assert validada["plano"]["recursos"]["grace_period_dias"] == 3

        linha = await conn.fetchrow("SELECT ultima_validacao_em FROM licencas WHERE id = $1", licenca["id"])
    assert linha["ultima_validacao_em"] is not None


@pytest.mark.asyncio
async def test_validar_licenca_suspensa_nao_levanta_excecao_devolve_status(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Licenca Validar Suspensa")
    plano_id = await _plano_id(pool, "starter")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        licenca, token = await servico.criar_licenca(conn, empresa_id, plano_id)
        await servico.suspender_licenca(conn, empresa_id, licenca["id"])
    resultado = await autenticar_licenca(pool, token)

    async with tenant_scoped_connection(pool, empresa_id) as conn:
        validada = await servico.validar_licenca(conn, resultado)
    assert validada["status"] == "suspensa"


@pytest.mark.asyncio
async def test_obter_status_licenca_nao_atualiza_ultima_validacao(pool, empresa_factory):
    """status é leitura pontual sem side-effect -- diferente de validate."""
    empresa_id = await empresa_factory("Empresa Licenca Status Sem Side Effect")
    plano_id = await _plano_id(pool, "starter")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        licenca, token = await servico.criar_licenca(conn, empresa_id, plano_id)
    resultado = await autenticar_licenca(pool, token)

    async with tenant_scoped_connection(pool, empresa_id) as conn:
        await servico.obter_status_licenca(conn, resultado)
        linha = await conn.fetchrow("SELECT ultima_validacao_em FROM licencas WHERE id = $1", licenca["id"])
    assert linha["ultima_validacao_em"] is None


@pytest.mark.asyncio
async def test_desativar_licenca_registra_evento_mas_nao_muda_status(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Licenca Desativar")
    plano_id = await _plano_id(pool, "starter")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        licenca, token = await servico.criar_licenca(conn, empresa_id, plano_id)
    resultado = await autenticar_licenca(pool, token)

    async with tenant_scoped_connection(pool, empresa_id) as conn:
        desativada = await servico.desativar_licenca(conn, resultado)
        assert desativada["status"] == "ativa"  # desinstalar o Agent != cancelar a licença

        evento = await conn.fetchrow(
            "SELECT tipo FROM licencas_eventos WHERE licenca_id = $1 AND tipo = 'licenca.desativada_pelo_agente'",
            licenca["id"],
        )
    assert evento is not None


# ---------------------------------------------------------------------------
# suspender_licenca / revogar_licenca / renovar_licenca
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_suspender_e_reativar_via_renovar(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Licenca Suspender Renovar")
    plano_id = await _plano_id(pool, "starter")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        licenca, _ = await servico.criar_licenca(conn, empresa_id, plano_id)

        suspensa = await servico.suspender_licenca(conn, empresa_id, licenca["id"])
        assert suspensa["status"] == "suspensa"

        renovada = await servico.renovar_licenca(conn, empresa_id, licenca["id"])
        assert renovada["status"] == "ativa"


@pytest.mark.asyncio
async def test_revogar_licenca_e_definitiva_nao_pode_ser_renovada(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Licenca Revogar Definitiva")
    plano_id = await _plano_id(pool, "starter")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        licenca, _ = await servico.criar_licenca(conn, empresa_id, plano_id)

        revogada = await servico.revogar_licenca(conn, empresa_id, licenca["id"])
        assert revogada["status"] == "revogada"

        with pytest.raises(ValueError):
            await servico.renovar_licenca(conn, empresa_id, licenca["id"])


@pytest.mark.asyncio
async def test_suspender_licenca_inexistente_retorna_none(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Licenca Suspender Inexistente")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        assert await servico.suspender_licenca(conn, empresa_id, uuid.uuid4()) is None


@pytest.mark.asyncio
async def test_revogar_licenca_de_outra_empresa_nao_afeta_nada(pool, empresa_factory):
    """RLS por si só já impediria a UPDATE de enxergar a linha, mas o teste
    confirma o comportamento de ponta a ponta pela camada de serviço --
    mesmo padrão de test_revogar_agente_de_outra_empresa_nao_afeta_nada."""
    empresa_a = await empresa_factory("Empresa Licenca Revogar Cross A")
    empresa_b = await empresa_factory("Empresa Licenca Revogar Cross B")
    plano_id = await _plano_id(pool, "starter")

    async with tenant_scoped_connection(pool, empresa_a) as conn_a:
        licenca_a, _ = await servico.criar_licenca(conn_a, empresa_a, plano_id)

    async with tenant_scoped_connection(pool, empresa_b) as conn_b:
        resultado = await servico.revogar_licenca(conn_b, empresa_b, licenca_a["id"])
    assert resultado is None

    async with tenant_scoped_connection(pool, empresa_a) as conn_a:
        linha = await conn_a.fetchrow("SELECT status FROM licencas WHERE id = $1", licenca_a["id"])
    assert linha["status"] == "ativa"


# ---------------------------------------------------------------------------
# registrar_endpoint / liberar_endpoint -- limite de vagas por plano
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_registrar_endpoint_ocupa_vaga_e_e_idempotente_para_o_mesmo_agente(pool, empresa_factory):
    """
    Fase D / D1 (ver ARQUITETURA_LICENCIAMENTO.md §10): `criar_agente` já
    ocupa a vaga automaticamente aqui, porque a licença já existe e está
    'ativa' quando o agente é criado -- as duas chamadas explícitas a
    `registrar_endpoint` abaixo passam a exercitar a idempotência tanto do
    auto-bind quanto de uma chamada manual repetida, sem mudar o que o
    teste queria provar (mesmo agente nunca consome uma segunda vaga).
    """
    empresa_id = await empresa_factory("Empresa Licenca Endpoint Idempotente")
    plano_id = await _plano_id(pool, "starter")  # max_endpoints = 5
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        licenca, _ = await servico.criar_licenca(conn, empresa_id, plano_id)
        agente, _ = await servico_agentes.criar_agente(conn, empresa_id, "host-endpoint-1")

        vaga_1 = await servico.registrar_endpoint(conn, empresa_id, licenca["id"], agente["id"])
        vaga_2 = await servico.registrar_endpoint(conn, empresa_id, licenca["id"], agente["id"])
        assert vaga_1["id"] == vaga_2["id"]  # mesmo agente não consome uma segunda vaga

        ocupadas = await conn.fetchval(
            "SELECT count(*) FROM licencas_endpoints WHERE licenca_id = $1 AND liberado_em IS NULL", licenca["id"],
        )
    assert ocupadas == 1


@pytest.mark.asyncio
async def test_registrar_endpoint_recusa_acima_do_limite_do_plano(pool, empresa_factory):
    """Cria um plano com max_endpoints=1 sob medida para o teste (evita
    depender do valor exato seedado para 'starter', que pode mudar).

    Fase D / D1: `criar_agente` só vincula automaticamente um agente à
    licença ATIVA que já existe NO MOMENTO da criação (ver
    ARQUITETURA_LICENCIAMENTO.md §10) -- por isso `agente_2` aqui nasce
    ANTES de qualquer licença existir (sem vínculo nenhum, exatamente como
    um agente de uma empresa sem licenciamento), preservando este teste
    como uma checagem direta de `registrar_endpoint`, isolada do
    comportamento de auto-bind na criação (que tem cobertura própria em
    tests/integration/test_agentes_service.py)."""
    empresa_id = await empresa_factory("Empresa Licenca Endpoint Limite")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        agente_2, _ = await servico_agentes.criar_agente(conn, empresa_id, "host-endpoint-limite-2")
    async with superadmin_scoped_connection(pool) as conn_admin:
        plano_id = await conn_admin.fetchval(
            "INSERT INTO planos (codigo, nome_exibicao, max_endpoints) VALUES ($1, $2, 1) RETURNING id",
            f"teste-limite-{uuid.uuid4().hex[:8]}", "Plano De Teste Limite 1",
        )

    async with tenant_scoped_connection(pool, empresa_id) as conn:
        licenca, _ = await servico.criar_licenca(conn, empresa_id, plano_id)
        # agente_1 nasce DEPOIS da licença já existir -- o auto-bind da
        # Fase D ocupa a única vaga do plano aqui mesmo, dentro de
        # criar_agente (nenhuma chamada manual a registrar_endpoint
        # necessária para ele).
        agente_1, _ = await servico_agentes.criar_agente(conn, empresa_id, "host-endpoint-limite-1")

        with pytest.raises(servico.LimiteEndpointsExcedidoError):
            await servico.registrar_endpoint(conn, empresa_id, licenca["id"], agente_2["id"])

        evento_negado = await conn.fetchrow(
            "SELECT tipo FROM licencas_eventos WHERE licenca_id = $1 AND tipo = 'licenca.endpoint_negado_limite'",
            licenca["id"],
        )
    assert evento_negado is not None


@pytest.mark.asyncio
async def test_liberar_endpoint_abre_vaga_para_um_agente_novo(pool, empresa_factory):
    """Depois de liberar, um plano com max_endpoints=1 aceita um agente
    diferente ocupar a vaga liberada.

    Fase D / D1: `agente_2` nasce ANTES de qualquer licença existir (sem
    vínculo automático -- ver ARQUITETURA_LICENCIAMENTO.md §10 e o
    raciocínio equivalente em
    test_registrar_endpoint_recusa_acima_do_limite_do_plano acima), para
    que ocupar a vaga liberada continue sendo a chamada MANUAL a
    `registrar_endpoint` que este teste quer exercitar."""
    empresa_id = await empresa_factory("Empresa Licenca Endpoint Liberar")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        agente_2, _ = await servico_agentes.criar_agente(conn, empresa_id, "host-endpoint-liberar-2")
    async with superadmin_scoped_connection(pool) as conn_admin:
        plano_id = await conn_admin.fetchval(
            "INSERT INTO planos (codigo, nome_exibicao, max_endpoints) VALUES ($1, $2, 1) RETURNING id",
            f"teste-liberar-{uuid.uuid4().hex[:8]}", "Plano De Teste Liberar 1",
        )

    async with tenant_scoped_connection(pool, empresa_id) as conn:
        licenca, _ = await servico.criar_licenca(conn, empresa_id, plano_id)
        # agente_1 nasce DEPOIS da licença -- auto-bind (Fase D) ocupa a
        # única vaga aqui mesmo, sem chamada manual a registrar_endpoint.
        agente_1, _ = await servico_agentes.criar_agente(conn, empresa_id, "host-endpoint-liberar-1")

        liberada = await servico.liberar_endpoint(conn, empresa_id, agente_1["id"])
        assert liberada["liberado_em"] is not None

        # a vaga liberada aceita um agente DIFERENTE -- prova de ponta a
        # ponta de que o plano de 1 vaga não ficou permanentemente ocupado
        # por um agente que já foi revogado.
        vaga_nova = await servico.registrar_endpoint(conn, empresa_id, licenca["id"], agente_2["id"])
        assert vaga_nova["agente_id"] == str(agente_2["id"])
