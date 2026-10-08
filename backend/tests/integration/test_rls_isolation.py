# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Teste OBRIGATÓRIO exigido pelo documento de migração original: abrir duas
conexões concorrentes, setar tenants diferentes, e confirmar que uma não vê
linha da outra. É o equivalente direto, a nível de banco, ao teste que já
existia no sistema single-tenant ("segunda empresa criada, admin acessa
incidentes e vê lista vazia") — mas agora provando o isolamento na camada
que realmente importa: RLS, não a lógica da aplicação.

Tudo que depende de isolamento multi-tenant (services/, api/v1/, web/)
confia neste teste passando primeiro.
"""
import uuid

import pytest
from tests.sql_cru import buscar, executar


pytestmark = pytest.mark.integration


async def _inserir_incidente(conn, empresa_id, incident_id="INC-TESTE-1"):
    await executar(conn, """
        INSERT INTO incidentes (empresa_id, incident_id, ip, severidade, pontuacao_risco, ataques)
        VALUES ($1, $2, '203.0.113.9', 'HIGH', 80, '["SQL Injection (SQLi)"]'::jsonb)
        """,
        empresa_id, incident_id,
    )


@pytest.mark.asyncio
async def test_duas_conexoes_concorrentes_tenants_diferentes_uma_nao_ve_linha_da_outra(db, empresa_factory):
    empresa_a = await empresa_factory("Empresa A")
    empresa_b = await empresa_factory("Empresa B")

    async with db.tenant_session(empresa_a) as conn_a:
        await _inserir_incidente(conn_a, empresa_a, "INC-A-1")

    async with db.tenant_session(empresa_b) as conn_b:
        await _inserir_incidente(conn_b, empresa_b, "INC-B-1")

    # Duas conexões concorrentes (não sequenciais), cada uma com seu próprio
    # tenant setado via SET LOCAL — o ponto central do teste é confirmar que
    # isso não vaza entre conexões simultâneas do mesmo pool.
    async with db.tenant_session(empresa_a) as conn_a, \
               db.tenant_session(empresa_b) as conn_b:
        linhas_a = await buscar(conn_a, "SELECT incident_id, empresa_id FROM incidentes ORDER BY incident_id")
        linhas_b = await buscar(conn_b, "SELECT incident_id, empresa_id FROM incidentes ORDER BY incident_id")

    ids_a = {r["incident_id"] for r in linhas_a}
    ids_b = {r["incident_id"] for r in linhas_b}

    assert ids_a == {"INC-A-1"}
    assert ids_b == {"INC-B-1"}
    assert "INC-B-1" not in ids_a
    assert "INC-A-1" not in ids_b
    assert all(r["empresa_id"] == empresa_a for r in linhas_a)
    assert all(r["empresa_id"] == empresa_b for r in linhas_b)


@pytest.mark.asyncio
async def test_sem_tenant_setado_retorna_zero_linhas_falha_fechada(db, empresa_factory, db_admin):
    """
    Uma conexão que ganhou o papel app_tenant mas NUNCA chamou set_config
    (o "esqueci de setar o tenant" que o doc original teme) deve ver ZERO
    linhas -- nunca um erro 500, e nunca as linhas de todo mundo.
    """
    empresa_a = await empresa_factory("Empresa Isolamento Falha Fechada")
    async with db.superadmin_session() as conn:
        await _inserir_incidente(conn, empresa_a, "INC-SEMSET-1")

    async with db.sessionmaker() as conn, conn.begin():
        await executar(conn, "SET LOCAL ROLE app_tenant")
        # Deliberadamente NÃO chama set_config('app.current_tenant', ...)
        linhas = await buscar(conn, "SELECT incident_id FROM incidentes")
    assert linhas == []


@pytest.mark.asyncio
async def test_tentativa_de_insert_cross_tenant_e_bloqueada_pela_policy(db, empresa_factory):
    """RLS sem FOR/WITH CHECK explícito ainda cobre INSERT (WITH CHECK
    reusa a expressão de USING) -- inserir com empresa_id de OUTRO tenant,
    dentro de uma transação escopada para o tenant A, deve falhar."""
    empresa_a = await empresa_factory("Empresa A Insert")
    empresa_b = await empresa_factory("Empresa B Insert")

    with pytest.raises(Exception):
        async with db.tenant_session(empresa_a) as conn:
            await _inserir_incidente(conn, empresa_b, "INC-CROSS-1")


@pytest.mark.asyncio
async def test_usuarios_tambem_isolado_por_rls(db, empresa_factory):
    empresa_a = await empresa_factory("Empresa A Usuarios")
    empresa_b = await empresa_factory("Empresa B Usuarios")

    async with db.superadmin_session() as conn:
        await executar(conn, "INSERT INTO usuarios (empresa_id, email, papel, senha_hash) VALUES ($1, $2, 'admin', 'x')",
            empresa_a, f"admin-a-{uuid.uuid4()}@example.com",
        )
        await executar(conn, "INSERT INTO usuarios (empresa_id, email, papel, senha_hash) VALUES ($1, $2, 'admin', 'x')",
            empresa_b, f"admin-b-{uuid.uuid4()}@example.com",
        )

    async with db.tenant_session(empresa_a) as conn:
        usuarios_visiveis = await buscar(conn, "SELECT empresa_id FROM usuarios")

    assert all(r["empresa_id"] == empresa_a for r in usuarios_visiveis)
    assert len(usuarios_visiveis) >= 1
