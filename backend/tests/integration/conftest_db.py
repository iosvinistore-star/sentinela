# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Fixtures de banco real para os testes de integração e de API. Precisa de um
Postgres acessível — localmente via `docker-compose -f docker-compose.test.yml
up -d` (ou qualquer Postgres 16 local), no CI via o `services: postgres:` do
workflow (ver .github/workflows/ci.yml).

Convenção de variáveis de ambiente (com defaults que batem com
docker-compose.test.yml, para "just work" localmente):
    TEST_DATABASE_URL_ADMIN       DSN de superusuário (aplica migrations)
    TEST_DATABASE_URL             DSN do role sentinela_app (o pool da app usa)
    TEST_SENTINELA_APP_DB_PASSWORD  senha do role sentinela_app
"""
import os
import uuid

import asyncpg
import pytest
import pytest_asyncio

from sentinela.db.migrations.run_migrations import aplicar_migrations
from sentinela.database import Database, DatabaseSettings
from sentinela.db.pool import superadmin_scoped_connection, tenant_scoped_connection

TEST_DATABASE_URL_ADMIN = os.environ.get(
    "TEST_DATABASE_URL_ADMIN", "postgresql://postgres:postgres_admin_pw@localhost:5432/sentinela_test"
)
TEST_SENTINELA_APP_DB_PASSWORD = os.environ.get("TEST_SENTINELA_APP_DB_PASSWORD", "app_pw_test123")
TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    f"postgresql://sentinela_app:{TEST_SENTINELA_APP_DB_PASSWORD}@localhost:5432/sentinela_test",
)


@pytest_asyncio.fixture(scope="session")
async def _schema_aplicado():
    """Aplica as migrations uma vez por sessão de teste (idempotente de qualquer forma)."""
    await aplicar_migrations(TEST_DATABASE_URL_ADMIN, TEST_SENTINELA_APP_DB_PASSWORD, log=lambda *_a: None)
    yield


@pytest_asyncio.fixture(scope="session")
async def pool(_schema_aplicado):
    p = Database.conectar(DatabaseSettings(url=TEST_DATABASE_URL, pool_size=5, max_overflow=5))
    yield p
    await p.fechar()


@pytest_asyncio.fixture(scope="session")
async def pool_admin(_schema_aplicado):
    """Pool com a DSN de superusuário — só para limpeza/inspeção direta nos testes."""
    p = Database.conectar(DatabaseSettings(url=TEST_DATABASE_URL_ADMIN, pool_size=2, max_overflow=2))
    yield p
    await p.fechar()


@pytest_asyncio.fixture
async def empresa_factory(pool):
    """
    Cria empresas de teste (via conexão superadmin, que ignora RLS) e limpa
    tudo que essas empresas geraram ao final do teste — mantém cada teste
    isolado dos demais mesmo compartilhando o mesmo banco.
    """
    criadas = []

    async def _criar(nome="Empresa Teste"):
        empresa_id = uuid.uuid4()
        async with superadmin_scoped_connection(pool) as conn:
            await conn.execute(
                "INSERT INTO empresas (id, nome) VALUES ($1, $2)", empresa_id, nome
            )
        criadas.append(empresa_id)
        return empresa_id

    yield _criar

    async with superadmin_scoped_connection(pool) as conn:
        for empresa_id in criadas:
            await conn.execute("DELETE FROM auditoria WHERE empresa_id = $1", empresa_id)
            await conn.execute("DELETE FROM bloqueios_firewall WHERE empresa_id = $1", empresa_id)
            await conn.execute("DELETE FROM incidentes WHERE empresa_id = $1", empresa_id)
            # reputacao_cache virou tenant-scoped (FK para empresas.id, ver
            # migrations/0007_reputacao_cache_tenant.sql) depois que esta
            # fixture de limpeza já existia -- sem apagar aqui também, o
            # DELETE FROM empresas abaixo estoura ForeignKeyViolationError
            # sempre que o teste consultou reputação de algum IP, e o erro
            # de teardown quebra (com ERROR, não FAILED) qualquer teste que
            # tenha usado reputação real em Postgres.
            await conn.execute("DELETE FROM reputacao_cache WHERE empresa_id = $1", empresa_id)
            # ips_protegidos (migrations/0014_autonomia_operacional.sql) --
            # mesmo motivo de reputacao_cache acima: FK para empresas.id
            # sem CASCADE.
            await conn.execute("DELETE FROM ips_protegidos WHERE empresa_id = $1", empresa_id)
            # licencas_eventos/licencas_endpoints/licencas
            # (migrations/0019_licenciamento.sql) -- mesmo motivo de
            # reputacao_cache/ips_protegidos acima (FK para empresas.id sem
            # CASCADE). Precisa vir ANTES do DELETE FROM agentes logo abaixo:
            # licencas_endpoints.agente_id referencia agentes(id) sem
            # CASCADE -- na ordem errada, apagar o agente primeiro estoura
            # ForeignKeyViolationError no teardown de qualquer teste que
            # tenha ocupado uma vaga de endpoint numa licença.
            await conn.execute("DELETE FROM licencas_eventos WHERE empresa_id = $1", empresa_id)
            await conn.execute("DELETE FROM licencas_endpoints WHERE empresa_id = $1", empresa_id)
            await conn.execute("DELETE FROM licencas WHERE empresa_id = $1", empresa_id)
            # agentes_eventos/agentes (migrations/0016_agentes_endpoint.sql)
            # -- mesmo motivo de reputacao_cache/ips_protegidos acima (FK
            # para empresas.id sem CASCADE). Precisa vir ANTES do DELETE FROM
            # usuarios logo abaixo: agentes.criado_por_usuario_id referencia
            # usuarios(id) sem CASCADE -- na ordem errada, apagar o usuário
            # primeiro estoura ForeignKeyViolationError no teardown de
            # qualquer teste que tenha criado um agente.
            # eventos_siem/eventos_siem_cold (migrations 0024/0025): FK para
            # empresas e agentes sem CASCADE -- precisa vir antes de agentes.
            # (app_superadmin recebeu SELECT/DELETE nelas em 0030.)
            await conn.execute("DELETE FROM eventos_siem WHERE empresa_id = $1", empresa_id)
            await conn.execute("DELETE FROM eventos_siem_cold WHERE empresa_id = $1", empresa_id)
            await conn.execute("DELETE FROM agentes_eventos WHERE empresa_id = $1", empresa_id)
            await conn.execute("DELETE FROM agentes WHERE empresa_id = $1", empresa_id)
            # agentes_enrollment_tokens (migrations/0022_agentes_enrollment.sql,
            # Fase D / D3) -- mesmo motivo de agentes/agentes_eventos acima:
            # `criado_por_usuario_id` referencia usuarios(id) sem CASCADE
            # (de propósito -- ver a migration). Precisa vir ANTES do DELETE
            # FROM usuarios logo abaixo, mesma ordem já aplicada a agentes.
            await conn.execute("DELETE FROM agentes_enrollment_tokens WHERE empresa_id = $1", empresa_id)
            # redefinicoes_senha não precisa de DELETE explícito aqui: tem
            # ON DELETE CASCADE em usuario_id (ver migrations/0009).
            await conn.execute("DELETE FROM usuarios WHERE empresa_id = $1", empresa_id)
            await conn.execute("DELETE FROM empresas WHERE id = $1", empresa_id)


@pytest.fixture
def conexao_tenant_factory(pool):
    """Atalho: `async with conexao_tenant_factory(empresa_id) as conn: ...`"""
    def _factory(empresa_id):
        return tenant_scoped_connection(pool, empresa_id)
    return _factory
