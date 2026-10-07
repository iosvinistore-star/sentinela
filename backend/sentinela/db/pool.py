# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Fachada de compatibilidade -- o acesso ao banco agora vive em
`sentinela.database` (SQLAlchemy). Este módulo some quando os chamadores
migrarem para `Database.tenant_session` / `Database.superadmin_session`.
"""
from contextlib import asynccontextmanager

from sentinela.database.config import PAPEL_APP_SUPERADMIN, PAPEL_APP_TENANT, DatabaseSettings  # noqa: F401
from sentinela.database.session import Database


def criar_pool(dsn: str, **_ignorado) -> Database:
    return Database.conectar(DatabaseSettings(url=dsn))


@asynccontextmanager
async def tenant_scoped_connection(db: Database, empresa_id):
    async with db.tenant_session(empresa_id) as sessao:
        yield sessao


@asynccontextmanager
async def superadmin_scoped_connection(db: Database):
    async with db.superadmin_session() as sessao:
        yield sessao
