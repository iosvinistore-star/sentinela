# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Sessões escopadas por tenant -- o ponto único por onde TODO acesso ao banco
passa.

Duas garantias, ambas herdadas do desenho anterior (db/pool.py) e agora
centralizadas aqui:

1. **RLS** -- `tenant_session` troca para o papel `app_tenant` e fixa
   `app.current_tenant` DENTRO da transação (`SET LOCAL` /
   `set_config(..., true)`). Nada vaza para a próxima requisição que
   reutilizar a conexão do pool.
2. **Uma transação por sessão** -- a sessão abre a transação ao entrar e faz
   commit ao sair (rollback se levantar exceção). Repositórios usam
   `flush()`, nunca `commit()`; quem controla a transação é o chamador.

Bind parameters: `SET` não aceita parâmetros; por isso o tenant vai por
`set_config()`, uma função comum.
"""

from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from sentinela.database.config import PAPEL_APP_SUPERADMIN, PAPEL_APP_TENANT, DatabaseSettings
from sentinela.database.engine import criar_engine
from sentinela.database.sessao import Sessao


class Database:
    """Engine + fábrica de sessões. Vive em `app.state.db`."""

    def __init__(self, engine: AsyncEngine):
        self.engine = engine
        self.sessionmaker = async_sessionmaker(engine, class_=Sessao, expire_on_commit=False, autoflush=False)

    @classmethod
    def conectar(cls, config: DatabaseSettings) -> "Database":
        return cls(criar_engine(config))

    @asynccontextmanager
    async def tenant_session(self, empresa_id) -> AsyncIterator[AsyncSession]:
        """Sessão cujo acesso é restrito (via RLS) à empresa informada."""
        async with self.sessionmaker() as sessao, sessao.begin():
            await sessao.execute(text(f"SET LOCAL ROLE {PAPEL_APP_TENANT}"))
            await sessao.execute(
                text("SELECT set_config('app.current_tenant', :empresa, true)"),
                {"empresa": str(empresa_id)},
            )
            yield sessao

    @asynccontextmanager
    async def superadmin_session(self) -> AsyncIterator[AsyncSession]:
        """
        Sessão com BYPASSRLS, só para rotas `exigir_superadmin`, rotinas de
        manutenção e o lookup de login (que precisa ler `usuarios` antes de
        saber a empresa do chamador).
        """
        async with self.sessionmaker() as sessao, sessao.begin():
            await sessao.execute(text(f"SET LOCAL ROLE {PAPEL_APP_SUPERADMIN}"))
            yield sessao

    async def ping(self) -> None:
        async with self.engine.connect() as conexao:
            await conexao.execute(text("SELECT 1"))

    async def fechar(self) -> None:
        await self.engine.dispose()
