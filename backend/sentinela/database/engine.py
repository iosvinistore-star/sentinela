# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Criação do engine assíncrono do SQLAlchemy (um por processo)."""

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from sentinela.database.config import DatabaseSettings


def criar_engine(config: DatabaseSettings) -> AsyncEngine:
    return create_async_engine(
        config.async_url,
        echo=config.echo,
        pool_size=config.pool_size,
        max_overflow=config.max_overflow,
        pool_timeout=config.pool_timeout,
        pool_recycle=config.pool_recycle,
        # Descarta conexões mortas antes de entregá-las (ping barato).
        pool_pre_ping=True,
    )
