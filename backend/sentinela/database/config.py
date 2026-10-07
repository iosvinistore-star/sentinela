# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Configuração do banco de dados -- isolada do resto de `sentinela.config`.

Tudo que diz respeito a *como* falar com o Postgres (URL, tamanho do pool,
timeouts, eco de SQL) mora aqui e só aqui. `Settings` (config.py) continua
dono das variáveis `DATABASE_URL`/`DATABASE_URL_ADMIN` (uma só fonte de
verdade para quem monta a aplicação); este módulo as recebe e acrescenta os
ajustes de pool, que antes eram constantes soltas dentro de `db/pool.py`.
"""

from dataclasses import dataclass, field

from sentinela.core.segredos import obter_segredo

PAPEL_APP_TENANT = "app_tenant"
PAPEL_APP_SUPERADMIN = "app_superadmin"


def para_url_asyncpg(url: str) -> str:
    """
    Converte uma DSN `postgresql://` / `postgres://` na URL que o SQLAlchemy
    assíncrono exige (`postgresql+asyncpg://`). URLs que já informam o driver
    passam intactas.
    """
    if url.startswith("postgresql+"):
        return url
    for prefixo in ("postgresql://", "postgres://"):
        if url.startswith(prefixo):
            return "postgresql+asyncpg://" + url[len(prefixo) :]
    raise ValueError("DATABASE_URL precisa começar com postgresql:// ou postgres://")


@dataclass
class DatabaseSettings:
    url: str
    # Pool: `pool_size` conexões permanentes + até `max_overflow` extras sob
    # pico. Os defaults somam 20, o mesmo teto do pool asyncpg anterior.
    pool_size: int = field(default_factory=lambda: int(obter_segredo("SENTINELA_DB_POOL_SIZE", "10")))
    max_overflow: int = field(default_factory=lambda: int(obter_segredo("SENTINELA_DB_MAX_OVERFLOW", "10")))
    pool_timeout: float = field(default_factory=lambda: float(obter_segredo("SENTINELA_DB_POOL_TIMEOUT", "30")))
    # Recicla conexões antigas (firewalls/NAT derrubam conexões ociosas).
    pool_recycle: int = field(default_factory=lambda: int(obter_segredo("SENTINELA_DB_POOL_RECYCLE", "1800")))
    echo: bool = field(default_factory=lambda: obter_segredo("SENTINELA_DB_ECHO", "false").strip().lower() in ("1", "true", "sim"))

    @property
    def async_url(self) -> str:
        return para_url_asyncpg(self.url)

    @classmethod
    def de_settings(cls, settings, **ajustes) -> "DatabaseSettings":
        """Monta a partir de `sentinela.config.Settings` (fonte da DATABASE_URL)."""
        return cls(url=settings.database_url, **ajustes)
