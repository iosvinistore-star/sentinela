# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Runner de migrations SQL — sem ORM/Alembic, só aplica os arquivos .sql
numerados desta pasta em ordem, uma vez cada, registrando o que já rodou em
`schema_migrations`. Mantém o estilo "SQL puro" já usado no resto do
projeto (nada aqui usa ORM).

Uso:
    python -m sentinela.db.migrations.run_migrations \
        --database-url-admin postgresql://postgres:senha@localhost:5432/sentinela

    # ou via variáveis de ambiente:
    DATABASE_URL_ADMIN=postgresql://... SENTINELA_APP_DB_PASSWORD=... \
        python -m sentinela.db.migrations.run_migrations

Conecta com uma DSN de SUPERUSUÁRIO (ex.: o role `postgres` do Postgres
gerenciado, ou qualquer superusuário local) — precisa de privilégio pra
criar roles (0004) e aplicar RLS/FORCE (0003), que um role comum não tem.
"""
import argparse
import asyncio
import os
from pathlib import Path

import asyncpg

PASTA_MIGRATIONS = Path(__file__).resolve().parent
PLACEHOLDER_SENHA_APP = "__SENTINELA_APP_PASSWORD__"


def _listar_arquivos_sql():
    return sorted(PASTA_MIGRATIONS.glob("[0-9][0-9][0-9][0-9]_*.sql"))


async def _garantir_tabela_controle(conn):
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            nome        text PRIMARY KEY,
            aplicado_em timestamptz NOT NULL DEFAULT now()
        )
        """
    )


async def _ja_aplicadas(conn):
    linhas = await conn.fetch("SELECT nome FROM schema_migrations")
    return {r["nome"] for r in linhas}


def _preparar_sql(conteudo, senha_app):
    if PLACEHOLDER_SENHA_APP in conteudo:
        if not senha_app:
            raise RuntimeError(
                f"{PLACEHOLDER_SENHA_APP} presente na migration, mas nenhuma senha foi "
                "fornecida (--sentinela-app-password ou env SENTINELA_APP_DB_PASSWORD)."
            )
        # Senha nunca deve conter aspas simples nesta substituição textual
        # simples (não é bind parameter -- CREATE ROLE não aceita $1).
        if "'" in senha_app:
            raise RuntimeError("SENTINELA_APP_DB_PASSWORD não pode conter aspas simples (').")
        conteudo = conteudo.replace(PLACEHOLDER_SENHA_APP, senha_app)
    return conteudo


async def aplicar_migrations(database_url_admin, senha_app=None, log=print):
    conn = await asyncpg.connect(database_url_admin)
    try:
        await _garantir_tabela_controle(conn)
        aplicadas = await _ja_aplicadas(conn)

        aplicadas_agora = []
        for caminho in _listar_arquivos_sql():
            if caminho.name in aplicadas:
                continue
            conteudo = _preparar_sql(caminho.read_text(encoding="utf-8"), senha_app)
            async with conn.transaction():
                await conn.execute(conteudo)
                await conn.execute(
                    "INSERT INTO schema_migrations (nome) VALUES ($1)", caminho.name
                )
            aplicadas_agora.append(caminho.name)
            log(f"[migrations] aplicada: {caminho.name}")

        if not aplicadas_agora:
            log("[migrations] nada a aplicar — schema já está atualizado.")
        return aplicadas_agora
    finally:
        await conn.close()


def _construir_parser():
    p = argparse.ArgumentParser(description="Aplica as migrations SQL do Sentinela SOC")
    p.add_argument(
        "--database-url-admin",
        default=os.environ.get("DATABASE_URL_ADMIN"),
        help="DSN de superusuário (ou env DATABASE_URL_ADMIN)",
    )
    p.add_argument(
        "--sentinela-app-password",
        default=os.environ.get("SENTINELA_APP_DB_PASSWORD"),
        help="Senha para o role sentinela_app (ou env SENTINELA_APP_DB_PASSWORD)",
    )
    return p


async def _main_async():
    args = _construir_parser().parse_args()
    if not args.database_url_admin:
        raise SystemExit("--database-url-admin (ou DATABASE_URL_ADMIN) é obrigatório")
    await aplicar_migrations(args.database_url_admin, args.sentinela_app_password)


def main():
    asyncio.run(_main_async())


if __name__ == "__main__":
    main()
