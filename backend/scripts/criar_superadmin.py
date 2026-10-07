# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Bootstrap do primeiro superadmin -- resolve o "ovo e galinha" de uma
instalação nova sem dados legados: criar uma empresa exige estar logado
como superadmin (`/admin/empresas`, `/api/v1/admin/empresas`), mas não há
como logar como superadmin antes de um existir. Este script conecta
diretamente com a DSN de superusuário do Postgres (a mesma usada pelas
migrations) e insere a linha em `superadmins` com a senha já hasheada
(bcrypt) -- fora da API, mas usando exatamente o mesmo hash que a API usaria.

Uso:
    SENTINELA_BOOTSTRAP_SENHA=uma-senha-forte python -m scripts.criar_superadmin \\
        --database-url-admin postgresql://postgres:senha@localhost:5432/sentinela \\
        --email superadmin@sua-empresa.example \\
        --senha-env SENTINELA_BOOTSTRAP_SENHA

Idempotente: rodar de novo com o mesmo email não duplica nem sobrescreve a
senha (ON CONFLICT DO NOTHING) -- rode `atualizar_senha.py` (não existe
ainda) ou um UPDATE manual se precisar trocar a senha de um superadmin
existente.

A senha nunca é aceita como argumento de CLI puro (evita vazar no
histórico do shell) -- só via variável de ambiente nomeada por --senha-env,
mesmo padrão de scripts/migrar_sqlite_para_postgres.py.
"""
import argparse
import asyncio
import os

import asyncpg

from sentinela.auth.security import hash_senha, validar_politica_senha


async def criar_superadmin(database_url_admin: str, email: str, senha: str) -> bool:
    validar_politica_senha(senha)
    conn = await asyncpg.connect(database_url_admin)
    try:
        row = await conn.fetchrow(
            """
            INSERT INTO superadmins (email, senha_hash) VALUES ($1, $2)
            ON CONFLICT (email) DO NOTHING
            RETURNING id
            """,
            email, hash_senha(senha),
        )
        return row is not None
    finally:
        await conn.close()


def _construir_parser():
    p = argparse.ArgumentParser(description="Cria o primeiro superadmin do Sentinela SOC")
    p.add_argument(
        "--database-url-admin",
        default=os.environ.get("DATABASE_URL_ADMIN"),
        help="DSN de superusuário do Postgres (ou env DATABASE_URL_ADMIN)",
    )
    p.add_argument("--email", required=True, help="Email do superadmin a criar")
    p.add_argument(
        "--senha-env",
        required=True,
        help="Nome da variável de ambiente que contém a senha (nunca passe a senha direto na CLI)",
    )
    return p


async def _main_async():
    args = _construir_parser().parse_args()
    if not args.database_url_admin:
        raise SystemExit("--database-url-admin (ou DATABASE_URL_ADMIN) é obrigatório")

    senha = os.environ.get(args.senha_env)
    if not senha:
        raise SystemExit(f"variável de ambiente {args.senha_env} não definida ou vazia")

    criado = await criar_superadmin(args.database_url_admin, args.email, senha)
    if criado:
        print(f"[criar_superadmin] superadmin criado: {args.email}")
    else:
        print(f"[criar_superadmin] já existia um superadmin com este email, nada foi alterado: {args.email}")


def main():
    asyncio.run(_main_async())


if __name__ == "__main__":
    main()
