# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Revoga IMEDIATAMENTE toda sessão já aberta de um superadmin, incrementando
`token_version` (ver migrations/0013_token_version_superadmin.sql).

Por que isto existe: diferente de um usuário de empresa (que pode trocar a
própria senha em Minha Conta, o que já incrementa token_version -- ver
services/usuarios.py:trocar_propria_senha), não existe hoje nenhum fluxo de
"trocar senha" para superadmin dentro da aplicação -- só o bootstrap inicial
(scripts/criar_superadmin.py). Ou seja: sem esta ferramenta, a única forma
de encerrar uma sessão de superadmin sob suspeita (cookie vazado, notebook
comprometido, alguém saindo da equipe) era esperar o cookie expirar sozinho
(`sessao_horas`, 12h por padrão) -- para a conta de maior impacto do
sistema, isso é tempo demais.

Uso (durante um incidente, ou rotina de desligamento de acesso):
    python -m scripts.revogar_sessao_superadmin \\
        --database-url-admin postgresql://postgres:senha@localhost:5432/sentinela \\
        --email superadmin-suspeito@sua-empresa.example

Roda com a DSN de superusuário do Postgres (mesma usada pelas migrations)
-- não passa pelo pool da aplicação de propósito: isto precisa funcionar
mesmo que a aplicação esteja com problema, e é uma ação operacional rara
o bastante para não valer a pena expor como rota HTTP (que exigiria, por
sua vez, sua própria autorização -- "quem pode revogar sessão de
superadmin" é uma pergunta melhor respondida fora da aplicação, por quem já
tem acesso direto ao banco de produção).

NÃO desativa a conta nem troca a senha -- só invalida o(s) JWT(s) já
emitido(s). O superadmin consegue logar de novo normalmente (um login novo
emite um "tv" atualizado).
"""
import argparse
import asyncio
import os

import asyncpg


async def revogar_sessao_superadmin(database_url_admin: str, email: str) -> int | None:
    """Devolve o novo `token_version`, ou `None` se não existe superadmin com este email."""
    conn = await asyncpg.connect(database_url_admin)
    try:
        row = await conn.fetchrow(
            "UPDATE superadmins SET token_version = token_version + 1 WHERE email = $1 RETURNING token_version",
            email,
        )
        return row["token_version"] if row else None
    finally:
        await conn.close()


def _construir_parser():
    p = argparse.ArgumentParser(
        description="Revoga imediatamente toda sessão já aberta de um superadmin (incrementa token_version)"
    )
    p.add_argument(
        "--database-url-admin",
        default=os.environ.get("DATABASE_URL_ADMIN"),
        help="DSN de superusuário do Postgres (ou env DATABASE_URL_ADMIN)",
    )
    p.add_argument("--email", required=True, help="Email do superadmin cuja(s) sessão(ões) revogar")
    return p


async def _main_async():
    args = _construir_parser().parse_args()
    if not args.database_url_admin:
        raise SystemExit("--database-url-admin (ou DATABASE_URL_ADMIN) é obrigatório")

    novo_tv = await revogar_sessao_superadmin(args.database_url_admin, args.email)
    if novo_tv is None:
        raise SystemExit(f"[revogar_sessao_superadmin] nenhum superadmin encontrado com email: {args.email}")
    print(
        f"[revogar_sessao_superadmin] sessões de {args.email} revogadas -- "
        f"qualquer cookie já emitido para de funcionar na próxima requisição (token_version agora = {novo_tv})."
    )


def main():
    asyncio.run(_main_async())


if __name__ == "__main__":
    main()
