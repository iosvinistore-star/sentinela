# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Autenticação de TOKEN DE ENROLLMENT (Fase D / D3) -- espelha
auth/licencas.py/auth/agentes.py no PADRÃO (prefixo em texto claro + hash
bcrypt do token inteiro + comparação timing-safe contra um hash dummy),
mas é uma família de token totalmente separada: um token de enrollment não
é um agente nem uma licença, é uma credencial de curta duração, multi-uso,
escopada a uma EMPRESA (não a uma máquina -- a máquina ainda não existe do
ponto de vista do backend no momento em que o token é gerado), trocada pela
identidade permanente de um agente na primeira execução do instalador. Ver
ARQUITETURA_LICENCIAMENTO.md §12 para o desenho completo. Nunca compartilha
tabela, prefixo ou hash com `agentes`/`licencas`.

Mesmo problema de "ovo e galinha" do login/agentes/licenças: RLS em
`agentes_enrollment_tokens` exige um tenant já setado, mas no momento em
que só temos o token ainda não sabemos a empresa. Resolvido do mesmo jeito
-- uma busca via `Database.superadmin_session` (BYPASSRLS), indexada pelo
PREFIXO do token.

Formato do token: "enr_<prefixo 12 hex>_<segredo 43 chars url-safe>".
"""
import asyncio
import secrets

import bcrypt

from sentinela.auth.security import verificar_senha
from sentinela.repositories.agentes import EnrollmentRepositorio

PREFIXO_TOKEN = "enr"
TAMANHO_PREFIXO_HEX = 12

# Mesmo raciocínio de auth/agentes.py:_HASH_DUMMY -- roda um bcrypt.checkpw
# mesmo quando o prefixo não bate com nenhum token de enrollment, para não
# vazar por timing se um prefixo "existe" ou não.
_HASH_DUMMY = bcrypt.hashpw(b"sentinela-enrollment-dummy-token", bcrypt.gensalt()).decode("utf-8")


def gerar_token() -> tuple[str, str]:
    """Retorna (token_completo, prefixo). O prefixo também está embutido no token
    (é como o lookup encontra a linha antes de verificar o hash)."""
    prefixo = secrets.token_hex(TAMANHO_PREFIXO_HEX // 2)
    segredo = secrets.token_urlsafe(32)
    token_completo = f"{PREFIXO_TOKEN}_{prefixo}_{segredo}"
    return token_completo, prefixo


def extrair_prefixo(token: str) -> str | None:
    # maxsplit=2: o segredo (gerado por secrets.token_urlsafe) pode conter
    # "_" -- mesma proteção já documentada em auth/agentes.py:extrair_prefixo.
    partes = token.split("_", 2)
    if len(partes) != 3 or partes[0] != PREFIXO_TOKEN:
        return None
    prefixo = partes[1]
    if len(prefixo) != TAMANHO_PREFIXO_HEX:
        return None
    return prefixo


async def autenticar_enrollment(db, token: str) -> dict | None:
    """
    Retorna {"enrollment_id", "empresa_id", "status", "expira_em",
    "max_usos", "usos"} se o token bater com um token de enrollment
    existente (de QUALQUER status/janela -- quem chama decide o que fazer
    com status='revogado'/expirado/esgotado, mesmo padrão de
    auth/licencas.py:autenticar_licenca: o instalador precisa conseguir
    distinguir "token não existe" (401) de "token existente mas não pode
    mais ser usado" (403, com o motivo no corpo)), ou None se o token não
    corresponde a nenhum registro.

    Nunca levanta exceção por token inválido -- quem chama decide o
    HTTPException (mesmo padrão de auth/agentes.py:autenticar_agente).
    """
    prefixo = extrair_prefixo(token or "")
    # A consulta (barata) roda e a sessão é devolvida ao pool ANTES do bcrypt:
    # o hash é caro em CPU e não deve segurar uma conexão do banco aberta.
    registro = None
    if prefixo is not None:
        async with db.superadmin_session() as sessao:
            registro = await EnrollmentRepositorio(sessao).buscar_por_prefixo(prefixo)
    token_valido = await asyncio.to_thread(
        verificar_senha, token, registro["token_hash"] if registro else _HASH_DUMMY
    )
    if registro and token_valido:
        return {
            "enrollment_id": registro["id"],
            "empresa_id": registro["empresa_id"],
            "status": registro["status"],
            "expira_em": registro["expira_em"],
            "max_usos": registro["max_usos"],
            "usos": registro["usos"],
        }
    return None
