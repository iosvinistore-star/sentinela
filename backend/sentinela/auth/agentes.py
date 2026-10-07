# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Autenticação de AGENTE (Sentinela Endpoint) -- espelha auth/login.py, mas
para uma máquina com um token de longa duração, não um humano com senha.

Mesmo problema de "ovo e galinha" do login: RLS em `agentes` exige um
tenant já setado, mas no momento em que só temos o token ainda não sabemos
a empresa. Resolvido do mesmo jeito -- uma busca via
`Database.superadmin_session` (BYPASSRLS), indexada, aqui pelo PREFIXO do
token (não pelo token inteiro, que só existe em hash).

Formato do token: "agt_<prefixo 12 hex>_<segredo 43 chars url-safe>".
Gerado por `gerar_token()`; só o hash bcrypt do token INTEIRO fica no
banco (`agentes.token_hash`) -- o prefixo fica em texto puro
(`agentes.token_prefixo`, UNIQUE, indexado) só para tornar o lookup O(1)
em vez de rodar bcrypt.checkpw contra TODO agente cadastrado a cada
heartbeat (o mesmo trade-off que uma API key de qualquer provedor --
GitHub, Stripe -- faz).
"""
import asyncio
import secrets

import bcrypt

from sentinela.auth.security import verificar_senha
from sentinela.repositories.agentes import AgenteRepositorio

PREFIXO_TOKEN = "agt"
TAMANHO_PREFIXO_HEX = 12

# Mesmo raciocínio de auth/login.py:HASH_DUMMY -- roda um bcrypt.checkpw
# mesmo quando o prefixo não bate com nenhum agente, para não vazar por
# timing se um prefixo "existe" ou não.
_HASH_DUMMY = bcrypt.hashpw(b"sentinela-agent-dummy-token", bcrypt.gensalt()).decode("utf-8")


def gerar_token() -> tuple[str, str]:
    """Retorna (token_completo, prefixo). O prefixo também está embutido no token
    (é como o lookup encontra a linha antes de verificar o hash)."""
    prefixo = secrets.token_hex(TAMANHO_PREFIXO_HEX // 2)
    segredo = secrets.token_urlsafe(32)
    token_completo = f"{PREFIXO_TOKEN}_{prefixo}_{segredo}"
    return token_completo, prefixo


def extrair_prefixo(token: str) -> str | None:
    # maxsplit=2: o segredo (gerado por secrets.token_urlsafe) pode conter
    # "_" -- um split() sem limite quebraria o parsing sempre que isso
    # acontecesse. O prefixo em si é sempre hex puro (nunca tem "_").
    partes = token.split("_", 2)
    if len(partes) != 3 or partes[0] != PREFIXO_TOKEN:
        return None
    prefixo = partes[1]
    if len(prefixo) != TAMANHO_PREFIXO_HEX:
        return None
    return prefixo


async def autenticar_agente(db, token: str) -> dict | None:
    """
    Retorna {"agente_id", "empresa_id", "hostname"} se o token bater com um
    agente com status='ativo', ou None. Nunca levanta exceção por token
    inválido/revogado -- quem chama decide o HTTPException (ver
    auth/dependencies.py:agente_atual).
    """
    prefixo = extrair_prefixo(token or "")
    # A consulta (barata) roda e a sessão é devolvida ao pool ANTES do bcrypt:
    # o hash é caro em CPU e não deve segurar uma conexão do banco aberta.
    agente = None
    if prefixo is not None:
        async with db.superadmin_session() as sessao:
            agente = await AgenteRepositorio(sessao).buscar_ativo_por_prefixo(prefixo)
    token_valido = await asyncio.to_thread(
        verificar_senha, token, agente["token_hash"] if agente else _HASH_DUMMY
    )
    if agente and token_valido:
        return {
            "agente_id": agente["id"],
            "empresa_id": agente["empresa_id"],
            "hostname": agente["hostname"],
        }
    return None
