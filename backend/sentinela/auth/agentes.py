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
import logging
import secrets

import bcrypt

from sentinela.auth.cache_token import cache_tokens
from sentinela.auth.security import hash_token, hash_token_e_rapido
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
    # `cache_tokens` evita o bcrypt quando este MESMO token já foi verificado contra o MESMO hash que está no banco
    # agora (ver auth/cache_token.py); um token revogado nem chega aqui, porque a linha deixa de ser encontrada.
    token_valido = await cache_tokens.verificar(token, agente["token_hash"] if agente else _HASH_DUMMY)
    if agente and token_valido and not hash_token_e_rapido(agente["token_hash"]):
        await _migrar_para_hash_rapido(db, agente["id"], token)
    if agente and token_valido:
        return {
            "agente_id": agente["id"],
            "empresa_id": agente["empresa_id"],
            "hostname": agente["hostname"],
        }
    return None


async def _migrar_para_hash_rapido(db, agente_id, token: str) -> None:
    """
    Token emitido antes do hash rápido (bcrypt): na primeira verificação bem-sucedida troca o hash guardado por
    `sha256$...` (ver `auth.security.hash_token`), e os heartbeats seguintes deixam de pagar bcrypt. Melhor esforço:
    falhar aqui nunca derruba a autenticação.
    """
    try:
        async with db.superadmin_session() as sessao:
            await AgenteRepositorio(sessao).atualizar_token_hash(agente_id, hash_token(token))
    except Exception:  # noqa: BLE001
        logging.getLogger(__name__).warning("não foi possível migrar o hash do token", exc_info=True)
