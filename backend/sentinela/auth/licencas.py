# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Autenticação de LICENÇA (Sentinela SaaS) -- espelha auth/agentes.py no
PADRÃO (prefixo em texto claro + hash bcrypt do token inteiro + comparação
timing-safe contra um hash dummy), mas é uma família de token totalmente
separada: uma licença não é um agente (EDR local), é o direito de uso do
produto concedido a uma empresa. Nunca compartilha tabela, prefixo ou hash
com auth/agentes.py -- ver ARQUITETURA_LICENCIAMENTO.md para o porquê de
serem conceitos distintos mesmo tendo a mesma forma de token.

Mesmo problema de "ovo e galinha" do login/agentes: RLS em `licencas` exige
um tenant já setado, mas no momento em que só temos o token ainda não
sabemos a empresa. Resolvido do mesmo jeito -- uma busca via
`superadmin_scoped_connection` (BYPASSRLS), indexada pelo PREFIXO do token
(não pelo token inteiro, que só existe em hash).

Formato do token: "lic_<prefixo 12 hex>_<segredo 43 chars url-safe>". Gerado
por `gerar_token()`; só o hash bcrypt do token INTEIRO fica no banco
(`licencas.token_hash`) -- o prefixo fica em texto puro
(`licencas.token_prefixo`, UNIQUE, indexado) só para tornar o lookup O(1) em
vez de rodar bcrypt.checkpw contra TODA licença cadastrada a cada validação.
"""
import asyncio
import secrets

import bcrypt

from sentinela.auth.security import verificar_senha
from sentinela.repositories.licencas import LicencaRepositorio

PREFIXO_TOKEN = "lic"
TAMANHO_PREFIXO_HEX = 12

# Mesmo raciocínio de auth/agentes.py:_HASH_DUMMY -- roda um bcrypt.checkpw
# mesmo quando o prefixo não bate com nenhuma licença, para não vazar por
# timing se um prefixo "existe" ou não.
_HASH_DUMMY = bcrypt.hashpw(b"sentinela-license-dummy-token", bcrypt.gensalt()).decode("utf-8")


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
    # acontecesse. O prefixo em si é sempre hex puro (nunca tem "_"). Mesmo
    # bug já documentado (e corrigido) em auth/agentes.py:extrair_prefixo.
    partes = token.split("_", 2)
    if len(partes) != 3 or partes[0] != PREFIXO_TOKEN:
        return None
    prefixo = partes[1]
    if len(prefixo) != TAMANHO_PREFIXO_HEX:
        return None
    return prefixo


async def autenticar_licenca(pool, token: str) -> dict | None:
    """
    Retorna {"licenca_id", "empresa_id", "plano_id", "status", "expira_em"}
    se o token bater com uma licença existente (de QUALQUER status -- quem
    chama decide o que fazer com status != 'ativa', ex.: devolver 403 em vez
    de 401, para o Agent conseguir distinguir "token errado" de "licença
    suspensa"), ou None se o token não corresponde a nenhuma licença.

    Nunca levanta exceção por token inválido/revogado -- quem chama decide
    o HTTPException (mesmo padrão de auth/agentes.py:autenticar_agente).
    """
    prefixo = extrair_prefixo(token or "")
    # A consulta (barata) roda e a sessão é devolvida ao pool ANTES do bcrypt:
    # o hash é caro em CPU e não deve segurar uma conexão do banco aberta.
    licenca = None
    if prefixo is not None:
        async with pool.superadmin_session() as sessao:
            licenca = await LicencaRepositorio(sessao).buscar_por_prefixo(prefixo)
    token_valido = await asyncio.to_thread(
        verificar_senha, token, licenca["token_hash"] if licenca else _HASH_DUMMY
    )
    if licenca and token_valido:
        return {
            "licenca_id": licenca["id"],
            "empresa_id": licenca["empresa_id"],
            "plano_id": licenca["plano_id"],
            "status": licenca["status"],
            "expira_em": licenca["expira_em"],
        }
    return None
