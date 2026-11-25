# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Hash de senha (bcrypt) e emissão/verificação de JWT de sessão.

bcrypt puro (não passlib — passlib está sem manutenção ativa e gera avisos
com versões recentes de bcrypt). Substitui o sha256 sem sal que o
dashboard.py antigo usava para DASHBOARD_SENHA.
"""
import hashlib
import secrets
import time

import bcrypt
import jwt

ALGORITMO_JWT = "HS256"

SENHA_MIN_CARACTERES = 12
SENHA_MAX_BYTES = 72  # limite físico do bcrypt -- ver validar_politica_senha()


def validar_politica_senha(senha: str) -> None:
    """
    Validação central de senha (comprimento mínimo + teto de bytes do
    bcrypt), usada por todo caminho que grava uma senha nova: criação de
    usuário, troca da própria senha e confirmação de redefinição de senha.

    O teto de `SENHA_MAX_BYTES` existe porque `bcrypt.hashpw` levanta
    `ValueError: password cannot be longer than 72 bytes` para qualquer
    senha acima disso (bytes, não caracteres -- um caractere não-ASCII pode
    valer mais de 1 byte em UTF-8). Sem checar isso ANTES de chamar
    `hash_senha`, uma senha longa demais derrubava o endpoint inteiro com
    um 500 não tratado.
    """
    if len(senha) < SENHA_MIN_CARACTERES:
        raise ValueError(f"senha deve ter pelo menos {SENHA_MIN_CARACTERES} caracteres")
    if len(senha.encode("utf-8")) > SENHA_MAX_BYTES:
        raise ValueError(f"senha não pode ter mais de {SENHA_MAX_BYTES} bytes (evite muitos caracteres não-ASCII)")


PREFIXO_HASH_TOKEN = "sha256$"


def hash_token(token: str) -> str:
    """
    Hash de um TOKEN DE MÁQUINA (agente, licença): `sha256$<hex>`.

    Tokens gerados pelo servidor têm 256 bits de entropia (`secrets.token_urlsafe(32)`): não há o que um
    força bruta lenta como o bcrypt proteja -- o segredo não é adivinhável nem por dicionário. bcrypt existe
    para SENHAS escolhidas por pessoas. Verificar o token a cada heartbeat com bcrypt custava ~0,3 s de CPU
    e limitava o servidor a poucas centenas de agentes; o SHA-256 custa microssegundos. (Mesmo desenho de
    chaves de API de provedores como GitHub e Stripe.)
    """
    return PREFIXO_HASH_TOKEN + hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_token_e_rapido(token_hash: str) -> bool:
    return token_hash.startswith(PREFIXO_HASH_TOKEN)


def verificar_hash_token(token: str, token_hash: str) -> bool:
    """Compara em tempo constante. Só para hashes `sha256$` (ver `hash_token`)."""
    return secrets.compare_digest(hash_token(token), token_hash)


def hash_senha(senha: str) -> str:
    return bcrypt.hashpw(senha.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verificar_senha(senha: str, hash_: str) -> bool:
    try:
        return bcrypt.checkpw(senha.encode("utf-8"), hash_.encode("utf-8"))
    except (ValueError, TypeError):
        # hash malformado/vazio -> nunca autentica, mas também nunca derruba a requisição
        return False


def emitir_token_sessao(payload: dict, segredo: str, horas_validade: int = 12) -> str:
    """
    payload esperado: {"sub": usuario_id, "empresa_id": ..., "papel": ..., "email": ...}
    (empresa_id é None para superadmin, que não pertence a nenhum tenant).
    """
    agora = int(time.time())
    corpo = {**payload, "iat": agora, "exp": agora + horas_validade * 3600}
    return jwt.encode(corpo, segredo, algorithm=ALGORITMO_JWT)


def decodificar_token_sessao(token: str, segredo: str) -> dict:
    """Levanta jwt.InvalidTokenError (ou subclasses, ex.: ExpiredSignatureError) se inválido/expirado."""
    return jwt.decode(token, segredo, algorithms=[ALGORITMO_JWT])


def gerar_refresh_token() -> str:
    """Token opaco de alta entropia; somente SHA-256 é persistido."""
    return secrets.token_urlsafe(48)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
