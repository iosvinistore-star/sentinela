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
