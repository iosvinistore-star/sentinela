# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Fase C -- MFA/TOTP (RFC 6238) e recovery codes.

Fluxo (C6):

    usuário autenticado -> inicia setup de MFA -> servidor gera segredo ->
    devolve QR/URI de provisionamento -> usuário digita o código do app
    autenticador -> servidor valida -> MFA ativado

    login -> senha válida -> se MFA habilitado, exige código TOTP (ou um
    recovery code) -> sessão completa só é emitida depois disso.

Este módulo cobre só a CRIPTOGRAFIA/geração/validação -- sem tocar banco
(isso é `services/mfa.py`) nem HTTP (isso é `api/v1/usuarios.py` e
`web/routes_usuarios.py`). Separação deliberada: os mesmos motivos que já
levaram `auth/security.py` (hash de senha, JWT) a ficar isolado de
`services/usuarios.py` (persistência) se aplicam aqui.

## Por que TOTP e não outro fator

`pyotp` implementa RFC 6238 (TOTP) -- não reinventado à mão, mesmo
raciocínio que já levou este projeto a usar `bcrypt`/`pyjwt` em vez de
hash/JWT escritos do zero.

## Por que Fernet para o segredo, e não um hash

Ao contrário de uma senha (que só precisa ser CONFERIDA, nunca lida de
volta -- por isso bcrypt, one-way, serve), o segredo TOTP precisa ser
RECUPERADO em claro toda vez que um código é validado (o servidor calcula
o código esperado a partir do segredo, e código digitado ≠ segredo -- não
dá pra comparar hashes). `cryptography.fernet.Fernet` (AES-128-CBC +
HMAC-SHA256 autenticado) cobre isso -- criptografia simétrica, não hash.
A chave (`SENTINELA_MFA_ENCRYPTION_KEY`, ver config.py:Settings.validar())
nunca é armazenada perto do segredo cifrado -- fica só em variável de
ambiente/segredo de infraestrutura, nunca na coluna `mfa_secret_cifrado`
nem em lugar nenhum do banco.

## Recovery codes -- por que hash (bcrypt) em vez de texto plano

Ao contrário do segredo TOTP, um recovery code É comparável como senha:
o usuário digita o código, o servidor só precisa saber "esse código bate
com algum dos que emiti e ainda não foi usado" -- nunca precisa
"recuperar" o valor original. Por isso hash (bcrypt, reaproveitando
`auth/security.py:hash_senha`/`verificar_senha`) é a escolha certa aqui,
ao contrário do segredo TOTP -- mesma lógica de por que senhas de login
são hasheadas e o segredo TOTP não pode ser.
"""
from __future__ import annotations

import secrets
import string

import pyotp
from cryptography.fernet import Fernet, InvalidToken

from sentinela.auth.security import hash_senha, verificar_senha

ISSUER_NAME = "Sentinela SOC"

# RFC 6238 usa passos de 30s por padrão (pyotp também). `valid_window=1`
# aceita o código do passo anterior E do próximo (tolerância de +-30s) --
# pequena o bastante para não enfraquecer a proteção (uma janela de +-30s
# não dá tempo útil de força bruta, já que rate limiting -- C9 -- também
# se aplica), grande o bastante para absorver relógios de cliente/servidor
# levemente dessincronizados (o caso real mais comum de "código correto
# recusado por engano").
JANELA_TOLERANCIA_CLOCK = 1

QUANTIDADE_RECOVERY_CODES = 10
# Formato "XXXX-XXXX-XXXX" (12 caracteres alfanuméricos maiúsculos, sem
# caracteres ambíguos como 0/O ou 1/I/L) -- confortável de digitar/ler,
# com entropia suficiente (32^12 ≈ 2^60 combinações) para não ser
# adivinhável por força bruta, mesmo sem rate limiting.
_ALFABETO_RECOVERY_CODE = "".join(c for c in (string.ascii_uppercase + string.digits) if c not in "0O1IL")


def gerar_segredo_totp() -> str:
    """Segredo base32 de 160 bits (padrão do pyotp) -- compatível com qualquer app autenticador (Google Authenticator, Authy etc.)."""
    return pyotp.random_base32()


def cifrar_segredo(segredo_totp: str, chave_fernet: str) -> bytes:
    return Fernet(chave_fernet.encode("utf-8")).encrypt(segredo_totp.encode("utf-8"))


def decifrar_segredo(segredo_cifrado: bytes, chave_fernet: str) -> str:
    """Levanta cryptography.fernet.InvalidToken se a chave estiver errada ou o valor tiver sido adulterado -- Fernet autentica (HMAC) além de cifrar, então isto também pega corrupção de dado, não só chave errada."""
    return Fernet(chave_fernet.encode("utf-8")).decrypt(segredo_cifrado).decode("utf-8")


def gerar_uri_provisionamento(segredo_totp: str, email: str) -> str:
    """URI otpauth:// para gerar o QR Code no cliente (front-end) -- este backend nunca desenha a imagem do QR, só fornece a URI (padrão de todo provedor TOTP: deixar o desenho do QR pro lado que já tem uma lib de imagem, evitando puxar essa dependência aqui)."""
    return pyotp.totp.TOTP(segredo_totp).provisioning_uri(name=email, issuer_name=ISSUER_NAME)


def verificar_codigo_totp(segredo_totp: str, codigo: str) -> bool:
    """
    `codigo` vem sempre como string (dígitos podem ter zero à esquerda,
    ex.: "007123" -- um int perderia isso). `pyotp.TOTP.verify` já rejeita
    silenciosamente qualquer valor que não seja um código numérico de 6
    dígitos, sem levantar exceção -- seguro chamar com entrada arbitrária
    do usuário.
    """
    if not codigo or not codigo.isdigit():
        return False
    return pyotp.totp.TOTP(segredo_totp).verify(codigo, valid_window=JANELA_TOLERANCIA_CLOCK)


def gerar_recovery_codes(quantidade: int = QUANTIDADE_RECOVERY_CODES) -> list[str]:
    """
    Códigos em CLARO -- só existem em memória neste momento (chamador
    mostra ao usuário UMA VEZ, ver C7: "nunca reexibir os códigos após o
    momento apropriado de exibição") e nunca são persistidos assim; quem
    persiste (services/mfa.py) chama `hash_recovery_code` em cada um antes
    de gravar.

    `secrets.choice` (não `random.choice`) -- gerador criptograficamente
    seguro, mesmo padrão de qualquer token de sessão/API deste projeto
    (ver auth/agentes.py/auth/licencas.py para tokens de longa duração
    equivalentes).
    """
    codigos = []
    for _ in range(quantidade):
        bruto = "".join(secrets.choice(_ALFABETO_RECOVERY_CODE) for _ in range(12))
        codigos.append(f"{bruto[0:4]}-{bruto[4:8]}-{bruto[8:12]}")
    return codigos


def hash_recovery_code(codigo: str) -> str:
    """Normaliza (maiúsculas, sem espaços) antes de hashear -- garante que
    comparar um código digitado com espaços/minúsculas acidentais ainda
    funcione (ver `verificar_recovery_code`, que aplica a MESMA normalização)."""
    return hash_senha(_normalizar_recovery_code(codigo))


def verificar_recovery_code(codigo_informado: str, hash_armazenado: str) -> bool:
    return verificar_senha(_normalizar_recovery_code(codigo_informado), hash_armazenado)


def _normalizar_recovery_code(codigo: str) -> str:
    return (codigo or "").strip().upper()


__all__ = [
    "InvalidToken",
    "JANELA_TOLERANCIA_CLOCK",
    "QUANTIDADE_RECOVERY_CODES",
    "cifrar_segredo",
    "decifrar_segredo",
    "gerar_recovery_codes",
    "gerar_segredo_totp",
    "gerar_uri_provisionamento",
    "hash_recovery_code",
    "verificar_codigo_totp",
    "verificar_recovery_code",
]
