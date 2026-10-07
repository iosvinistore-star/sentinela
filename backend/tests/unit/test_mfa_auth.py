# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testes de unidade de sentinela.auth.mfa -- geração/cifragem de segredo,
validação de código TOTP, geração/hash/verificação de recovery codes. Sem
Postgres (isso é testado em tests/api/test_mfa_api.py, ponta a ponta).
"""
import time

import pyotp
import pytest

from sentinela.auth import mfa

_CHAVE_FERNET = "FubcIZSMWTNTDq6fxHGe66Wooatc2PzAdSjz14ZmcQM="


def test_gerar_segredo_totp_e_base32_valido():
    segredo = mfa.gerar_segredo_totp()
    assert len(segredo) >= 16
    # base32 -- RuntimeError/binascii.Error se não for válido.
    pyotp.TOTP(segredo).now()


def test_dois_segredos_gerados_sao_diferentes():
    assert mfa.gerar_segredo_totp() != mfa.gerar_segredo_totp()


def test_cifrar_e_decifrar_segredo_roundtrip():
    segredo = mfa.gerar_segredo_totp()
    cifrado = mfa.cifrar_segredo(segredo, _CHAVE_FERNET)
    assert cifrado != segredo.encode("utf-8")
    assert mfa.decifrar_segredo(cifrado, _CHAVE_FERNET) == segredo


def test_decifrar_com_chave_errada_levanta_invalid_token():
    segredo = mfa.gerar_segredo_totp()
    cifrado = mfa.cifrar_segredo(segredo, _CHAVE_FERNET)
    outra_chave = "aWDXFf3O8kX1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6o="
    with pytest.raises(mfa.InvalidToken):
        mfa.decifrar_segredo(cifrado, outra_chave)


def test_gerar_uri_provisionamento_contem_issuer_e_email():
    segredo = mfa.gerar_segredo_totp()
    uri = mfa.gerar_uri_provisionamento(segredo, "analista@empresa.example.com")
    assert uri.startswith("otpauth://totp/")
    assert "Sentinela" in uri
    assert "analista%40empresa.example.com" in uri or "analista@empresa.example.com" in uri


def test_verificar_codigo_totp_correto_e_aceito():
    segredo = mfa.gerar_segredo_totp()
    codigo_atual = pyotp.TOTP(segredo).now()
    assert mfa.verificar_codigo_totp(segredo, codigo_atual) is True


def test_verificar_codigo_totp_errado_e_recusado():
    segredo = mfa.gerar_segredo_totp()
    assert mfa.verificar_codigo_totp(segredo, "000000") is False


def test_verificar_codigo_totp_de_outro_segredo_e_recusado():
    segredo_a = mfa.gerar_segredo_totp()
    segredo_b = mfa.gerar_segredo_totp()
    codigo_de_b = pyotp.TOTP(segredo_b).now()
    assert mfa.verificar_codigo_totp(segredo_a, codigo_de_b) is False


def test_verificar_codigo_totp_entrada_nao_numerica_e_recusada_sem_excecao():
    segredo = mfa.gerar_segredo_totp()
    assert mfa.verificar_codigo_totp(segredo, "abcdef") is False
    assert mfa.verificar_codigo_totp(segredo, "") is False
    assert mfa.verificar_codigo_totp(segredo, None) is False


def test_verificar_codigo_totp_tolerancia_de_clock_aceita_passo_anterior():
    """JANELA_TOLERANCIA_CLOCK=1 aceita o passo de 30s anterior/seguinte -- simula
    um relógio de cliente levemente atrasado gerando o código de 30s atrás."""
    segredo = mfa.gerar_segredo_totp()
    totp = pyotp.TOTP(segredo)
    codigo_passado = totp.at(int(time.time()) - 30)
    assert mfa.verificar_codigo_totp(segredo, codigo_passado) is True


def test_verificar_codigo_totp_fora_da_janela_e_recusado():
    segredo = mfa.gerar_segredo_totp()
    totp = pyotp.TOTP(segredo)
    codigo_muito_antigo = totp.at(int(time.time()) - 300)  # 10 passos atrás -- bem fora da janela de 1
    assert mfa.verificar_codigo_totp(segredo, codigo_muito_antigo) is False


def test_gerar_recovery_codes_quantidade_e_formato():
    codigos = mfa.gerar_recovery_codes()
    assert len(codigos) == mfa.QUANTIDADE_RECOVERY_CODES
    assert len(set(codigos)) == len(codigos)  # todos únicos
    for codigo in codigos:
        partes = codigo.split("-")
        assert len(partes) == 3
        assert all(len(p) == 4 for p in partes)
        # Sem caracteres ambíguos (0/O, 1/I/L).
        assert not (set(codigo) & set("0O1IL"))


def test_recovery_code_hash_e_verificacao():
    codigo = mfa.gerar_recovery_codes(1)[0]
    hash_ = mfa.hash_recovery_code(codigo)
    assert mfa.verificar_recovery_code(codigo, hash_) is True
    assert mfa.verificar_recovery_code("XXXX-XXXX-XXXX", hash_) is False


def test_recovery_code_verificacao_e_case_insensitive_e_ignora_espacos():
    codigo = mfa.gerar_recovery_codes(1)[0]
    hash_ = mfa.hash_recovery_code(codigo)
    variante = f"  {codigo.lower()}  "
    assert mfa.verificar_recovery_code(variante, hash_) is True
