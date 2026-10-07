# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM

from sentinela.auth.security import gerar_refresh_token, hash_refresh_token

def test_refresh_token_is_opaque_and_high_entropy():
    a, b = gerar_refresh_token(), gerar_refresh_token()
    assert a != b
    assert len(a) >= 60
    assert hash_refresh_token(a) != hash_refresh_token(b)

def test_refresh_hash_is_deterministic():
    token = gerar_refresh_token()
    assert hash_refresh_token(token) == hash_refresh_token(token)
