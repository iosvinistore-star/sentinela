# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Cache de verificação de token (auth/cache_token.py): só sucesso é lembrado e o hash do banco manda."""
import pytest

from sentinela.auth import cache_token as modulo
from sentinela.auth.cache_token import CacheVerificacaoToken
from sentinela.auth.security import hash_senha

TOKEN = "agt_aaaaaaaaaaaa_segredo-de-teste"


@pytest.fixture
def hash_bom():
    return hash_senha(TOKEN)


@pytest.fixture
def chamadas(monkeypatch):
    """Conta quantas vezes o bcrypt de verdade foi chamado."""
    contador = {"n": 0}
    original = modulo.verificar_senha

    def espiao(senha, hash_):
        contador["n"] += 1
        return original(senha, hash_)

    monkeypatch.setattr(modulo, "verificar_senha", espiao)
    return contador


@pytest.mark.asyncio
async def test_segunda_verificacao_do_mesmo_token_nao_roda_bcrypt(hash_bom, chamadas):
    cache = CacheVerificacaoToken()
    assert await cache.verificar(TOKEN, hash_bom) is True
    assert await cache.verificar(TOKEN, hash_bom) is True
    assert await cache.verificar(TOKEN, hash_bom) is True
    assert chamadas["n"] == 1
    assert (cache.acertos, cache.erros) == (2, 1)


@pytest.mark.asyncio
async def test_falha_nunca_e_cacheada(hash_bom, chamadas):
    cache = CacheVerificacaoToken()
    for _ in range(3):
        assert await cache.verificar("agt_aaaaaaaaaaaa_token-errado", hash_bom) is False
    assert chamadas["n"] == 3  # o caminho caro continua valendo para quem erra


@pytest.mark.asyncio
async def test_hash_trocado_no_banco_invalida_o_cache(hash_bom, chamadas):
    """Token reemitido: o hash no banco mudou, então o que foi verificado antes não vale mais."""
    cache = CacheVerificacaoToken()
    assert await cache.verificar(TOKEN, hash_bom) is True
    outro_hash = hash_senha("agt_aaaaaaaaaaaa_outro-segredo")
    assert await cache.verificar(TOKEN, outro_hash) is False
    assert chamadas["n"] == 2
    # e o cache não ficou "envenenado": com o hash antigo de volta, verifica de novo e passa
    assert await cache.verificar(TOKEN, hash_bom) is True


@pytest.mark.asyncio
async def test_expira_apos_o_ttl(hash_bom, chamadas):
    agora = {"t": 1000.0}
    cache = CacheVerificacaoToken(ttl_segundos=60, relogio=lambda: agora["t"])
    assert await cache.verificar(TOKEN, hash_bom) is True
    agora["t"] += 59
    assert await cache.verificar(TOKEN, hash_bom) is True
    assert chamadas["n"] == 1
    agora["t"] += 2
    assert await cache.verificar(TOKEN, hash_bom) is True
    assert chamadas["n"] == 2


@pytest.mark.asyncio
async def test_tamanho_e_limitado_descartando_o_menos_usado(chamadas):
    cache = CacheVerificacaoToken(max_entradas=2)
    tokens = [f"agt_aaaaaaaaaaaa_t{i}" for i in range(3)]
    hashes = [hash_senha(t) for t in tokens]
    for t, h in zip(tokens, hashes):
        assert await cache.verificar(t, h) is True
    assert len(cache._entradas) == 2
    antes = chamadas["n"]
    assert await cache.verificar(tokens[0], hashes[0]) is True  # o mais antigo foi descartado
    assert chamadas["n"] == antes + 1


@pytest.mark.asyncio
async def test_desligado_com_zero_entradas(hash_bom, chamadas):
    cache = CacheVerificacaoToken(max_entradas=0)
    assert await cache.verificar(TOKEN, hash_bom) is True
    assert await cache.verificar(TOKEN, hash_bom) is True
    assert chamadas["n"] == 2
    assert len(cache._entradas) == 0


@pytest.mark.asyncio
async def test_token_nao_fica_em_memoria_em_claro(hash_bom):
    cache = CacheVerificacaoToken()
    await cache.verificar(TOKEN, hash_bom)
    assert TOKEN not in cache._entradas
    assert all(TOKEN not in str(v) for v in cache._entradas.values())


@pytest.mark.asyncio
async def test_hash_rapido_nao_usa_bcrypt_nem_cache(chamadas):
    from sentinela.auth.security import hash_token

    cache = CacheVerificacaoToken()
    h = hash_token(TOKEN)
    assert h.startswith("sha256$") and TOKEN not in h
    assert await cache.verificar(TOKEN, h) is True
    assert await cache.verificar("agt_aaaaaaaaaaaa_errado", h) is False
    assert chamadas["n"] == 0 and len(cache._entradas) == 0
