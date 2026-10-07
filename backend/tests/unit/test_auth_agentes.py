# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testes unitários de auth/agentes.py -- geração/parsing/verificação do token
de longa duração usado pelo Sentinela Endpoint (agente local), sem tocar o
banco (autenticar_agente é coberto em tests/integration/test_agentes_service.py
e tests/api/test_agentes_api.py, que precisam de Postgres real para RLS).

Cobre especificamente o bug que a própria implementação já documenta ter
sido pego e corrigido antes de rodar qualquer teste: `token.split("_")`
sem limite quebrava porque `secrets.token_urlsafe(32)` pode produzir um
segredo contendo "_" -- por isso `extrair_prefixo` usa `split("_", 2)`.
"""
from sentinela.auth.agentes import PREFIXO_TOKEN, TAMANHO_PREFIXO_HEX, extrair_prefixo, gerar_token


def test_gerar_token_tem_o_formato_esperado():
    token, prefixo = gerar_token()
    assert token.startswith(f"{PREFIXO_TOKEN}_")
    assert len(prefixo) == TAMANHO_PREFIXO_HEX
    # o prefixo devolvido por gerar_token() é exatamente o segundo campo do token
    partes = token.split("_", 2)
    assert len(partes) == 3
    assert partes[1] == prefixo


def test_gerar_token_produz_valores_unicos_a_cada_chamada():
    token_a, prefixo_a = gerar_token()
    token_b, prefixo_b = gerar_token()
    assert token_a != token_b
    assert prefixo_a != prefixo_b


def test_extrair_prefixo_de_um_token_valido():
    token, prefixo = gerar_token()
    assert extrair_prefixo(token) == prefixo


def test_extrair_prefixo_tolera_segredo_contendo_underscore():
    """
    O bug real: um segredo gerado por secrets.token_urlsafe(32) que contenha
    "_" faz `token.split("_")` (sem limite) devolver MAIS de 3 partes --
    `split("_", 2)` preserva o segredo inteiro como o terceiro campo,
    underscores e tudo.
    """
    token_forjado = f"{PREFIXO_TOKEN}_{'a' * TAMANHO_PREFIXO_HEX}_segredo_com_varios_underscores_dentro"
    assert extrair_prefixo(token_forjado) == "a" * TAMANHO_PREFIXO_HEX


def test_extrair_prefixo_rejeita_prefixo_de_familia_errada():
    assert extrair_prefixo("sess_abcdef012345_segredoqualquer") is None


def test_extrair_prefixo_rejeita_tamanho_de_prefixo_errado():
    assert extrair_prefixo(f"{PREFIXO_TOKEN}_curto_segredo") is None


def test_extrair_prefixo_rejeita_token_sem_partes_suficientes():
    assert extrair_prefixo(PREFIXO_TOKEN) is None
    assert extrair_prefixo("") is None
    assert extrair_prefixo(f"{PREFIXO_TOKEN}_{'a' * TAMANHO_PREFIXO_HEX}") is None


def test_extrair_prefixo_de_none_nao_estoura_via_autenticar_agente_e_recebe_string_vazia():
    # auth/dependencies.py chama extrair_prefixo(token or "") -- confirma
    # que a própria função também tolera a string vazia diretamente.
    assert extrair_prefixo("") is None
