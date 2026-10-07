# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testes unitários de auth/enrollment.py -- geração/parsing do token de
ENROLLMENT (Fase D / D3), sem tocar o banco (autenticar_enrollment é
coberto em tests/integration/test_enrollment_service.py e
tests/api/test_enrollment_api.py, que precisam de Postgres real para RLS).

Espelha tests/unit/test_auth_licencas.py/test_auth_agentes.py -- mesma
família de bug já corrigida na implementação original (segredo de
secrets.token_urlsafe podendo conter "_", exigindo split(_, 2) em vez de
split(_) sem limite).
"""
from sentinela.auth.enrollment import PREFIXO_TOKEN, TAMANHO_PREFIXO_HEX, extrair_prefixo, gerar_token


def test_gerar_token_tem_o_formato_esperado():
    token, prefixo = gerar_token()
    assert token.startswith(f"{PREFIXO_TOKEN}_")
    assert len(prefixo) == TAMANHO_PREFIXO_HEX
    partes = token.split("_", 2)
    assert len(partes) == 3
    assert partes[1] == prefixo


def test_gerar_token_produz_valores_unicos_a_cada_chamada():
    token_a, prefixo_a = gerar_token()
    token_b, prefixo_b = gerar_token()
    assert token_a != token_b
    assert prefixo_a != prefixo_b


def test_prefixo_de_enrollment_nunca_colide_com_agente_ou_licenca():
    """Família de token própria ("enr") -- nunca compartilha prefixo com
    auth/agentes.py ("agt") nem auth/licencas.py ("lic")."""
    from sentinela.auth.agentes import PREFIXO_TOKEN as PREFIXO_AGENTE
    from sentinela.auth.licencas import PREFIXO_TOKEN as PREFIXO_LICENCA
    assert PREFIXO_TOKEN not in (PREFIXO_AGENTE, PREFIXO_LICENCA)
    assert PREFIXO_TOKEN == "enr"


def test_extrair_prefixo_de_um_token_valido():
    token, prefixo = gerar_token()
    assert extrair_prefixo(token) == prefixo


def test_extrair_prefixo_tolera_segredo_contendo_underscore():
    token_forjado = f"{PREFIXO_TOKEN}_{'a' * TAMANHO_PREFIXO_HEX}_segredo_com_varios_underscores_dentro"
    assert extrair_prefixo(token_forjado) == "a" * TAMANHO_PREFIXO_HEX


def test_extrair_prefixo_rejeita_prefixo_de_familia_errada():
    assert extrair_prefixo("agt_abcdef012345_segredoqualquer") is None


def test_extrair_prefixo_rejeita_tamanho_de_prefixo_errado():
    assert extrair_prefixo(f"{PREFIXO_TOKEN}_curto_segredo") is None


def test_extrair_prefixo_rejeita_token_sem_partes_suficientes():
    assert extrair_prefixo(PREFIXO_TOKEN) is None
    assert extrair_prefixo("") is None
    assert extrair_prefixo(f"{PREFIXO_TOKEN}_{'a' * TAMANHO_PREFIXO_HEX}") is None
