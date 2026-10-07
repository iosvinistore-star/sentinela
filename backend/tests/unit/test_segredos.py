# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testes do provedor de segredos (segredos.py).
"""
import pytest

from sentinela.core import segredos


@pytest.fixture(autouse=True)
def restaurar_provedor_padrao():
    """Garante que cada teste começa e termina com o provedor padrão ativo,
    mesmo que troque o provedor no meio do teste."""
    provedor_original = segredos.obter_provedor()
    yield
    segredos.definir_provedor(provedor_original)


def test_provedor_de_variaveis_de_ambiente_le_do_os_environ(monkeypatch):
    monkeypatch.setenv("MINHA_CHAVE_DE_TESTE", "valor-secreto")
    provedor = segredos.ProvedorDeVariaveisDeAmbiente()
    assert provedor.obter("MINHA_CHAVE_DE_TESTE") == "valor-secreto"


def test_provedor_de_variaveis_de_ambiente_usa_padrao_quando_ausente(monkeypatch):
    monkeypatch.delenv("CHAVE_INEXISTENTE_XYZ", raising=False)
    provedor = segredos.ProvedorDeVariaveisDeAmbiente()
    assert provedor.obter("CHAVE_INEXISTENTE_XYZ", "padrao") == "padrao"
    assert provedor.obter("CHAVE_INEXISTENTE_XYZ") is None


def test_obter_segredo_usa_o_provedor_ativo(monkeypatch):
    monkeypatch.setenv("OUTRA_CHAVE_DE_TESTE", "outro-valor")
    assert segredos.obter_segredo("OUTRA_CHAVE_DE_TESTE") == "outro-valor"


def test_definir_provedor_troca_a_fonte_dos_segredos():
    class ProvedorFalso(segredos.ProvedorDeSegredos):
        def obter(self, nome, padrao=None):
            return f"falso:{nome}"

    segredos.definir_provedor(ProvedorFalso())
    assert segredos.obter_segredo("QUALQUER_CHAVE") == "falso:QUALQUER_CHAVE"


def test_definir_provedor_rejeita_objeto_que_nao_implementa_a_interface():
    with pytest.raises(TypeError):
        segredos.definir_provedor(object())


def test_obter_provedor_devolve_o_provedor_atualmente_ativo():
    class ProvedorFalso(segredos.ProvedorDeSegredos):
        def obter(self, nome, padrao=None):
            return None

    novo_provedor = ProvedorFalso()
    segredos.definir_provedor(novo_provedor)
    assert segredos.obter_provedor() is novo_provedor
