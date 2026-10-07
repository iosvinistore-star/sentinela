# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Interface de provedor de segredos.

Por trás desta interface, hoje só existe uma implementação: leitura direta
de variáveis de ambiente (ProvedorDeVariaveisDeAmbiente). O resto do código
(reputacao.py, dashboard.py) depende só da interface ProvedorDeSegredos —
nunca de os.environ diretamente — para que, no futuro, trocar para Vault,
AWS Secrets Manager, Azure Key Vault ou qualquer outro backend seja questão
de escrever uma nova classe aqui e chamar `definir_provedor(...)`, sem tocar
em mais nada no projeto.
"""
from abc import ABC, abstractmethod
import os


class ProvedorDeSegredos(ABC):
    """Contrato que qualquer fonte de segredos precisa implementar."""

    @abstractmethod
    def obter(self, nome, padrao=None):
        """Devolve o valor do segredo `nome`, ou `padrao` se não existir."""
        raise NotImplementedError


class ProvedorDeVariaveisDeAmbiente(ProvedorDeSegredos):
    """
    Implementação padrão (e única, por enquanto): lê diretamente do
    ambiente do processo. É o comportamento que o projeto já tinha antes
    desta interface existir — nada muda para quem já configura
    ABUSEIPDB_API_KEY, VT_API_KEY, DASHBOARD_SENHA etc. como variável de
    ambiente.
    """

    def obter(self, nome, padrao=None):
        return os.environ.get(nome, padrao)


# Provedor ativo do processo. Trocável em runtime via definir_provedor() —
# útil tanto para uma futura integração com um cofre de segredos quanto
# para isolar testes.
_provedor_ativo = ProvedorDeVariaveisDeAmbiente()


def obter_provedor():
    """Devolve o provedor de segredos atualmente ativo."""
    return _provedor_ativo


def definir_provedor(provedor):
    """Troca o provedor de segredos ativo para todo o processo."""
    global _provedor_ativo
    if not isinstance(provedor, ProvedorDeSegredos):
        raise TypeError("provedor precisa implementar ProvedorDeSegredos")
    _provedor_ativo = provedor


def obter_segredo(nome, padrao=None):
    """Atalho conveniente: obter_segredo('VT_API_KEY')."""
    return _provedor_ativo.obter(nome, padrao)
