# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Base declarativa de todos os modelos ORM.

O schema é de propriedade das migrations SQL (db/migrations): os modelos o
espelham, não o criam. tests/integration/test_models_schema.py garante que não
divirjam.
"""

import ipaddress
from typing import Any, ClassVar

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    # Colunas que NUNCA saem em `para_dict()` (hashes, segredos cifrados).
    # Quem realmente precisa delas lê o atributo do modelo, explicitamente.
    _sensiveis: ClassVar[frozenset[str]] = frozenset()

    def para_dict(self) -> dict[str, Any]:
        """
        Linha -> dict simples (colunas apenas, sem relacionamentos).

        `inet` vira str: o driver devolve `ipaddress` objects, que nem o JSON
        nem os templates sabem serializar. UUIDs permanecem `uuid.UUID` --
        cada chamador converte quando o contrato da API pede string. Colunas
        em `_sensiveis` são omitidas.
        """
        dados = {}
        for coluna in self.__table__.columns:
            if coluna.key in self._sensiveis:
                continue
            valor = getattr(self, coluna.key)
            if isinstance(valor, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                valor = str(valor)
            dados[coluna.key] = valor
        return dados
