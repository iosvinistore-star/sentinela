# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Os modelos ORM (sentinela/models) espelham o schema criado pelas migrations SQL; este teste garante que os dois
não divergem: toda tabela/coluna de modelo existe no banco real, com a mesma nulabilidade e chave primária.
"""
import pytest
from sqlalchemy import inspect

import sentinela.models  # noqa: F401  (registra as tabelas em Base.metadata)
from sentinela.database.base import Base

pytestmark = pytest.mark.integration


def _comparar(conexao_sincrona):
    inspetor = inspect(conexao_sincrona)
    problemas = []
    tabelas_no_banco = set(inspetor.get_table_names())
    for nome, tabela in Base.metadata.tables.items():
        if nome not in tabelas_no_banco:
            problemas.append(f"tabela {nome} não existe no banco")
            continue
        colunas_banco = {c["name"]: c for c in inspetor.get_columns(nome)}
        pk_banco = set(inspetor.get_pk_constraint(nome)["constrained_columns"])
        for coluna in tabela.columns:
            real = colunas_banco.get(coluna.name)
            if real is None:
                problemas.append(f"{nome}.{coluna.name}: coluna não existe no banco")
                continue
            if coluna.nullable != real["nullable"] and coluna.name not in pk_banco:
                problemas.append(f"{nome}.{coluna.name}: nullable do modelo={coluna.nullable}, do banco={real['nullable']}")
        pk_modelo = {c.name for c in tabela.primary_key.columns}
        if pk_modelo != pk_banco:
            problemas.append(f"{nome}: PK do modelo={sorted(pk_modelo)}, do banco={sorted(pk_banco)}")
    return problemas


async def test_modelos_espelham_o_schema_das_migrations(db_admin):
    async with db_admin.engine.connect() as conexao:
        problemas = await conexao.run_sync(_comparar)
    assert problemas == []


async def test_colunas_do_banco_cobertas_pelos_modelos(db_admin):
    """O inverso: coluna que existe no banco para uma tabela mapeada precisa estar no modelo."""

    def _faltando(conexao_sincrona):
        inspetor = inspect(conexao_sincrona)
        ausentes = []
        for nome, tabela in Base.metadata.tables.items():
            nomes_modelo = {c.name for c in tabela.columns}
            for c in inspetor.get_columns(nome):
                if c["name"] not in nomes_modelo:
                    ausentes.append(f"{nome}.{c['name']}")
        return ausentes

    async with db_admin.engine.connect() as conexao:
        assert await conexao.run_sync(_faltando) == []
