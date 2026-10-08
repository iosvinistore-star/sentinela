# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Sessão assíncrona da aplicação."""
from sqlalchemy.ext.asyncio import AsyncSession


class Sessao(AsyncSession):
    """
    `AsyncSession` com `populate_existing` por padrão.

    Os repositórios fazem `UPDATE ... RETURNING <Modelo>` e `SELECT`s de
    linhas que a mesma sessão pode já ter carregado. Sem isso o SQLAlchemy
    devolve o objeto que já estava no identity map, com os valores ANTIGOS
    (ex.: uma licença recém-suspensa voltaria como 'ativa'). Aqui a leitura
    do banco sempre vence a memória.
    """

    async def execute(self, statement, params=None, *args, execution_options=None, **kwargs):
        opcoes = {"populate_existing": True, **(execution_options or {})}
        return await super().execute(statement, params, *args, execution_options=opcoes, **kwargs)
