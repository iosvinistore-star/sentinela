# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
TRANSITÓRIO -- ponte de compatibilidade com a API do asyncpg.

Permite que o código ainda não migrado para o ORM (`conn.fetchrow("... $1",
x)`) continue funcionando em cima de uma `AsyncSession`, enquanto cada módulo
é convertido para repositórios/ORM. Será REMOVIDO quando o último chamador for
convertido (ver grep por .fetchrow( e .fetchval( em sentinela/).
"""
import json
import re
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

_PARAM = re.compile(r"\$(\d+)(?:::([\w\[\]]+))?")
# ":algo" solto (dentro de literais, ex. '{"a":1}') não pode virar bind do SQLAlchemy.
_DOIS_PONTOS_SOLTO = re.compile(r"(?<![:\\]):(?=\w)")


def _traduzir(sql: str, args: tuple) -> tuple:
    def troca(m):
        n, tipo = m.group(1), m.group(2)
        return f"CAST(:p{n} AS {tipo})" if tipo else f":p{n}"

    sql = _DOIS_PONTOS_SOLTO.sub(r"\\:", sql)
    return text(_PARAM.sub(troca, sql)), {f"p{i}": v for i, v in enumerate(args, 1)}


_OIDS_JSON = {114, 3802}  # json, jsonb: o asyncpg cru devolvia str; o SQLAlchemy decodifica.


def _registros(resultado) -> list:
    colunas_json = {d[0] for d in resultado.cursor.description if d[1] in _OIDS_JSON}
    linhas = [Registro(r._mapping) for r in resultado.all()]
    for linha in linhas:
        for c in colunas_json:
            if linha[c] is not None and not isinstance(linha[c], str):
                linha[c] = json.dumps(linha[c])
    return linhas


class Registro(dict):
    """Linha como dict (imita o `asyncpg.Record` no uso real do código)."""


class SessaoComCompat(AsyncSession):
    async def execute(self, statement, *args, **kwargs):
        if isinstance(statement, str):
            stmt, params = _traduzir(statement, args)
            resultado = await super().execute(stmt, params)
            if resultado.returns_rows:
                return resultado
            return f"{statement.split(None, 1)[0].upper()} {resultado.rowcount}"
        return await super().execute(statement, *args, **kwargs)

    async def _linhas(self, sql, args):
        stmt, params = _traduzir(sql, args)
        resultado = await super().execute(stmt, params)
        return _registros(resultado)

    async def fetch(self, sql, *args):
        return await self._linhas(sql, args)

    async def fetchrow(self, sql, *args):
        linhas = await self._linhas(sql, args)
        return linhas[0] if linhas else None

    async def fetchval(self, sql, *args):
        stmt, params = _traduzir(sql, args)
        return (await super().execute(stmt, params)).scalar()

    async def executemany(self, sql, lista):
        for args in lista:
            await self.execute(sql, *args)

    @asynccontextmanager
    async def transaction(self):
        async with self.begin_nested():
            yield
