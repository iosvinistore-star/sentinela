# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
SQL cru para SETUP e INSPEÇÃO nos testes (inserir fixtures, conferir o que ficou gravado, limpar).

O código da aplicação NÃO usa SQL cru: fala com o banco só por repositórios/ORM. Os testes, às vezes, precisam
olhar o banco "por fora" da camada que estão testando -- é para isso que serve este módulo. Aceita a notação
`$1, $2::tipo` do asyncpg para manter as asserções existentes legíveis.
"""
import json
import re

from sqlalchemy import text

_PARAM = re.compile(r"\$(\d+)(?:::([\w\[\]]+))?")
_DOIS_PONTOS_SOLTO = re.compile(r"(?<![:\\]):(?=\w)")
_OIDS_JSON = {114, 3802}


def _traduzir(sql, args):
    def troca(m):
        n, tipo = m.group(1), m.group(2)
        return f"CAST(:p{n} AS {tipo})" if tipo else f":p{n}"

    sql = _DOIS_PONTOS_SOLTO.sub(r"\\:", sql)
    return text(_PARAM.sub(troca, sql)), {f"p{i}": v for i, v in enumerate(args, 1)}


class Linha(dict):
    """Linha como dict."""


def _linhas(resultado):
    colunas_json = {d[0] for d in resultado.cursor.description if d[1] in _OIDS_JSON}
    linhas = [Linha(r._mapping) for r in resultado.all()]
    for linha in linhas:
        for c in colunas_json:
            if linha[c] is not None and not isinstance(linha[c], str):
                linha[c] = json.dumps(linha[c])  # jsonb "cru", como o asyncpg devolveria
    return linhas


async def buscar(sessao, sql, *args):
    stmt, params = _traduzir(sql, args)
    return _linhas(await sessao.execute(stmt, params))


async def buscar_um(sessao, sql, *args):
    linhas = await buscar(sessao, sql, *args)
    return linhas[0] if linhas else None


async def valor(sessao, sql, *args):
    stmt, params = _traduzir(sql, args)
    return (await sessao.execute(stmt, params)).scalar()


async def executar(sessao, sql, *args):
    stmt, params = _traduzir(sql, args)
    resultado = await sessao.execute(stmt, params)
    return resultado.rowcount
