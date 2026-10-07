# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Avaliador Sigma -- subconjunto documentado e testado do padrão Sigma.

Por que reescrito na V8.2: o avaliador anterior (a) ignorava qualquer
condição diferente de ``selection``/``not ...`` -- ``selection and not
filter`` virava só ``selection``, ou seja, o filtro de exclusão era
descartado em silêncio e a regra disparava em mais eventos do que devia;
(b) não entendia modificadores (``CommandLine|contains``), então a chave
literal "CommandLine|contains" era procurada no evento e a regra nunca
casava; (c) não mapeava nomes de campo Sigma (``EventID``,
``TargetUserName``...) para o esquema normalizado do SIEM; (d) comparava
``logsource.product`` por substring do ``source_type`` (``linux`` nunca
casava com ``unix_log``).

Suportado (e coberto por testes em tests/unit/test_sigma.py):

* ``detection`` com identificadores de busca arbitrários (``selection``,
  ``filter_*``, ``keywords``...). Cada identificador é um mapa (AND entre
  campos), uma lista de mapas (OR) ou uma lista de strings (busca por
  palavra-chave em ``message``/``raw_event``).
* ``condition`` com ``and``/``or``/``not``, parênteses, ``1 of padrao*``,
  ``all of padrao*``, ``1 of them``, ``all of them``. Uma lista de
  condições é tratada como OR (comportamento do padrão).
* Modificadores: ``contains``, ``startswith``, ``endswith``, ``all``,
  ``re``, ``cidr``, ``exists``.
* Curingas ``*`` e ``?`` em qualquer posição, com escape ``\\*``/``\\?``;
  comparação sem diferenciar maiúsculas/minúsculas (padrão Sigma).
* ``campo: null`` casa quando o campo está ausente ou vazio.

Não suportado (a regra é REJEITADA na criação, nunca ignorada em silêncio):
agregações (``| count() by ...``), ``near``, modificadores de codificação
(``base64``, ``base64offset``, ``utf16le``, ``wide``, ``windash``) e
correlações Sigma v2. Isso fica explícito na API (422) para que a matriz
técnica do edital não prometa mais do que o motor faz.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Callable

__all__ = ["SigmaErro", "RegraCompilada", "compilar_regra", "avaliar_sigma"]


class SigmaErro(ValueError):
    """Regra Sigma inválida ou usa recurso não suportado por este motor."""


# Nome de campo Sigma (comparado em minúsculas) -> campo normalizado do SIEM.
MAPA_CAMPOS: dict[str, str] = {
    "eventid": "event_type",
    "event_id": "event_type",
    "eventtype": "event_type",
    "user": "username",
    "username": "username",
    "targetusername": "username",
    "subjectusername": "username",
    "accountname": "username",
    "ipaddress": "source_ip",
    "sourceip": "source_ip",
    "src_ip": "source_ip",
    "sourceaddress": "source_ip",
    "clientip": "source_ip",
    "destinationip": "destination_ip",
    "dst_ip": "destination_ip",
    "destinationaddress": "destination_ip",
    "sourceport": "source_port",
    "src_port": "source_port",
    "ipport": "source_port",
    "destinationport": "destination_port",
    "dst_port": "destination_port",
    "computer": "hostname",
    "computername": "hostname",
    "hostname": "hostname",
    "host": "hostname",
    "workstationname": "hostname",
    "protocol": "protocol",
    "action": "action",
    "severity": "severity",
    "level": "severity",
    "message": "message",
    "msg": "message",
    "raw": "raw_event",
    "raw_event": "raw_event",
    "source": "source",
    "source_type": "source_type",
}

# logsource.product -> source_types normalizados que representam o produto.
MAPA_PRODUTOS: dict[str, set[str]] = {
    "windows": {"windows_event_log", "windows", "wineventlog"},
    "linux": {"unix_log", "linux", "syslog", "auditd"},
    "unix": {"unix_log", "syslog"},
    "network": {"netflow", "ipfix", "snmp", "snmp_trap", "firewall"},
    "netflow": {"netflow", "ipfix"},
    "snmp": {"snmp", "snmp_trap"},
}

MODIFICADORES_SUPORTADOS = {"contains", "startswith", "endswith", "all", "re", "cidr", "exists"}
MODIFICADORES_REJEITADOS = {"base64", "base64offset", "utf16le", "utf16be", "utf16", "wide", "windash", "expand", "fieldref", "gt", "gte", "lt", "lte"}

_MAX_REGEX = 512
_MAX_VALORES = 500


@dataclass(frozen=True)
class RegraCompilada:
    produtos: frozenset[str] | None
    predicado: Callable[[dict[str, Any]], bool]

    def casa(self, evento: dict[str, Any]) -> bool:
        if self.produtos is not None:
            st = str(evento.get("source_type") or "").lower()
            if st not in self.produtos:
                return False
        return self.predicado(evento)


# --------------------------------------------------------------------------
# Valores
# --------------------------------------------------------------------------

def _curinga_para_regex(valor: str) -> re.Pattern[str]:
    partes: list[str] = []
    i = 0
    while i < len(valor):
        c = valor[i]
        if c == "\\" and i + 1 < len(valor) and valor[i + 1] in "*?\\":
            partes.append(re.escape(valor[i + 1]))
            i += 2
            continue
        if c == "*":
            partes.append(".*")
        elif c == "?":
            partes.append(".")
        else:
            partes.append(re.escape(c))
        i += 1
    return re.compile("^" + "".join(partes) + "$", re.IGNORECASE | re.DOTALL)


def _tem_curinga(valor: str) -> bool:
    return re.search(r"(?<!\\)[*?]", valor) is not None


def _escapar_curinga(valor: str) -> str:
    return valor.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")


def _compilar_valor(valor: Any, modificadores: list[str]) -> Callable[[Any], bool]:
    if valor is None:
        return lambda atual: atual is None or str(atual) == ""

    if "exists" in modificadores:
        esperado = bool(valor) if not isinstance(valor, str) else valor.lower() == "true"
        return lambda atual: (atual is not None and str(atual) != "") == esperado

    if "re" in modificadores:
        padrao = str(valor)
        if len(padrao) > _MAX_REGEX:
            raise SigmaErro(f"regex maior que {_MAX_REGEX} caracteres")
        try:
            rx = re.compile(padrao)
        except re.error as exc:
            raise SigmaErro(f"regex inválida: {exc}") from exc
        return lambda atual: atual is not None and rx.search(str(atual)) is not None

    if "cidr" in modificadores:
        try:
            rede = ipaddress.ip_network(str(valor), strict=False)
        except ValueError as exc:
            raise SigmaErro(f"CIDR inválido: {valor}") from exc

        def _cidr(atual: Any) -> bool:
            if atual is None:
                return False
            try:
                return ipaddress.ip_address(str(atual)) in rede
            except ValueError:
                return False
        return _cidr

    texto = str(valor).lower() if isinstance(valor, bool) else str(valor)
    if "contains" in modificadores:
        texto = f"*{_escapar_curinga(texto)}*" if not _tem_curinga(texto) else f"*{texto}*"
    elif "startswith" in modificadores:
        texto = f"{_escapar_curinga(texto)}*" if not _tem_curinga(texto) else f"{texto}*"
    elif "endswith" in modificadores:
        texto = f"*{_escapar_curinga(texto)}" if not _tem_curinga(texto) else f"*{texto}"

    if _tem_curinga(texto):
        rx = _curinga_para_regex(texto)
        return lambda atual: atual is not None and rx.match(str(atual)) is not None
    literal = texto.replace("\\*", "*").replace("\\?", "?").lower()
    return lambda atual: atual is not None and str(atual).lower() == literal


def _valor_do_evento(evento: dict[str, Any], campo: str) -> Any:
    if campo in evento:
        return evento[campo]
    normalizado = MAPA_CAMPOS.get(campo.lower())
    if normalizado is not None:
        return evento.get(normalizado)
    # Campos extras que o Agent/parsers anexam (ex.: evento["campos"]["LogonType"]).
    extras = evento.get("campos")
    if isinstance(extras, dict):
        for k, v in extras.items():
            if k.lower() == campo.lower():
                return v
    return None


def _compilar_campo(chave: str, valor: Any) -> Callable[[dict[str, Any]], bool]:
    partes = chave.split("|")
    campo, modificadores = partes[0], [m.lower() for m in partes[1:]]
    for m in modificadores:
        if m in MODIFICADORES_REJEITADOS or m not in MODIFICADORES_SUPORTADOS:
            raise SigmaErro(f"modificador Sigma não suportado: |{m}")
    if not campo:
        raise SigmaErro("campo vazio na seleção")
    valores = valor if isinstance(valor, list) else [valor]
    if len(valores) > _MAX_VALORES:
        raise SigmaErro(f"mais de {_MAX_VALORES} valores em {campo}")
    comparadores = [_compilar_valor(v, modificadores) for v in valores]
    exigir_todos = "all" in modificadores

    def _pred(evento: dict[str, Any]) -> bool:
        atual = _valor_do_evento(evento, campo)
        if exigir_todos:
            return all(c(atual) for c in comparadores)
        return any(c(atual) for c in comparadores)
    return _pred


def _compilar_busca(nome: str, definicao: Any) -> Callable[[dict[str, Any]], bool]:
    if isinstance(definicao, dict):
        if not definicao:
            raise SigmaErro(f"identificador '{nome}' vazio")
        preds = [_compilar_campo(k, v) for k, v in definicao.items()]
        return lambda ev: all(p(ev) for p in preds)
    if isinstance(definicao, list):
        if not definicao:
            raise SigmaErro(f"identificador '{nome}' vazio")
        if all(isinstance(x, dict) for x in definicao):
            alternativas = [_compilar_busca(nome, x) for x in definicao]
            return lambda ev: any(a(ev) for a in alternativas)
        if all(isinstance(x, (str, int)) for x in definicao):
            palavras = [_compilar_valor(f"*{x}*" if not _tem_curinga(str(x)) else str(x), []) for x in definicao]

            def _keywords(ev: dict[str, Any]) -> bool:
                alvo = f"{ev.get('message') or ''}\n{ev.get('raw_event') or ''}"
                return any(p(alvo) for p in palavras)
            return _keywords
    if isinstance(definicao, (str, int)):
        return _compilar_busca(nome, [definicao])
    raise SigmaErro(f"formato não suportado no identificador '{nome}'")


# --------------------------------------------------------------------------
# Condição
# --------------------------------------------------------------------------

_TOKEN_RX = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*.\-]+|\|)")


def _tokenizar(condicao: str) -> list[str]:
    tokens: list[str] = []
    pos = 0
    condicao = condicao.strip()
    # Checado ANTES de tokenizar: "sel | count() by User > 5" falharia no
    # '>' com uma mensagem genérica, e o usuário precisa saber o motivo real.
    if "|" in condicao:
        raise SigmaErro("agregações Sigma ('| count() ...') não são suportadas")
    while pos < len(condicao):
        m = _TOKEN_RX.match(condicao, pos)
        if not m or m.end() == pos:
            raise SigmaErro(f"condição inválida perto de: {condicao[pos:pos + 20]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    if "|" in tokens:
        raise SigmaErro("agregações Sigma ('| count() ...') não são suportadas")
    return tokens


class _Parser:
    def __init__(self, tokens: list[str], buscas: dict[str, Callable[[dict[str, Any]], bool]]):
        self.t = tokens
        self.i = 0
        self.buscas = buscas

    def _peek(self) -> str | None:
        return self.t[self.i] if self.i < len(self.t) else None

    def _next(self) -> str:
        if self.i >= len(self.t):
            raise SigmaErro("condição terminou inesperadamente")
        tok = self.t[self.i]
        self.i += 1
        return tok

    def parse(self) -> Callable[[dict[str, Any]], bool]:
        expr = self._or()
        if self._peek() is not None:
            raise SigmaErro(f"token inesperado na condição: {self._peek()!r}")
        return expr

    def _or(self):
        esquerda = self._and()
        while (self._peek() or "").lower() == "or":
            self._next()
            direita = self._and()
            esquerda = (lambda a, b: lambda ev: a(ev) or b(ev))(esquerda, direita)
        return esquerda

    def _and(self):
        esquerda = self._not()
        while (self._peek() or "").lower() == "and":
            self._next()
            direita = self._not()
            esquerda = (lambda a, b: lambda ev: a(ev) and b(ev))(esquerda, direita)
        return esquerda

    def _not(self):
        if (self._peek() or "").lower() == "not":
            self._next()
            inner = self._not()
            return lambda ev: not inner(ev)
        return self._atomo()

    def _selecionar(self, padrao: str) -> list[Callable[[dict[str, Any]], bool]]:
        if padrao.lower() == "them":
            nomes = list(self.buscas)
        else:
            rx = _curinga_para_regex(padrao)
            nomes = [n for n in self.buscas if rx.match(n)]
        if not nomes:
            raise SigmaErro(f"nenhum identificador casa com '{padrao}'")
        return [self.buscas[n] for n in nomes]

    def _atomo(self):
        tok = self._next()
        if tok == "(":
            expr = self._or()
            if self._next() != ")":
                raise SigmaErro("parêntese não fechado")
            return expr
        baixo = tok.lower()
        if baixo in {"1", "all", "any"} and (self._peek() or "").lower() == "of":
            self._next()
            alvos = self._selecionar(self._next())
            if baixo == "all":
                return lambda ev: all(a(ev) for a in alvos)
            return lambda ev: any(a(ev) for a in alvos)
        if baixo in {"and", "or", "not", ")", "of"}:
            raise SigmaErro(f"token inesperado: {tok!r}")
        if tok not in self.buscas:
            raise SigmaErro(f"identificador '{tok}' não existe em detection")
        return self.buscas[tok]


def compilar_regra(regra: dict[str, Any]) -> RegraCompilada:
    """Compila uma regra (dict com ``logsource``/``detection``). Levanta SigmaErro."""
    logsource = regra.get("logsource") or {}
    if not isinstance(logsource, dict):
        raise SigmaErro("logsource deve ser um objeto")
    produtos: frozenset[str] | None = None
    produto = logsource.get("product")
    if produto:
        p = str(produto).lower()
        produtos = frozenset(MAPA_PRODUTOS.get(p, {p}))

    detection = regra.get("detection") or {}
    if not isinstance(detection, dict) or not detection:
        raise SigmaErro("detection vazio")
    condicao = detection.get("condition", "selection")
    buscas = {nome: _compilar_busca(nome, d) for nome, d in detection.items() if nome not in {"condition", "timeframe"}}
    if "timeframe" in detection:
        raise SigmaErro("timeframe/agregação não suportado")
    if not buscas:
        raise SigmaErro("detection sem identificadores de busca")

    condicoes = condicao if isinstance(condicao, list) else [condicao]
    preds = [_Parser(_tokenizar(str(c)), buscas).parse() for c in condicoes]
    predicado = preds[0] if len(preds) == 1 else (lambda ev: any(p(ev) for p in preds))
    return RegraCompilada(produtos=produtos, predicado=predicado)


def avaliar_sigma(regra: dict[str, Any], evento: dict[str, Any]) -> bool:
    """Compatibilidade: compila e avalia. Regra inválida nunca casa."""
    try:
        return compilar_regra(regra).casa(evento)
    except SigmaErro:
        return False
