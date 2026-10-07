# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Configuração central de logging estruturado (Fase E / E2) -- ver
ARQUITETURA_OBSERVABILIDADE.md §1 para o desenho completo, escrito ANTES
deste código.

Decisão: formatter JSON escrito à mão (stdlib `logging`+`json`), não uma
biblioteca de terceiros (`python-json-logger`/`structlog`) -- o formato
necessário aqui (uma linha JSON por evento, com um punhado de campos fixos
mais o contexto de correlação de `core/log_context.py`) é simples o
bastante para não justificar mais uma dependência de supply chain, mesmo
raciocínio já aplicado ao HKDF do Sentinela Agent em Go
(`ARQUITETURA_LICENCIAMENTO.md` §13).
"""
import json
import logging
import logging.config
import traceback
from datetime import datetime, timezone

from sentinela.core.log_context import obter_contexto
from sentinela.core.redacao import mascarar_dados, mascarar_texto

FORMATOS_VALIDOS = ("json", "texto")

# Conjunto de atributos que TODO `logging.LogRecord` já tem por padrão --
# calculado a partir de uma instância de referência (em vez de listado à
# mão) para não depender de manter esta lista em sincronia manualmente a
# cada versão nova do Python que adicione um atributo (ex.: `taskName`,
# adicionado no 3.12). Usado para separar "campos extras" (passados via
# `logger.info(..., extra={...})`) do resto do registro.
_LOGRECORD_REFERENCIA = logging.LogRecord("", 0, "", 0, "", (), None)
_CAMPOS_PADRAO_LOGRECORD = set(_LOGRECORD_REFERENCIA.__dict__.keys()) | {"message", "asctime"}


class FormatadorJSON(logging.Formatter):
    """
    Uma linha JSON por evento de log -- `timestamp` (UTC, ISO 8601,
    milissegundos), `level`, `logger`, `message`, mais:
      - todo o contexto de correlação da requisição atual (`request_id`,
        `empresa_id`, etc. -- ver `core/log_context.py`);
      - `exception` (traceback completo) quando o log foi emitido dentro
        de um `except`/`logger.exception(...)`;
      - qualquer campo extra passado via `logger.info(..., extra={...})`.

    `message` passa por `mascarar_texto` e os campos extras/contexto por
    `mascarar_dados` (ver `core/redacao.py`) -- defesa em profundidade
    contra um valor sensível (token, senha) acabar interpolado numa
    mensagem de log ou num `extra=` por engano em algum lugar do código,
    hoje ou no futuro (ver ARQUITETURA_OBSERVABILIDADE.md §1.6).
    """

    def format(self, record: logging.LogRecord) -> str:
        timestamp = (
            datetime.fromtimestamp(record.created, tz=timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
        evento = {
            "timestamp": timestamp,
            "level": record.levelname,
            "logger": record.name,
            "message": mascarar_texto(record.getMessage()),
        }
        evento.update(mascarar_dados(obter_contexto()))

        if record.exc_info:
            evento["exception"] = mascarar_texto("".join(traceback.format_exception(*record.exc_info)))

        extras = {
            chave: valor
            for chave, valor in record.__dict__.items()
            if chave not in _CAMPOS_PADRAO_LOGRECORD and chave not in evento
        }
        # `mascarar_dados` decide redação PELO NOME da chave (ver
        # core/redacao.py:campo_sensivel) -- precisa receber o dict
        # inteiro de uma vez para conseguir associar cada valor à sua
        # chave; chamar mascarar_dados(valor) isoladamente por campo (bug
        # já corrigido aqui) perde essa associação e nunca redige nada por
        # nome de campo, só o padrão de Bearer/JWT solto dentro de um
        # texto -- que é bem mais estreito do que a garantia que este
        # método promete (ver ARQUITETURA_OBSERVABILIDADE.md §1.6).
        evento.update(mascarar_dados(extras))

        return json.dumps(evento, ensure_ascii=False, default=str)


class FormatadorTexto(logging.Formatter):
    """Formato legível para desenvolvimento local (`SENTINELA_LOG_FORMATO=texto`)
    -- ainda passa pela mesma redação de segredos que o formato JSON."""

    def format(self, record: logging.LogRecord) -> str:
        record.msg = mascarar_texto(record.getMessage())
        record.args = ()
        return super().format(record)


def configurar_logging(nivel: str = "INFO", formato: str = "json") -> None:
    """
    Chamada uma vez, o mais cedo possível na construção da aplicação (ver
    `main.py:criar_app`, ANTES até de `Settings.validar()` rodar -- um
    `formato` inválido derruba a aplicação na hora de construir o
    `FastAPI()`, não na primeira requisição).

    `formato`: `"json"` (produção, um objeto JSON por linha) ou `"texto"`
    (desenvolvimento local, legível num terminal). Sem default condicionado
    a `ENV` de propósito -- ver ARQUITETURA_OBSERVABILIDADE.md §1.7.
    """
    if formato not in FORMATOS_VALIDOS:
        raise RuntimeError(
            f"SENTINELA_LOG_FORMATO inválido: {formato!r} -- use um de {FORMATOS_VALIDOS}."
        )

    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "json": {"()": FormatadorJSON},
            "texto": {
                "()": FormatadorTexto,
                "format": "%(asctime)s %(levelname)-8s %(name)s -- %(message)s",
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": formato,
                "stream": "ext://sys.stdout",
            },
        },
        "root": {"level": nivel, "handlers": ["console"]},
        "loggers": {
            # uvicorn continua logando startup/erros de baixo nível do
            # próprio servidor ASGI -- reaproveita o MESMO
            # formatter/handler (JSON consistente com o resto).
            "uvicorn": {"level": nivel, "handlers": ["console"], "propagate": False},
            "uvicorn.error": {"level": nivel, "handlers": ["console"], "propagate": False},
            # DESLIGADO de propósito -- web/logging_middleware.py já loga
            # uma linha por requisição com MAIS contexto (request_id,
            # empresa_id, duracao_ms) do que o access log padrão do
            # uvicorn. Ver ARQUITETURA_OBSERVABILIDADE.md §1.5.
            "uvicorn.access": {"level": "WARNING", "handlers": [], "propagate": False},
            # Todo `logging.getLogger("sentinela.X")` do resto do código
            # (core/email.py, services/automacao.py, services/
            # redefinicao_senha.py, web/logging_middleware.py, ...) sobe
            # até aqui por herança de nome (propagate=True nos filhos, que
            # não são configurados individualmente) e para aqui --
            # propagate=False evita duplicar a linha no root também.
            "sentinela": {"level": nivel, "handlers": ["console"], "propagate": False},
        },
    }
    logging.config.dictConfig(config)
