# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testes de core/logging_config.py -- Fase E / E2, ver
ARQUITETURA_OBSERVABILIDADE.md §1.2/§1.6/§1.7.

Testa o `FormatadorJSON`/`FormatadorTexto` diretamente (chamando
`.format(record)` com um `logging.LogRecord` construído à mão) em vez de
passar pelo pipeline completo de `logging.config.dictConfig` + captura de
stdout -- mais determinístico (não depende de timing de handler/stream) e
testa exatamente a unidade que decide o conteúdo de cada linha.
"""
import json
import logging

import pytest

from sentinela.core.log_context import iniciar_contexto
from sentinela.core.logging_config import (
    FormatadorJSON,
    FormatadorTexto,
    configurar_logging,
)
from sentinela.core.redacao import MASCARA


def _registro(msg="mensagem de teste", level=logging.INFO, args=(), exc_info=None, extra=None):
    record = logging.LogRecord(
        name="sentinela.teste", level=level, pathname=__file__, lineno=1,
        msg=msg, args=args, exc_info=exc_info,
    )
    for chave, valor in (extra or {}).items():
        setattr(record, chave, valor)
    return record


@pytest.fixture(autouse=True)
def _contexto_limpo():
    """Cada teste começa com o contexto de correlação zerado -- evita que
    um teste anterior (ou outro módulo de teste que toque
    core/log_context.py) vaze estado para este."""
    iniciar_contexto()
    yield
    iniciar_contexto()


def test_formatador_json_campos_basicos():
    formatador = FormatadorJSON()
    linha = formatador.format(_registro("evento simples"))
    evento = json.loads(linha)
    assert evento["level"] == "INFO"
    assert evento["logger"] == "sentinela.teste"
    assert evento["message"] == "evento simples"
    assert "timestamp" in evento
    # ISO 8601 UTC com sufixo Z, não +00:00 (ver docstring do módulo).
    assert evento["timestamp"].endswith("Z")


def test_formatador_json_aplica_formatacao_percent_do_logging():
    formatador = FormatadorJSON()
    linha = formatador.format(_registro("usuário %s fez login", args=("fulano",)))
    evento = json.loads(linha)
    assert evento["message"] == "usuário fulano fez login"


def test_formatador_json_inclui_contexto_de_correlacao():
    iniciar_contexto(request_id="req-123", empresa_id="empresa-1")
    formatador = FormatadorJSON()
    evento = json.loads(formatador.format(_registro("algo aconteceu")))
    assert evento["request_id"] == "req-123"
    assert evento["empresa_id"] == "empresa-1"


def test_formatador_json_inclui_campos_extra():
    formatador = FormatadorJSON()
    evento = json.loads(formatador.format(_registro("requisição concluída", extra={"status": 200, "duracao_ms": 12.3})))
    assert evento["status"] == 200
    assert evento["duracao_ms"] == 12.3


def test_formatador_json_inclui_traceback_em_excecao():
    formatador = FormatadorJSON()
    try:
        raise ValueError("algo quebrou")
    except ValueError:
        import sys
        registro = _registro("falhou", level=logging.ERROR, exc_info=sys.exc_info())
    evento = json.loads(formatador.format(registro))
    assert "exception" in evento
    assert "ValueError: algo quebrou" in evento["exception"]


def test_formatador_json_mascara_segredo_na_mensagem():
    formatador = FormatadorJSON()
    evento = json.loads(formatador.format(_registro("Authorization: Bearer abc123.def456-xyz")))
    assert "abc123" not in evento["message"]
    assert MASCARA in evento["message"]


def test_formatador_json_mascara_segredo_em_campo_extra():
    formatador = FormatadorJSON()
    evento = json.loads(formatador.format(_registro("evento", extra={"senha": "hunter2", "usuario": "fulano"})))
    assert evento["senha"] == MASCARA
    assert evento["usuario"] == "fulano"


def test_formatador_json_mascara_segredo_no_contexto_de_correlacao():
    # Defesa em profundidade -- nenhum campo de contexto real deveria se
    # chamar "token", mas se algum código futuro chamar
    # adicionar_contexto(token=...) por engano, ainda sai mascarado.
    iniciar_contexto(request_id="req-1", token="lic_abc123")
    formatador = FormatadorJSON()
    evento = json.loads(formatador.format(_registro("evento")))
    assert evento["token"] == MASCARA
    assert evento["request_id"] == "req-1"


def test_formatador_json_produz_json_valido_mesmo_com_valor_nao_serializavel():
    class ObjetoQualquer:
        def __str__(self):
            return "representação em texto"

    formatador = FormatadorJSON()
    evento = json.loads(formatador.format(_registro("evento", extra={"objeto": ObjetoQualquer()})))
    assert evento["objeto"] == "representação em texto"


def test_formatador_texto_mascara_segredo_e_nao_quebra_com_percent_literal():
    formatador = FormatadorTexto("%(levelname)s %(message)s")
    linha = formatador.format(_registro("Authorization: Bearer abc123 -- 100%% de certeza"))
    assert "abc123" not in linha
    assert MASCARA in linha


def test_configurar_logging_aceita_formatos_validos():
    configurar_logging(nivel="DEBUG", formato="json")
    configurar_logging(nivel="INFO", formato="texto")


def test_configurar_logging_recusa_formato_invalido():
    with pytest.raises(RuntimeError, match="SENTINELA_LOG_FORMATO"):
        configurar_logging(formato="xml")


def test_configurar_logging_desliga_uvicorn_access_e_liga_sentinela():
    configurar_logging(nivel="INFO", formato="json")
    logger_acesso_uvicorn = logging.getLogger("uvicorn.access")
    assert logger_acesso_uvicorn.handlers == []

    logger_sentinela = logging.getLogger("sentinela")
    assert len(logger_sentinela.handlers) == 1
    assert logger_sentinela.propagate is False
    assert isinstance(logger_sentinela.handlers[0].formatter, FormatadorJSON)


def test_configurar_logging_com_formato_texto_usa_formatador_texto():
    configurar_logging(nivel="INFO", formato="texto")
    logger_sentinela = logging.getLogger("sentinela")
    assert isinstance(logger_sentinela.handlers[0].formatter, FormatadorTexto)
    # Restaura para "json" -- outros testes do processo (ex.: os que
    # criam a app via criar_app()) não deveriam herdar "texto" só porque
    # este teste rodou antes.
    configurar_logging(nivel="INFO", formato="json")


def test_logger_filho_de_sentinela_propaga_ate_o_pai_configurado():
    """`logging.getLogger("sentinela.email")` (core/email.py) não é
    configurado individualmente -- deve propagar até o logger "sentinela"
    (que tem o handler) e nunca até a raiz (propagate=False em
    "sentinela")."""
    configurar_logging(nivel="INFO", formato="json")
    logger_filho = logging.getLogger("sentinela.email")
    assert logger_filho.handlers == []
    assert logger_filho.getEffectiveLevel() == logging.INFO
    # Confirma que o record realmente seria manipulado só pelo handler do
    # pai "sentinela", nunca duplicado no root.
    ancestral_com_handler = logger_filho
    while ancestral_com_handler.handlers == [] and ancestral_com_handler.parent is not None:
        ancestral_com_handler = ancestral_com_handler.parent
    assert ancestral_com_handler.name == "sentinela"
