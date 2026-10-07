# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testes do middleware de logging estruturado (web/logging_middleware.py) --
Fase E / E2, ver ARQUITETURA_OBSERVABILIDADE.md §1.4/§1.5.

Mesmo padrão de tests/unit/test_limite_corpo.py: monta uma Starlette app
mínima com só este middleware, usando TestClient. O conteúdo emitido pelo
logger ("sentinela.acesso") é capturado anexando um `logging.Handler` de
teste DIRETO no logger (sem passar por `logging.config.dictConfig`) -- ver
o comentário da fixture `_linhas_capturadas` para o porquê disso ser mais
robusto do que capturar stdout.
"""
import logging

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from sentinela.core.log_context import obter_contexto
from sentinela.web.logging_middleware import HEADER_REQUEST_ID, MiddlewareDeLogging


async def _rota_ok(request):
    return PlainTextResponse("ok")


async def _rota_erro_cliente(request):
    return JSONResponse({"detail": "não encontrado"}, status_code=404)


async def _rota_erro_servidor(request):
    return JSONResponse({"detail": "erro interno"}, status_code=500)


async def _rota_excecao_nao_tratada(request):
    raise RuntimeError("algo quebrou de verdade")


async def _rota_eco_contexto(request):
    """Usada só para inspecionar o que o middleware colocou no contexto de
    correlação ANTES do handler da rota rodar."""
    contexto = obter_contexto()
    return JSONResponse(contexto)


def _montar_app(proxies_confiaveis: str = "") -> Starlette:
    app = Starlette(routes=[
        Route("/ok", _rota_ok),
        Route("/erro-cliente", _rota_erro_cliente),
        Route("/erro-servidor", _rota_erro_servidor),
        Route("/excecao", _rota_excecao_nao_tratada),
        Route("/contexto", _rota_eco_contexto),
    ])
    app.add_middleware(MiddlewareDeLogging, proxies_confiaveis=proxies_confiaveis)
    return app


@pytest.fixture
def cliente():
    # raise_server_exceptions=False -- precisamos que uma exceção não
    # tratada dentro da rota chegue como uma resposta 500 de verdade
    # (Starlette's ServerErrorMiddleware faria isso em produção), não
    # reexplodida no teste -- o middleware sob teste roda ANTES dessa
    # camada, então ele mesmo captura e loga a exceção antes dela virar
    # uma resposta 500 do servidor.
    return TestClient(_montar_app(), raise_server_exceptions=False)


class _HandlerDeTeste(logging.Handler):
    def __init__(self):
        super().__init__()
        self.registros = []

    def emit(self, record):
        self.registros.append(record)


@pytest.fixture
def linhas_capturadas():
    """
    Anexa um handler de teste DIRETO no logger "sentinela.acesso" (não via
    dictConfig) -- funciona independente de `configurar_logging` já ter
    rodado neste processo de teste ou não, e não depende de capturar
    stdout (que teria o problema clássico de `StreamHandler` guardar uma
    referência à stream ORIGINAL, resolvida no momento de
    `logging.config.dictConfig`, não reavaliada a cada write -- então
    `capsys` não veria nada se a config já tivesse rodado antes deste
    teste com outra referência de stdout).
    """
    logger = logging.getLogger("sentinela.acesso")
    handler = _HandlerDeTeste()
    nivel_anterior = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    yield handler.registros
    logger.removeHandler(handler)
    logger.setLevel(nivel_anterior)


def test_adiciona_header_x_request_id_quando_cliente_nao_manda_nenhum(cliente):
    resposta = cliente.get("/ok")
    assert HEADER_REQUEST_ID in resposta.headers
    assert len(resposta.headers[HEADER_REQUEST_ID]) > 0


def test_propaga_x_request_id_valido_enviado_pelo_cliente(cliente):
    resposta = cliente.get("/ok", headers={HEADER_REQUEST_ID: "meu-id-123"})
    assert resposta.headers[HEADER_REQUEST_ID] == "meu-id-123"


def test_gera_novo_request_id_quando_cliente_manda_valor_invalido(cliente):
    # Espaço e "/" não batem no padrão -- ver
    # ARQUITETURA_OBSERVABILIDADE.md §1.4 para o porquê de não confiar
    # cegamente num valor controlado pelo cliente.
    valor_invalido = "valor com espaco/e barra"
    resposta = cliente.get("/ok", headers={HEADER_REQUEST_ID: valor_invalido})
    assert resposta.headers[HEADER_REQUEST_ID] != valor_invalido
    assert len(resposta.headers[HEADER_REQUEST_ID]) > 0


def test_gera_novo_request_id_quando_cliente_manda_valor_longo_demais(cliente):
    valor_longo = "a" * 200
    resposta = cliente.get("/ok", headers={HEADER_REQUEST_ID: valor_longo})
    assert resposta.headers[HEADER_REQUEST_ID] != valor_longo


def test_dois_request_ids_gerados_em_chamadas_diferentes_sao_diferentes(cliente):
    r1 = cliente.get("/ok")
    r2 = cliente.get("/ok")
    assert r1.headers[HEADER_REQUEST_ID] != r2.headers[HEADER_REQUEST_ID]


def test_inicia_contexto_com_metodo_e_path_antes_do_handler_rodar(cliente):
    resposta = cliente.get("/contexto")
    contexto = resposta.json()
    assert contexto["metodo"] == "GET"
    assert contexto["path"] == "/contexto"
    assert "request_id" in contexto


def test_loga_uma_linha_info_para_resposta_2xx(cliente, linhas_capturadas):
    cliente.get("/ok")
    assert len(linhas_capturadas) == 1
    registro = linhas_capturadas[0]
    assert registro.levelno == logging.INFO
    assert registro.status == 200
    assert isinstance(registro.duracao_ms, float)


def test_loga_warning_para_resposta_4xx(cliente, linhas_capturadas):
    cliente.get("/erro-cliente")
    assert linhas_capturadas[0].levelno == logging.WARNING
    assert linhas_capturadas[0].status == 404


def test_loga_error_para_resposta_5xx(cliente, linhas_capturadas):
    cliente.get("/erro-servidor")
    assert linhas_capturadas[0].levelno == logging.ERROR
    assert linhas_capturadas[0].status == 500


def test_loga_excecao_nao_tratada_e_relanca(cliente, linhas_capturadas):
    resposta = cliente.get("/excecao")
    assert resposta.status_code == 500
    assert len(linhas_capturadas) == 1
    registro = linhas_capturadas[0]
    assert registro.levelno == logging.ERROR
    assert registro.exc_info is not None
    assert registro.status == 500


def test_cada_requisicao_tem_seu_proprio_contexto_isolado(cliente):
    r1 = cliente.get("/contexto", headers={HEADER_REQUEST_ID: "primeira-req"})
    r2 = cliente.get("/contexto", headers={HEADER_REQUEST_ID: "segunda-req"})
    assert r1.json()["request_id"] == "primeira-req"
    assert r2.json()["request_id"] == "segunda-req"
