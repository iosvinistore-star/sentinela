# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testes do middleware de teto de tamanho de corpo (web/limite_corpo.py) --
ver o docstring daquele módulo para o cenário de DoS que ele fecha (corpo
multipart gigantesco sendo recebido/parseado por inteiro antes do teto de
10 MB de api/v1/logs.py ter qualquer chance de rejeitar).

Dois níveis de teste aqui:
  1. Via TestClient/Starlette (`Content-Length` declarado antecipadamente).
  2. Direto no protocolo ASGI (scope/receive/send), simulando um corpo que
     chega em chunks e ultrapassa o limite SEM um `Content-Length` correto
     -- o caso que só a contagem em `receive()` (não o cabeçalho) pega.
"""
import asyncio

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from sentinela.web.limite_corpo import LimiteTamanhoCorpoMiddleware

LIMITE = 1000


async def _rota_eco(request):
    corpo = await request.body()
    return PlainTextResponse(f"recebido:{len(corpo)}")


def _montar_app() -> Starlette:
    app = Starlette(routes=[Route("/upload", _rota_eco, methods=["POST"])])
    app.add_middleware(LimiteTamanhoCorpoMiddleware, max_bytes=LIMITE)
    return app


@pytest.fixture
def cliente():
    return TestClient(_montar_app())


def test_corpo_dentro_do_limite_passa(cliente):
    resp = cliente.post("/upload", content=b"x" * 500)
    assert resp.status_code == 200
    assert resp.text == "recebido:500"


def test_content_length_acima_do_limite_e_rejeitado_sem_chamar_a_rota(cliente):
    """Content-Length declarado (900+algo acima de 1000) já é suficiente
    pra rejeitar -- a rota nunca roda, então nunca lemos o corpo de
    verdade."""
    resp = cliente.post("/upload", content=b"x" * 2000)
    assert resp.status_code == 413
    assert "excede" in resp.json()["detail"]


def test_corpo_exatamente_no_limite_passa(cliente):
    resp = cliente.post("/upload", content=b"x" * LIMITE)
    assert resp.status_code == 200
    assert resp.text == f"recebido:{LIMITE}"


def test_corpo_um_byte_acima_do_limite_e_rejeitado(cliente):
    resp = cliente.post("/upload", content=b"x" * (LIMITE + 1))
    assert resp.status_code == 413


async def _app_alvo_que_nunca_deveria_ler_tudo(scope, receive, send):
    """Simula uma rota (como a de upload) que só saberia que o corpo é
    grande demais DEPOIS de terminar de lê-lo inteiro via `receive()` em
    loop -- exatamente o padrão de api/v1/logs.py lendo em chunks de 1 MB.
    Se o middleware estiver fazendo o trabalho dele, esta função nunca
    termina o loop (a exceção interrompe antes)."""
    total = 0
    while True:
        mensagem = await receive()
        total += len(mensagem.get("body", b""))
        if not mensagem.get("more_body", False):
            break
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": f"nao deveria chegar aqui: {total}".encode()})


def _scope_sem_content_length(path="/qualquer"):
    return {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": [],  # sem Content-Length -- simula chunked/cliente que mente
        "query_string": b"",
    }


def _fabrica_receive_em_chunks(chunks: list[bytes]):
    """`receive()` que entrega um chunk por chamada, como um cliente real
    mandando o corpo aos poucos pela rede."""
    restante = list(chunks)

    async def receive():
        if not restante:
            return {"type": "http.disconnect"}
        chunk = restante.pop(0)
        return {
            "type": "http.request",
            "body": chunk,
            "more_body": bool(restante),
        }

    return receive


def test_sem_content_length_corta_pela_contagem_em_receive():
    """O caso que só a segunda camada de defesa (contar bytes conforme
    chegam) cobre: nenhum Content-Length no cabeçalho para o pre-check
    interceptar, então o middleware precisa cortar no meio do streaming."""
    middleware = LimiteTamanhoCorpoMiddleware(_app_alvo_que_nunca_deveria_ler_tudo, max_bytes=LIMITE)
    receive = _fabrica_receive_em_chunks([b"a" * 400, b"b" * 400, b"c" * 400])  # soma 1200 > 1000

    respostas_enviadas = []

    async def send(mensagem):
        respostas_enviadas.append(mensagem)

    asyncio.run(middleware(_scope_sem_content_length(), receive, send))

    status = next(m["status"] for m in respostas_enviadas if m["type"] == "http.response.start")
    corpo = b"".join(m["body"] for m in respostas_enviadas if m["type"] == "http.response.body")
    assert status == 413
    assert b"nao deveria chegar aqui" not in corpo


def test_dentro_do_limite_sem_content_length_chega_na_aplicacao():
    middleware = LimiteTamanhoCorpoMiddleware(_app_alvo_que_nunca_deveria_ler_tudo, max_bytes=LIMITE)
    receive = _fabrica_receive_em_chunks([b"a" * 300, b"b" * 300])  # soma 600 < 1000

    respostas_enviadas = []

    async def send(mensagem):
        respostas_enviadas.append(mensagem)

    asyncio.run(middleware(_scope_sem_content_length(), receive, send))

    status = next(m["status"] for m in respostas_enviadas if m["type"] == "http.response.start")
    corpo = b"".join(m["body"] for m in respostas_enviadas if m["type"] == "http.response.body")
    assert status == 200
    assert corpo == b"nao deveria chegar aqui: 600"


def test_websocket_e_ignorado_pelo_middleware():
    """`scope["type"] != "http"` (ex.: websocket) passa direto -- este
    middleware não tem nada a ver com esse protocolo."""
    chamadas = []

    async def app_alvo(scope, receive, send):
        chamadas.append(scope["type"])

    middleware = LimiteTamanhoCorpoMiddleware(app_alvo, max_bytes=LIMITE)
    scope = {"type": "websocket", "path": "/ws"}

    async def receive():
        return {"type": "websocket.connect"}

    async def send(mensagem):
        pass

    asyncio.run(middleware(scope, receive, send))
    assert chamadas == ["websocket"]
