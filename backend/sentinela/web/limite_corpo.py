# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Limite GLOBAL de tamanho de corpo de requisição -- camada anterior ao
`MAX_LOG_UPLOAD_BYTES` (10 MB) de api/v1/logs.py/web/routes_logs.py, não um
substituto dele.

O problema que isto fecha: `MAX_LOG_UPLOAD_BYTES` só é checado DENTRO da
rota, chunk a chunk, enquanto `arquivo.read()` é chamado explicitamente no
código da aplicação. Mas para uma rota que recebe `UploadFile`/`Form`, o
FastAPI resolve esses parâmetros chamando `await request.form()` ANTES de
qualquer linha do corpo da rota rodar -- e é o parser de multipart do
Starlette (via `python-multipart`) que lê o corpo da requisição inteiro do
socket nesse momento, escrevendo cada parte de arquivo num
`SpooledTemporaryFile` (memória até um teto pequeno, depois disco). Ou seja:
um cliente que manda um corpo multipart de, digamos, 2 GB faz o servidor
gastar tempo de rede, CPU (parsing) e I/O de disco recebendo o corpo
INTEIRO antes que o código da rota sequer comece a executar e tenha a
chance de rejeitar com 413 -- o teto de 10 MB da rota nunca chega a ser
consultado a tempo de evitar esse custo.

Este middleware ASGI roda ANTES de qualquer parsing de rota (é a camada
mais externa possível dentro da aplicação -- middlewares Starlette
envolvem o roteamento inteiro) e corta a requisição em dois pontos:

  1. `Content-Length` declarado acima do limite -- responde 413 e nunca
     chama o resto da aplicação; nem um byte do corpo é lido.
  2. Para requisições sem `Content-Length` confiável (chunked
     transfer-encoding, ou um cliente que simplesmente mente no cabeçalho)
     -- contamos os bytes conforme chegam via `receive()` e abortamos assim
     que o total ultrapassa o limite, antes de repassar esses bytes para o
     parser de multipart/form-data do Starlette.

Isto é defesa em profundidade DENTRO do processo Python -- não substitui um
limite de tamanho de corpo no reverse proxy/load balancer na frente do
uvicorn (nginx `client_max_body_size`, Traefik `maxRequestBodyBytes`,
Cloudflare, AWS ALB `httpDesyncMitigationMode`/WAF). Um limite no proxy é
estritamente melhor quando disponível: rejeita a requisição antes mesmo de
abrir uma conexão com este processo, protegendo também a banda/CPU do
proxy. Este middleware é o que garante a mesma proteção quando o Sentinela
roda sem proxy na frente (dev, um único container exposto direto) ou como
segunda camada caso o proxy esteja mal configurado.
"""
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

# Maior corpo legítimo esperado hoje é o upload de log (MAX_LOG_UPLOAD_BYTES
# = 10 MB, ver api/v1/logs.py/web/routes_logs.py) -- a margem acima disso
# cobre o overhead de boundaries/headers do multipart e os demais campos do
# form (limite, verificar_reputacao, etc.), sem abrir espaço de sobra para
# abuso. Toda outra rota do sistema troca JSON/form pequenos (payloads na
# casa dos KB), então um teto pensado para o upload cobre confortavelmente
# o resto da aplicação também.
MAX_CORPO_REQUISICAO_BYTES_PADRAO = 12 * 1024 * 1024


class _CorpoExcedeLimiteError(Exception):
    pass


async def _responder_413(send: Send) -> None:
    corpo = b'{"detail":"corpo da requisicao excede o limite permitido"}'
    await send({
        "type": "http.response.start",
        "status": 413,
        "headers": [(b"content-type", b"application/json")],
    })
    await send({"type": "http.response.body", "body": corpo})


class LimiteTamanhoCorpoMiddleware:
    """Middleware ASGI puro (não `BaseHTTPMiddleware`) -- precisa envolver
    `receive` diretamente para contar bytes conforme chegam, antes que
    QUALQUER outra camada (inclusive o parser de multipart) os consuma."""

    def __init__(self, app: ASGIApp, max_bytes: int = MAX_CORPO_REQUISICAO_BYTES_PADRAO):
        self._app = app
        self._max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        content_length = headers.get("content-length")
        if content_length is not None:
            try:
                declarado = int(content_length)
            except ValueError:
                declarado = None
            if declarado is not None and declarado > self._max_bytes:
                await _responder_413(send)
                return

        total_recebido = 0
        limite = self._max_bytes
        resposta_iniciada = False

        async def receive_limitado():
            nonlocal total_recebido
            mensagem = await receive()
            if mensagem["type"] == "http.request":
                total_recebido += len(mensagem.get("body", b""))
                if total_recebido > limite:
                    raise _CorpoExcedeLimiteError()
            return mensagem

        async def send_rastreado(mensagem):
            nonlocal resposta_iniciada
            if mensagem["type"] == "http.response.start":
                resposta_iniciada = True
            await send(mensagem)

        try:
            await self._app(scope, receive_limitado, send_rastreado)
        except _CorpoExcedeLimiteError:
            # Só é seguro mandar uma resposta 413 própria se a aplicação
            # ainda não começou a responder (ex.: já mandou headers de uma
            # resposta de streaming) -- nesse caso raríssimo, deixamos a
            # exceção propagar e o servidor ASGI encerra a conexão.
            if not resposta_iniciada:
                await _responder_413(send)
            else:
                raise
