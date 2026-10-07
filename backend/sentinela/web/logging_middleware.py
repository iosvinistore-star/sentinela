# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Middleware de logging estruturado por requisição (Fase E / E2) -- ver
ARQUITETURA_OBSERVABILIDADE.md §1.4/§1.5 para o desenho completo.

Três responsabilidades:
  1. Gera (ou propaga, se o cliente já mandou um valor válido) um
     `X-Request-Id` -- devolvido também na resposta, para correlacionar um
     erro relatado por um cliente com as linhas de log daquela requisição
     específica. Também inicia o contexto de correlação
     (`core/log_context.py`) que o resto do código (dependências de
     autenticação, handlers de rota) enriquece ao longo da requisição.
  2. Loga UMA linha por requisição (método, path, status, duração) --
     substitui o access log padrão do uvicorn (desligado em
     `core/logging_config.py`) por um com mais contexto.
  3. (Fase E / E1, ver ARQUITETURA_OBSERVABILIDADE.md §2.3) Registra a
     mesma medição (duração, status) nas métricas Prometheus de
     `core/metricas.py`, reaproveitando o timing já calculado aqui em vez
     de medir a requisição duas vezes com um middleware separado -- só que
     usando o TEMPLATE da rota (`/agentes/{agente_id}`), não o path bruto
     usado no log, porque um rótulo de métrica precisa de cardinalidade
     limitada.
"""
import logging
import re
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from sentinela.core.log_context import iniciar_contexto
from sentinela.core.metricas import registrar_requisicao, resolver_rota_para_metrica
from sentinela.util import obter_ip_cliente

logger = logging.getLogger("sentinela.acesso")

HEADER_REQUEST_ID = "X-Request-Id"

# Aceita um X-Request-Id fornecido pelo cliente/proxy só se bater este
# padrão restrito -- qualquer coisa fora disso (vazio, longo demais,
# caracteres fora do padrão) é descartada e um valor novo é gerado no
# lugar. O valor entra tanto numa linha de log indexada por um agregador
# quanto num header de resposta -- nenhum dos dois deveria confiar
# cegamente num valor 100% controlado pelo cliente (mesmo raciocínio do
# nonce de D6, ver ARQUITETURA_LICENCIAMENTO.md §11).
_PADRAO_REQUEST_ID_VALIDO = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _resolver_request_id(request: Request) -> str:
    recebido = request.headers.get(HEADER_REQUEST_ID)
    if recebido and _PADRAO_REQUEST_ID_VALIDO.match(recebido):
        return recebido
    return uuid.uuid4().hex


class MiddlewareDeLogging(BaseHTTPMiddleware):
    def __init__(self, app, proxies_confiaveis: str = ""):
        super().__init__(app)
        self._proxies_confiaveis = proxies_confiaveis

    async def dispatch(self, request: Request, call_next):
        request_id = _resolver_request_id(request)
        ip_cliente = obter_ip_cliente(request, self._proxies_confiaveis)
        iniciar_contexto(
            request_id=request_id,
            metodo=request.method,
            path=request.url.path,
            ip_cliente=ip_cliente,
        )

        inicio = time.monotonic()
        try:
            resposta = await call_next(request)
        except Exception:
            duracao_segundos = time.monotonic() - inicio
            duracao_ms = round(duracao_segundos * 1000, 1)
            logger.exception(
                "requisição falhou com exceção não tratada",
                extra={"status": 500, "duracao_ms": duracao_ms},
            )
            # A rota (se alguma bateu) já foi resolvida pelo roteamento do
            # Starlette antes da exceção estourar dentro do handler -- ainda
            # assim cai em ROTA_DESCONHECIDA se o roteamento nem chegou a
            # rodar (ex.: exceção num middleware mais interno).
            registrar_requisicao(
                metodo=request.method,
                rota=resolver_rota_para_metrica(request),
                status=500,
                duracao_segundos=duracao_segundos,
            )
            raise

        duracao_segundos = time.monotonic() - inicio
        duracao_ms = round(duracao_segundos * 1000, 1)
        if resposta.status_code >= 500:
            nivel = logging.ERROR
        elif resposta.status_code >= 400:
            nivel = logging.WARNING
        else:
            nivel = logging.INFO
        logger.log(
            nivel,
            "requisição concluída",
            extra={"status": resposta.status_code, "duracao_ms": duracao_ms},
        )
        registrar_requisicao(
            metodo=request.method,
            rota=resolver_rota_para_metrica(request),
            status=resposta.status_code,
            duracao_segundos=duracao_segundos,
        )

        resposta.headers[HEADER_REQUEST_ID] = request_id
        return resposta
