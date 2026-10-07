# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
GET /metrics -- exposição Prometheus (Fase E / E1), ver
ARQUITETURA_OBSERVABILIDADE.md §2 para o desenho completo.

Deliberadamente FORA de /api/v1 (mesmo raciocínio de routes_saude.py --
um scraper Prometheus não faz login, não manda cookie/CSRF). Protegido por
um token compartilhado OPCIONAL (`SENTINELA_METRICS_TOKEN`, ver
config.py) em vez de autenticação de sessão completa: se a variável não
está configurada, a rota responde 404 (não existe operacionalmente, mesmo
padrão de `agentes_endpoint_habilitado`); se está, exige o header
`X-Metrics-Token` com o valor exato, comparado com `secrets.compare_digest`
para não vazar o valor certo por timing.
"""
import secrets

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse, Response

from sentinela.core.metricas import TIPO_CONTEUDO_METRICAS, gerar_metricas

router = APIRouter(tags=["metricas"])

HEADER_METRICS_TOKEN = "X-Metrics-Token"


@router.get("/metrics")
async def metricas(request: Request):
    settings = request.app.state.settings
    token_configurado = settings.metrics_token
    if not token_configurado:
        # Feature desligada -- 404, não 403: não confirma nem nega que a
        # capacidade existe para quem não deveria nem saber que ela existe.
        return PlainTextResponse("not found", status_code=404)

    token_recebido = request.headers.get(HEADER_METRICS_TOKEN, "")
    if not secrets.compare_digest(token_recebido, token_configurado):
        return PlainTextResponse("unauthorized", status_code=401)

    return Response(content=gerar_metricas(), media_type=TIPO_CONTEUDO_METRICAS)
