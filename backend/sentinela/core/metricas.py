# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Métricas Prometheus (Fase E / E1) -- ver ARQUITETURA_OBSERVABILIDADE.md §2
para o desenho completo, escrito ANTES deste código.

`CollectorRegistry` PRÓPRIO (não o `REGISTRY` global do módulo
`prometheus_client`) -- deixa explícito, num só lugar, tudo que este
processo exporta, e evita colidir com qualquer outro código no mesmo
processo que eventualmente registre métricas no registro global.

Três métricas nesta etapa, deliberadamente (ver §2.2/§2.5 para o porquê do
escopo não incluir métricas de negócio ainda):
  - `sentinela_http_requisicoes_total` -- volume por rota/status.
  - `sentinela_http_requisicao_duracao_segundos` -- latência (histograma).
  - `sentinela_app_info` -- metadado estático (versão), sem rótulo variável.
"""
from prometheus_client import CollectorRegistry, Counter, Histogram, Info, generate_latest
from prometheus_client import CONTENT_TYPE_LATEST as TIPO_CONTEUDO_METRICAS

# `TIPO_CONTEUDO_METRICAS` é reexportado aqui de propósito -- consumido por
# web/routes_metricas.py como o `media_type` correto da resposta HTTP (o
# formato de exposição do Prometheus tem seu próprio content-type
# versionado, não é "text/plain" genérico).
__all__ = [
    "REGISTRO",
    "TIPO_CONTEUDO_METRICAS",
    "ROTA_DESCONHECIDA",
    "registrar_requisicao",
    "resolver_rota_para_metrica",
    "definir_versao_aplicacao",
    "gerar_metricas",
]

REGISTRO = CollectorRegistry()

REQUISICOES_TOTAL = Counter(
    "sentinela_http_requisicoes_total",
    "Total de requisições HTTP recebidas, por método, rota (template) e status.",
    ["metodo", "rota", "status"],
    registry=REGISTRO,
)

REQUISICAO_DURACAO_SEGUNDOS = Histogram(
    "sentinela_http_requisicao_duracao_segundos",
    "Duração de requisições HTTP em segundos, por método e rota (template).",
    ["metodo", "rota"],
    registry=REGISTRO,
)

INFO_APLICACAO = Info(
    "sentinela_app",
    "Metadados estáticos da build em execução.",
    registry=REGISTRO,
)

# Rótulo usado quando nenhuma rota do Starlette bateu com o path (404
# genuíno) -- nunca o path bruto, ver ARQUITETURA_OBSERVABILIDADE.md §2.3
# (rótulo de série temporal do Prometheus precisa ter cardinalidade
# limitada; um path com um UUID/ID solto criaria uma série nova por
# requisição).
ROTA_DESCONHECIDA = "desconhecida"


def registrar_requisicao(metodo: str, rota: str, status: int, duracao_segundos: float) -> None:
    REQUISICOES_TOTAL.labels(metodo=metodo, rota=rota, status=str(status)).inc()
    REQUISICAO_DURACAO_SEGUNDOS.labels(metodo=metodo, rota=rota).observe(duracao_segundos)


def resolver_rota_para_metrica(request) -> str:
    """Extrai o TEMPLATE da rota (ex.: "/api/v1/agentes/{agente_id}"),
    não o path bruto -- só disponível em `request.scope["route"]` depois
    que o roteamento do Starlette já rodou (ou seja, depois de
    `call_next` retornar, dentro do middleware que chama esta função)."""
    rota = request.scope.get("route")
    if rota is not None and getattr(rota, "path", None):
        return rota.path
    return ROTA_DESCONHECIDA


def definir_versao_aplicacao(versao: str) -> None:
    INFO_APLICACAO.info({"versao": versao})


def gerar_metricas() -> bytes:
    return generate_latest(REGISTRO)
