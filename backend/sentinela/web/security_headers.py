# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Cabeçalhos de segurança HTTP -- item 18 do plano de endurecimento
pós-auditoria: CSP, X-Content-Type-Options, X-Frame-Options,
Referrer-Policy, Permissions-Policy e HSTS em TODA resposta (API JSON,
HTML/HTMX, estáticos, build do React em /app) -- via um único middleware em
main.py, para que nenhuma rota individual precise se lembrar de setar isso.

A CSP abaixo é deliberadamente estrita (nada de 'unsafe-inline' em
script-src/style-src) porque o projeto inteiro -- tanto o HTML/Jinja2
servido por web/templates/ quanto o build do React em frontend-react/dist
-- já não depende de nenhum <script>/<style> inline nem de recurso
carregado de outro domínio (htmx.min.js é servido localmente em
/static/js/, o CSS do React é um arquivo separado gerado pelo Vite, sem
CSS-in-JS). Duas exceções que existiam antes desta correção (um
onchange="..." inline em incidentes/lista.html e um style="..." inline em
usuarios/minha_conta.html) foram removidas junto com este item -- ver
web/static/js/app.js e web/static/css/estilo.css -- especificamente para
que a CSP pudesse ficar estrita sem abrir uma exceção só para elas.
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# default-src 'self': ponto de partida restritivo -- qualquer diretiva não
# listada explicitamente abaixo herda isso, em vez do padrão "permite tudo"
# de não ter CSP nenhuma.
# connect-src 'self': cobre tanto o `fetch` do React (frontend-react/src/api/client.ts,
# sempre para /api/v1/... mesmo-origem) quanto as requisições HTMX.
# frame-ancestors 'none': equivalente moderno (e mais forte -- cobre também
# navegadores/contexto que X-Frame-Options não cobre) do X-Frame-Options
# abaixo; mantemos os dois porque X-Frame-Options ainda importa para
# navegadores antigos que não leem frame-ancestors.
# object-src 'none': nenhuma rota deste projeto serve <object>/<embed>/Flash;
# fechar isso remove uma superfície clássica de XSS via plugin.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    # PWA (app instalável no celular, ver frontend-react/public/): o service
    # worker é um worker script, e sem worker-src ele herdaria default-src --
    # que alguns navegadores tratam como proibido para workers. manifest-src
    # idem para o manifest. Ambos 'self': mesmo origem, como todo o resto.
    "worker-src 'self'; "
    "manifest-src 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "object-src 'none'"
)

# Nega por padrão as permissões de browser mais sensíveis/mais comumente
# abusadas por um XSS ou uma dependência de terceiro comprometida -- este
# projeto não usa nenhuma delas. "interest-cohort=()" desliga o FLoC/Topics
# do Chrome (rastreamento entre sites), não uma permissão tradicional, mas
# a mesma sintaxe de Permissions-Policy é o jeito padrão de recusar.
PERMISSIONS_POLICY = (
    "geolocation=(), camera=(), microphone=(), payment=(), usb=(), "
    "magnetometer=(), gyroscope=(), accelerometer=(), interest-cohort=()"
)

# O Swagger UI/ReDoc que o FastAPI serve automaticamente em /docs, /redoc e
# /openapi.json carrega JS/CSS de um CDN externo (cdn.jsdelivr.net) -- a CSP
# estrita acima quebraria essas duas páginas (que não são usadas por
# nenhuma rota do produto em si, só documentação/exploração manual da API).
# Em vez de afrouxar a CSP do resto do site inteiro para acomodar só essas
# duas páginas, elas ficam de fora só da diretiva CSP (os outros
# cabeçalhos -- nosniff, X-Frame-Options, Referrer-Policy,
# Permissions-Policy, HSTS -- continuam se aplicando normalmente a elas).
#
# Em produção (ENV=production) main.py desliga essas três rotas por
# completo (`docs_url=None`/`redoc_url=None`/`openapi_url=None` na
# construção do FastAPI, ver criar_app()) -- ponto 5 do review de
# hardening: reduz superfície de ataque e, na prática, esvazia esta lista
# de exceção (as rotas nem existem mais para responder). Continuam listadas
# aqui porque em dev/teste (onde /docs e /redoc continuam ativas) a
# exceção ainda é necessária.
_CAMINHOS_SEM_CSP = {"/docs", "/redoc", "/openapi.json"}


class CabecalhosDeSegurancaMiddleware(BaseHTTPMiddleware):
    """
    `producao` vem de `Settings.producao` (mesma flag que já controla o
    `Secure` do cookie de sessão -- ver auth/dependencies.py). HSTS só faz
    sentido -- e só é seguro -- anunciar quando o tráfego real está atrás de
    HTTPS; em dev (HTTP puro, localhost) declarar HSTS não quebra nada
    tecnicamente, mas não protege nada real e só atrapalha quem testa local
    sem TLS, então fica condicionado à mesma flag de produção.
    """

    def __init__(self, app, producao: bool = False):
        super().__init__(app)
        self._producao = producao

    async def dispatch(self, request: Request, call_next) -> Response:
        resposta = await call_next(request)
        resposta.headers["X-Content-Type-Options"] = "nosniff"
        resposta.headers["X-Frame-Options"] = "DENY"
        resposta.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resposta.headers["Permissions-Policy"] = PERMISSIONS_POLICY
        if request.url.path not in _CAMINHOS_SEM_CSP:
            resposta.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
        if self._producao:
            # 1 ano + includeSubDomains -- valor comum de "produção madura";
            # sem `preload` de propósito (entrar na lista de preload do
            # Chrome é uma decisão além do escopo deste middleware, exige
            # submissão manual do domínio real).
            resposta.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resposta
