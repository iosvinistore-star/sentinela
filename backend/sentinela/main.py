# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
FastAPI app factory. Monta:
    /api/v1/...   API JSON pura (consumida pelo React)
    /             rotas HTML (Jinja2 + HTMX)
    /app          build estático do React SPA (produção)

O `Database` (engine SQLAlchemy assíncrono + sessões escopadas por tenant, ver
`sentinela.database`) é criado uma vez no lifespan e guardado em `app.state.db`
— toda dependência de banco (conexao_tenant/conexao_superadmin) lê daí via
`request.app.state.db`.
"""
import asyncio
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from sentinela.api.v1.router import router as api_v1_router
from sentinela.auth.dependencies import NOME_COOKIE_SESSAO
from sentinela.config import carregar_settings
from sentinela.core.logging_config import configurar_logging
from sentinela.core.metricas import definir_versao_aplicacao
from sentinela.core.redacao import MASCARA, campo_sensivel, mascarar_texto
from sentinela.db.limitadores_compartilhados import LimitadorTentativasCompartilhado, LimitadorUploadsCompartilhado
from sentinela.database import Database, DatabaseSettings
from sentinela.services import push as servico_push
from sentinela.services.automacao import rodar_ciclo_autonomo_periodicamente
from sentinela.siem.syslog import iniciar_syslog_udp
from sentinela.siem.retencao import rodar_retencao_siem_periodicamente
from sentinela.web.deps import AcessoEmpresaSuspensaError, RedirecionarParaLogin, SessaoInvalidaError
from sentinela.web.limite_corpo import LimiteTamanhoCorpoMiddleware
from sentinela.web.logging_middleware import MiddlewareDeLogging
from sentinela.web.router import router as web_router
from sentinela.web.routes_metricas import router as metricas_router
from sentinela.web.routes_saude import router as saude_router
from sentinela.web.security_headers import CabecalhosDeSegurancaMiddleware


@asynccontextmanager
async def _lifespan(app: FastAPI):
    settings = carregar_settings()
    settings.validar()
    app.state.settings = settings
    app.state.db = Database.conectar(DatabaseSettings.de_settings(settings))
    # Alerta no celular (services/push.py): registra a app para que a
    # criação de incidente possa disparar a notificação sem carregar o
    # objeto FastAPI por toda a camada de serviço.
    servico_push.registrar_app(app)
    # Compartilhado via Postgres entre réplicas/workers -- ver
    # db/limitadores_compartilhados.py (substitui as versões em memória de
    # auth/rate_limit.py/core/limites_upload.py, que resolviam o item 4 das
    # "Limitações conhecidas" do README só para uma única réplica).
    app.state.limitador_login = LimitadorTentativasCompartilhado(app.state.db)
    # Correção de bug encontrado em revisão crítica (2026-09): o heartbeat
    # de agente (auth/dependencies.py:agente_atual) passou a usar
    # `limitador_login` chaveado por (ip, prefixo do token) -- não só por
    # ip -- para que UM token ruim/revogado em loop não consiga bloquear
    # TODOS os outros agentes que saem pela mesma NAT/proxy corporativo
    # (o caso comum de uma frota de EDR, não uma exceção). Mas chavear por
    # prefixo abre uma via nova: um atacante pode inventar um prefixo de
    # 12 hex DIFERENTE a cada tentativa (extrair_prefixo só valida
    # FORMATO, não se o agente existe) e nunca acumular falhas na mesma
    # chave, driblando o limite por completo. Este segundo limitador é o
    # backstop: um teto BEM mais folgado (40 falhas/60s) só por IP, sem
    # olhar prefixo -- não deveria nunca disparar para uma frota legítima
    # (mesmo várias dezenas de agentes com problema simultâneo não bateriam
    # nisso no cadência normal de heartbeat de 15-30s), mas para qualquer
    # flood de verdade (prefixos forjados incluídos).
    app.state.limitador_agente_ip = LimitadorTentativasCompartilhado(
        app.state.db, max_tentativas=40, janela_segundos=60, bloqueio_segundos=60,
    )
    # Volume por usuário/empresa também compartilhado; concorrência de
    # análise de log continua em memória DE PROPÓSITO -- ver docstring de
    # LimitadorUploadsCompartilhado.
    app.state.limitador_uploads = LimitadorUploadsCompartilhado(app.state.db)
    # Rate limiting de licenciamento (ver auth/dependencies.py:
    # licenca_atual) -- instâncias PRÓPRIAS, nunca reaproveitam
    # limitador_login/limitador_agente_ip: um token de licença ruim em loop
    # não deve consumir o orçamento de tentativas de login humano nem do
    # heartbeat de agentes EDR, e vice-versa. Mesmos parâmetros do backstop
    # por IP de agentes (40 falhas/60s) -- mesmo raciocínio, adaptado para
    # licenciamento em vez de heartbeat de endpoint.
    app.state.limitador_licenca = LimitadorTentativasCompartilhado(app.state.db)
    app.state.limitador_licenca_ip = LimitadorTentativasCompartilhado(
        app.state.db, max_tentativas=40, janela_segundos=60, bloqueio_segundos=60,
    )
    # Fase D / D3 -- troca de token de enrollment por identidade de agente
    # (ver auth/dependencies.py:enrollment_atual e
    # ARQUITETURA_LICENCIAMENTO.md §12). Instâncias PRÓPRIAS, mesmo
    # raciocínio de isolamento de orçamento já aplicado a
    # limitador_licenca/limitador_agente_ip: um token de enrollment ruim em
    # loop não deve consumir o orçamento de tentativas de nenhuma outra
    # família de token.
    app.state.limitador_enrollment = LimitadorTentativasCompartilhado(app.state.db)
    app.state.limitador_enrollment_ip = LimitadorTentativasCompartilhado(
        app.state.db, max_tentativas=40, janela_segundos=60, bloqueio_segundos=60,
    )
    # Fase C (MFA/TOTP, C9) -- instância PRÓPRIA, nunca reaproveita
    # `limitador_login`: um código TOTP/recovery errado em loop não deve
    # consumir o orçamento de tentativas de SENHA de ninguém, e vice-versa
    # (dois fatores diferentes, dois orçamentos de tentativa diferentes).
    # Chaveado por usuário (ver api/v1/auth.py/api/v1/usuarios.py), não por
    # IP -- um código TOTP de 6 dígitos tem espaço de busca pequeno o
    # bastante (10^6) para que um limite por usuário (não diluído entre
    # vários alvos atrás do mesmo IP) seja a defesa que importa aqui.
    app.state.limitador_mfa = LimitadorTentativasCompartilhado(app.state.db)
    # Modo autônomo (ver services/automacao.py) -- SEM esta tarefa em
    # background, o autoajuste de modo_firewall e a auto-triagem de
    # incidentes (capacidades 1 e 2, ambas opt-in por tenant) só
    # reavaliariam quando uma requisição HTTP (upload de log) disparasse
    # `responder_a_incidentes`, o que continuaria sendo uma dependência
    # humana disfarçada de automação. Roda em background pelo tempo de
    # vida do processo; cancelada de propósito no shutdown (não
    # `await`ada até terminar -- ela nunca termina sozinha, é um loop
    # infinito por design).
    app.state.tarefa_syslog = await iniciar_syslog_udp(app.state.db)
    app.state.tarefa_retencao_siem = asyncio.create_task(
        rodar_retencao_siem_periodicamente(
            app.state.db,
            settings.siem_retencao_intervalo_horas,
            settings.siem_hot_days,
            settings.siem_cold_days,
        )
    )
    app.state.tarefa_ciclo_autonomo = asyncio.create_task(
        rodar_ciclo_autonomo_periodicamente(app.state.db, settings.ciclo_autonomo_intervalo_segundos)
    )
    try:
        yield
    finally:
        if app.state.tarefa_syslog is not None:
            transport, batcher = app.state.tarefa_syslog
            transport.close()
            await batcher.stop()
        app.state.tarefa_retencao_siem.cancel()
        try:
            await app.state.tarefa_retencao_siem
        except asyncio.CancelledError:
            pass
        app.state.tarefa_ciclo_autonomo.cancel()
        try:
            await app.state.tarefa_ciclo_autonomo
        except asyncio.CancelledError:
            pass
        await app.state.db.fechar()


def criar_app() -> FastAPI:
    # Lido ANTES de instanciar FastAPI de propósito -- `docs_url`/
    # `redoc_url`/`openapi_url` só podem ser decididos na hora da
    # construção (não dá pra "desmontar" essas rotas depois).
    #
    # Ponto 5 do review de hardening pós-auditoria: Swagger UI (/docs) e
    # ReDoc (/redoc) expõem publicamente a superfície inteira da API
    # (todo endpoint, todo schema de request/response) para qualquer
    # visitante não-autenticado -- útil em desenvolvimento, mas superfície
    # de ataque desnecessária num SOC em produção (facilita reconhecimento
    # por um atacante, e essas duas páginas eram justamente a única
    # exceção à CSP estrita deste projeto, ver
    # web/security_headers.py:_CAMINHOS_SEM_CSP, por dependerem de um CDN
    # externo). Desligadas (`None`) quando ENV=production; continuam
    # disponíveis em dev/teste para quem estiver explorando a API
    # manualmente.
    settings_dev = carregar_settings()
    # Fase E / E2 -- chamado ANTES de tudo (inclusive antes de instanciar
    # FastAPI()): um SENTINELA_LOG_FORMATO inválido derruba a aplicação
    # aqui, na construção, não silenciosamente na primeira linha de log ou
    # só quando o lifespan chamar settings.validar(). Ver
    # ARQUITETURA_OBSERVABILIDADE.md §1.7.
    configurar_logging(settings_dev.log_nivel, settings_dev.log_formato)
    # Fase E / E1 -- metadado estático exposto em /metrics
    # (sentinela_app_info), ver ARQUITETURA_OBSERVABILIDADE.md §2.2.
    definir_versao_aplicacao("8.3.0")
    app = FastAPI(
        title="Sentinela SOC",
        lifespan=_lifespan,
        docs_url=None if settings_dev.producao else "/docs",
        redoc_url=None if settings_dev.producao else "/redoc",
        openapi_url=None if settings_dev.producao else "/openapi.json",
    )

    # CORS só em desenvolvimento, só para o dev server do Vite (porta
    # separada do FastAPI localmente) -- em produção o React é servido pelo
    # próprio FastAPI (mesmo-origin), então CORS nem entra em jogo.
    if settings_dev.env == "development":
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[settings_dev.cors_dev_origin],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Item 18 do plano de endurecimento pós-auditoria -- CSP,
    # X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
    # Permissions-Policy e (só em produção) HSTS em toda resposta, ver
    # web/security_headers.py para o porquê de cada diretiva.
    app.add_middleware(CabecalhosDeSegurancaMiddleware, producao=settings_dev.producao)

    # Opcional (SENTINELA_ALLOWED_HOSTS vazio = desativado, preservando o
    # comportamento permissivo de antes para quem não configurar) -- sem
    # isso, `Request.base_url`/`Request.url` em qualquer rota são
    # derivados do cabeçalho `Host`, que o CLIENTE controla, não o
    # servidor. `SENTINELA_URL_BASE_PUBLICA` (ver services/redefinicao_senha.py)
    # já fecha o único uso disso hoje que ia parar num e-mail, mas isto
    # aqui é a segunda camada: rejeita a requisição inteira (400) antes de
    # qualquer rota rodar, caso um novo código no futuro volte a confiar
    # no Host sem essa ressalva.
    if settings_dev.allowed_hosts:
        hosts = [h.strip() for h in settings_dev.allowed_hosts.split(",") if h.strip()]
        if hosts:
            app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)

    # Adicionado por ÚLTIMO de propósito: `add_middleware` empilha o
    # middleware mais recente como o MAIS EXTERNO (primeiro a ver a
    # requisição) -- queremos o teto de tamanho de corpo envolvendo TUDO,
    # inclusive TrustedHost/CORS/cabeçalhos de segurança acima, para
    # rejeitar um corpo grande demais o mais cedo possível, antes de
    # QUALQUER outro processamento (ver web/limite_corpo.py).
    app.add_middleware(LimiteTamanhoCorpoMiddleware, max_bytes=settings_dev.max_corpo_requisicao_bytes)

    # Fase E / E2 -- adicionado por ÚLTIMO de propósito (mesmo raciocínio
    # do comentário acima): sendo o MAIS EXTERNO de todos, o middleware de
    # logging vê a requisição bruta primeiro e a resposta final por
    # último, capturando a duração e o status de QUALQUER rejeição feita
    # por um middleware mais interno (inclusive um 413 do
    # LimiteTamanhoCorpoMiddleware) -- nenhuma requisição fica de fora do
    # access log estruturado. Ver ARQUITETURA_OBSERVABILIDADE.md §1.4/§1.5.
    app.add_middleware(MiddlewareDeLogging, proxies_confiaveis=settings_dev.proxies_confiaveis)

    app.include_router(saude_router)
    app.include_router(metricas_router)
    app.include_router(api_v1_router, prefix="/api/v1")
    app.include_router(web_router)

    static_dir = os.path.join(os.path.dirname(__file__), "web", "static")
    app.mount("/static", StaticFiles(directory=static_dir), name="web-static")

    @app.exception_handler(RedirecionarParaLogin)
    async def _redirecionar_para_login(request: Request, exc: RedirecionarParaLogin):
        destino = f"/login?proxima={exc.proxima}" if exc.proxima and exc.proxima != "/" else "/login"
        return RedirectResponse(destino, status_code=303)

    @app.exception_handler(AcessoEmpresaSuspensaError)
    async def _acesso_empresa_suspensa(request: Request, exc: AcessoEmpresaSuspensaError):
        settings = request.app.state.settings
        resposta = RedirectResponse(f"/login?erro=empresa_{exc.status}", status_code=303)
        resposta.delete_cookie(NOME_COOKIE_SESSAO, path="/", samesite="lax", secure=settings.cookie_seguro)
        return resposta

    @app.exception_handler(SessaoInvalidaError)
    async def _sessao_invalida(request: Request, exc: SessaoInvalidaError):
        settings = request.app.state.settings
        resposta = RedirectResponse("/login?erro=sessao_invalida", status_code=303)
        resposta.delete_cookie(NOME_COOKIE_SESSAO, path="/", samesite="lax", secure=settings.cookie_seguro)
        return resposta

    @app.exception_handler(ValueError)
    async def _valor_invalido(request: Request, exc: ValueError):
        """
        Rede de segurança para qualquer `ValueError` de validação que escape
        de uma checagem explícita numa rota (ex.: um serviço que valide
        senha/email/status e ainda não tenha sido envolvido num try/except
        local) -- vira um 422 claro em vez de um 500 cru. `ValueError` é
        usado neste projeto especificamente para erros de validação de
        entrada (ver services/usuarios.py, services/empresas.py), nunca
        para bugs de programação, então mapear a exceção inteira para 422
        aqui é seguro e evita duplicar o mesmo try/except em toda rota.

        Item 16 do plano de endurecimento -- `mascarar_texto` aqui é defesa
        em profundidade: nenhuma mensagem de ValueError deste projeto
        interpola hoje um valor sensível, mas se uma passar a fazer isso no
        futuro (ex.: "senha 'abc123' muito curta"), pelo menos um Bearer/JWT
        solto no meio do texto já sai mascarado. Não cobre uma senha em
        texto claro dentro da frase (mascarar_texto só reconhece o FORMATO
        de token/JWT) -- por isso nenhuma mensagem de validação deste
        projeto deve ecoar o valor bruto recebido; ver comentário no handler
        de RequestValidationError abaixo, que é quem realmente fecha essa
        lacuna para os campos em CAMPOS_SENSIVEIS.
        """
        return JSONResponse(status_code=422, content={"detail": mascarar_texto(str(exc))})

    @app.exception_handler(RequestValidationError)
    async def _erro_de_validacao(request: Request, exc: RequestValidationError):
        """
        Item 16 do plano de endurecimento -- o handler PADRÃO do FastAPI/
        Pydantic ecoa o valor bruto submetido em cada erro de validação
        através da chave "input" de cada item de `exc.errors()`. Isso é uma
        fuga de segredo real: POST /api/v1/usuarios/me/senha (ou
        /api/v1/auth/redefinir-senha) com uma `senha_nova`/`senha_atual`
        que falhe uma validação (ex.: curta demais) devolvia a senha em
        texto claro no corpo da resposta 422 -- visível em qualquer log de
        acesso/proxy que grave o corpo da resposta, painel de erros do
        frontend, etc.

        Este handler substitui o padrão preservando a MESMA estrutura de
        resposta (`{"detail": [...]}`, mesmas chaves em cada item -- o
        frontend React que já lê `detail[].msg`/`loc` continua funcionando
        sem mudança), só que com "input" trocado por MASCARA sempre que o
        ÚLTIMO segmento de "loc" (o nome do campo, ex.: ("body",
        "senha_nova")) estiver em CAMPOS_SENSIVEIS (ver core/redacao.py).
        "loc" tem esse mesmo formato para corpo JSON, form data e
        querystring, então isto cobre os três.

        `jsonable_encoder` primeiro, igual o handler padrão do FastAPI usa
        internamente -- `exc.errors()` pode conter valores não serializáveis
        direto em JSON (ex.: `ctx` com uma exceção Python aninhada); só
        depois de virar dict/list/str "puros" é seguro mascarar e devolver.
        """
        erros = []
        for erro in jsonable_encoder(exc.errors()):
            loc = erro.get("loc") or ()
            campo = loc[-1] if loc else None
            if "input" in erro and campo_sensivel(campo):
                erro["input"] = MASCARA
            erros.append(erro)
        return JSONResponse(status_code=422, content={"detail": erros})

    _montar_react_se_existir(app)

    return app


def localizar_dist_frontend() -> str | None:
    """Pasta do build do React (frontend-react/dist), ou None se não existir.

    V8.2: antes só olhava três níveis acima deste arquivo (a estrutura do
    repositório: backend/sentinela/main.py -> raiz/frontend-react/dist). Na
    imagem Docker o backend fica em /app e o build em /app/frontend-react/dist,
    então o caminho calculado virava /frontend-react/dist e a interface /app
    NUNCA era servida em produção. Agora: SENTINELA_FRONTEND_DIST, depois a
    estrutura do repositório, depois a da imagem.
    """
    import os

    aqui = os.path.dirname(os.path.abspath(__file__))
    candidatos = [
        os.environ.get("SENTINELA_FRONTEND_DIST", ""),
        os.path.join(os.path.dirname(os.path.dirname(aqui)), "frontend-react", "dist"),
        os.path.join(os.path.dirname(aqui), "frontend-react", "dist"),
    ]
    for c in candidatos:
        if c and os.path.isfile(os.path.join(c, "index.html")):
            return c
    return None


def _montar_react_se_existir(app: FastAPI):
    """
    Monta o build do React (frontend-react/dist) em /app, se existir --
    ausente em dev antes do primeiro `npm run build`, presente na imagem
    Docker de produção (ver backend/Dockerfile, build multi-stage).
    """
    import os

    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles

    dist_dir = localizar_dist_frontend()
    if dist_dir is None:
        return
    assets_dir = os.path.join(dist_dir, "assets")
    index_path = os.path.join(dist_dir, "index.html")

    if os.path.isdir(assets_dir):
        app.mount("/app/assets", StaticFiles(directory=assets_dir), name="react-assets")

    # Arquivos de raiz do PWA (ver frontend-react/public/). Precisam ser
    # servidos COMO ARQUIVO, com o tipo certo: o fallback abaixo devolve o
    # index.html para qualquer caminho, e um manifest ou um service worker
    # que chega como text/html é recusado pelo navegador sem erro visível --
    # o app simplesmente não fica instalável.
    _ARQUIVOS_PWA = {
        "manifest.webmanifest": "application/manifest+json",
        "sw.js": "text/javascript",
        "icone-192.png": "image/png",
        "icone-512.png": "image/png",
        "icone-maskable.png": "image/png",
    }

    @app.get("/app/{full_path:path}")
    async def spa_fallback(full_path: str):
        tipo = _ARQUIVOS_PWA.get(full_path)
        if tipo is not None:
            caminho = os.path.join(dist_dir, full_path)
            if os.path.isfile(caminho):
                # O service worker não pode ser cacheado pelo navegador: é
                # ele quem controla a atualização de todo o resto, e uma
                # cópia velha em cache prende o app numa versão antiga.
                cabecalhos = {"Cache-Control": "no-cache"} if full_path == "sw.js" else {}
                return FileResponse(caminho, media_type=tipo, headers=cabecalhos)
        return FileResponse(index_path)


app = criar_app()
