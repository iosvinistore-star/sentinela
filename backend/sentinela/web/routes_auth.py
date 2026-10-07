# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""GET/POST /login, POST /logout, GET / -- rotas HTML de autenticação.

/login é um <form method="post"> comum, sem HTMX/JS -- funciona mesmo com
JavaScript desabilitado, e evita o problema do "ovo e galinha" do CSRF por
header (não há sessão ainda para carregar um `hx-headers`). Ver a isenção
correspondente em `auth/dependencies.ROTAS_ISENTAS_DE_CSRF`.
"""
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from sentinela.auth.dependencies import (
    NOME_COOKIE_SESSAO,
    NOME_COOKIE_REFRESH,
    PRE_AUTH_MFA_TTL_SEGUNDOS,
    PROPOSITO_PRE_AUTH_MFA,
    exigir_csrf_header,
    usuario_atual,
)
from sentinela.auth.login import ContaEmpresaInativaError, autenticar
from sentinela.auth.security import decodificar_token_sessao, emitir_token_sessao
from sentinela.db.pool import tenant_scoped_connection, superadmin_scoped_connection
from sentinela.services import mfa as servico_mfa
from sentinela.services import refresh_tokens as servico_refresh
from sentinela.services import redefinicao_senha as servico_redefinicao
from sentinela.util import obter_ip_cliente
from sentinela.web.deps import templates

router = APIRouter()


def _destino_seguro(proxima: str | None) -> str:
    r"""
    Aceita somente caminhos locais absolutos; bloqueia open redirect via
    URL "protocol-relative" (//evil.example) -- e a variante com barra
    invertida (/\\evil.example), que `startswith("//")` sozinho NÃO
    pegava. Todo navegador (é uma regra do próprio WHATWG URL Standard,
    não um bug de navegador específico) trata `\\` como equivalente a `/`
    ao interpretar uma URL de esquema "especial" como http/https -- então
    `/\\evil.example` é resolvido exatamente como `//evil.example` (um
    redirect pra OUTRO host), mesmo sem começar com duas barras de verdade.
    Normalizar antes de checar fecha as duas variantes (e combinações
    tipo `/\/evil.example`) de uma vez.
    """
    if not proxima or not proxima.startswith("/"):
        return "/"
    if proxima.replace("\\", "/").startswith("//"):
        return "/"
    return proxima


def _refresh_cookie_kwargs(settings):
    return dict(key=NOME_COOKIE_REFRESH, httponly=True, secure=settings.cookie_seguro, samesite="lax", path="/api/v1/auth", max_age=servico_refresh.REFRESH_DIAS * 86400)


def _cookie_kwargs(settings):
    return dict(
        key=NOME_COOKIE_SESSAO, httponly=True, secure=settings.cookie_seguro,
        samesite="lax", path="/", max_age=settings.sessao_horas * 3600,
    )


@router.get("/")
async def raiz(usuario: dict | None = Depends(usuario_atual)):
    if usuario is None:
        return RedirectResponse("/login", status_code=303)
    if usuario.get("papel") == "superadmin":
        return RedirectResponse("/admin/empresas", status_code=303)
    return RedirectResponse("/incidentes", status_code=303)


@router.get("/login")
async def formulario_login(request: Request, proxima: str = "/", erro: str | None = None,
                             usuario: dict | None = Depends(usuario_atual)):
    if usuario is not None:
        return RedirectResponse("/", status_code=303)
    mensagem_erro = None
    if erro and erro.startswith("empresa_"):
        # Ver web/deps.py:AcessoEmpresaSuspensaError -- sessão válida
        # derrubada porque a empresa foi suspensa/cancelada DEPOIS do login.
        status = erro.split("_", 1)[1]
        mensagem_erro = f"Sua sessão foi encerrada porque a empresa está {status}. Contate o administrador."
    elif erro == "sessao_invalida":
        # Ver web/deps.py:SessaoInvalidaError -- sessão válida derrubada
        # porque o usuário foi desativado ou teve o papel alterado DEPOIS
        # do login. Mensagem genérica de propósito: não precisa (nem
        # deveria) dizer qual dos dois foi.
        mensagem_erro = "Sua sessão foi encerrada. Faça login novamente."
    return templates.TemplateResponse(
        request, "login.html", {"usuario": None, "erro": mensagem_erro, "proxima": proxima}
    )


@router.post("/login")
async def submeter_login(request: Request, email: str = Form(...), senha: str = Form(...), proxima: str = Form("/")):
    settings = request.app.state.settings
    pool = request.app.state.pool
    limitador = request.app.state.limitador_login
    chave = f"login:{obter_ip_cliente(request, request.app.state.settings.proxies_confiaveis)}"

    restante = await limitador.reservar_tentativa(chave)
    if restante > 0:
        return templates.TemplateResponse(
            request, "login.html",
            {"usuario": None, "erro": f"Muitas tentativas. Tente de novo em {int(restante) + 1} segundos.", "proxima": proxima},
            status_code=429,
        )

    try:
        credenciais = await autenticar(pool, email, senha)
    except ContaEmpresaInativaError as exc:
        await limitador.registrar_sucesso(chave)  # senha certa -- não é força bruta
        return templates.TemplateResponse(
            request, "login.html",
            {"usuario": None, "erro": f"Sua empresa está {exc.status}. Contate o administrador.", "proxima": proxima},
            status_code=403,
        )
    if credenciais is None:
        return templates.TemplateResponse(
            request, "login.html",
            {"usuario": None, "erro": "Email ou senha inválidos.", "proxima": proxima},
            status_code=401,
        )
    await limitador.registrar_sucesso(chave)

    payload = {
        "sub": str(credenciais["id"]),
        "empresa_id": str(credenciais["empresa_id"]) if credenciais["empresa_id"] else None,
        "papel": credenciais["papel"],
        "email": credenciais["email"],
    }
    # "tv" (token_version) -- ver auth/dependencies.py:conexao_tenant/
    # conexao_superadmin e migrations/0011_token_version.sql/
    # 0013_token_version_superadmin.sql. Presente para os dois tipos de
    # conta: permite revogar QUALQUER sessão (usuário de empresa OU
    # superadmin) antes da expiração natural do cookie.
    payload["tv"] = credenciais["token_version"]
    # Fase C -- "papel_saas" (ver auth/rbac.py e auth/login.py): claim
    # nova e aditiva, presente só para sessões de superadmin.
    if "papel_saas" in credenciais:
        payload["papel_saas"] = credenciais["papel_saas"]

    # Fase C (C6) -- ver api/v1/auth.py:login para a mesma lógica do lado
    # API. Em vez de um cookie de sessão completo, mostra um formulário
    # HTML pedindo o código TOTP/recovery, carregando o token
    # intermediário num campo hidden (nunca num cookie -- `usuario_atual`
    # recusa explicitamente qualquer token com a claim "purpose").
    if credenciais.get("mfa_habilitado"):
        pre_auth_payload = {**payload, "purpose": PROPOSITO_PRE_AUTH_MFA}
        pre_auth_token = emitir_token_sessao(
            pre_auth_payload, settings.jwt_secret, PRE_AUTH_MFA_TTL_SEGUNDOS / 3600,
        )
        return templates.TemplateResponse(
            request, "mfa_login.html",
            {"usuario": None, "erro": None, "proxima": proxima, "pre_auth_token": pre_auth_token},
        )

    token = emitir_token_sessao(payload, settings.jwt_secret, settings.sessao_horas)

    destino = _destino_seguro(proxima)
    if destino == "/login":
        destino = "/"
    resposta = RedirectResponse(destino, status_code=303)
    resposta.set_cookie(value=token, **_cookie_kwargs(settings))
    async with superadmin_scoped_connection(pool) as conn_refresh:
        refresh, _ = await servico_refresh.criar(conn_refresh, credenciais["tipo"], credenciais["id"], credenciais["token_version"])
    resposta.set_cookie(value=refresh, **_refresh_cookie_kwargs(settings))
    return resposta


@router.post("/login/mfa", dependencies=[Depends(exigir_csrf_header)])
async def submeter_mfa_login(
    request: Request,
    pre_auth_token: str = Form(...),
    codigo: str = Form(""),
    recovery_code: str = Form(""),
    proxima: str = Form("/"),
):
    """Segundo passo do login HTMX quando `submeter_login` devolveu o
    formulário de MFA -- ver docstring de `mfa_verificar` (api/v1/auth.py)
    para o mesmo raciocínio de segurança do token intermediário."""
    settings = request.app.state.settings
    pool = request.app.state.pool

    try:
        pre_auth = decodificar_token_sessao(pre_auth_token, settings.jwt_secret)
    except Exception:
        return templates.TemplateResponse(
            request, "mfa_login.html",
            {"usuario": None, "erro": "Sessão de login expirada. Faça login novamente.",
             "proxima": proxima, "pre_auth_token": None},
            status_code=401,
        )
    if pre_auth.get("purpose") != PROPOSITO_PRE_AUTH_MFA:
        return RedirectResponse("/login", status_code=303)

    usuario_id = pre_auth["sub"]
    empresa_id = pre_auth.get("empresa_id")

    limitador = request.app.state.limitador_mfa
    chave = f"mfa-login:{usuario_id}"
    restante = await limitador.reservar_tentativa(chave)
    if restante > 0:
        return templates.TemplateResponse(
            request, "mfa_login.html",
            {"usuario": None, "erro": f"Muitas tentativas. Tente de novo em {int(restante) + 1} segundos.",
             "proxima": proxima, "pre_auth_token": pre_auth_token},
            status_code=429,
        )

    if pre_auth.get("papel") == "superadmin":
        async with superadmin_scoped_connection(pool) as conn:
            ok = await servico_mfa.verificar_no_login_superadmin(
                conn, settings.mfa_encryption_key, usuario_id, codigo=codigo or None, recovery_code=recovery_code or None,
            )
    else:
        async with tenant_scoped_connection(pool, empresa_id) as conn:
            ok = await servico_mfa.verificar_no_login(
                conn, settings.mfa_encryption_key, empresa_id, usuario_id, codigo=codigo or None, recovery_code=recovery_code or None,
            )
    if not ok:
        return templates.TemplateResponse(
            request, "mfa_login.html",
            {"usuario": None, "erro": "Código inválido.", "proxima": proxima, "pre_auth_token": pre_auth_token},
            status_code=401,
        )
    await limitador.registrar_sucesso(chave)

    payload = {k: v for k, v in pre_auth.items() if k not in ("purpose", "iat", "exp")}
    token = emitir_token_sessao(payload, settings.jwt_secret, settings.sessao_horas)

    destino = _destino_seguro(proxima)
    if destino == "/login":
        destino = "/"
    resposta = RedirectResponse(destino, status_code=303)
    resposta.set_cookie(value=token, **_cookie_kwargs(settings))
    async with superadmin_scoped_connection(pool) as conn_refresh:
        refresh, _ = await servico_refresh.criar(conn_refresh, "superadmin" if payload.get("papel") == "superadmin" else "usuario", payload["sub"], payload["tv"])
    resposta.set_cookie(value=refresh, **_refresh_cookie_kwargs(settings))
    return resposta


@router.post("/logout", dependencies=[Depends(exigir_csrf_header)])
async def logout(request: Request):
    settings = request.app.state.settings
    resposta = RedirectResponse("/login", status_code=303)
    # HX-Redirect faz o htmx trocar a página inteira (window.location), em
    # vez de tentar dar swap na resposta dentro do hx-target do botão --
    # é o padrão certo do htmx pra "essa ação termina a sessão, recarregue
    # tudo", ao contrário de um swap parcial.
    resposta.headers["HX-Redirect"] = "/login"
    resposta.delete_cookie(NOME_COOKIE_SESSAO, path="/", samesite="lax", secure=settings.cookie_seguro)
    resposta.delete_cookie(NOME_COOKIE_REFRESH, path="/api/v1/auth", samesite="lax", secure=settings.cookie_seguro)
    return resposta


@router.get("/esqueci-senha")
async def formulario_esqueci_senha(request: Request):
    return templates.TemplateResponse(request, "esqueci_senha.html", {"usuario": None, "enviado": False})


@router.post("/esqueci-senha", dependencies=[Depends(exigir_csrf_header)])
async def submeter_esqueci_senha(request: Request, email: str = Form(...)):
    """
    Mesma resposta sempre (200, "enviado"), o email exista ou não -- ver
    services/redefinicao_senha.py. Também passa pelo limitador (mesma
    chave, mas namespace separado do login) pra não virar um jeito grátis
    de floodar a caixa de entrada de alguém com pedidos de reset.
    """
    limitador = request.app.state.limitador_login
    chave = f"esqueci-senha:{obter_ip_cliente(request, request.app.state.settings.proxies_confiaveis)}"
    restante = await limitador.reservar_tentativa(chave)  # conta como "uso", não como falha de senha -- só limita frequência
    if restante > 0:
        # 200, não 429: desde que este formulário virou hx-post (para poder
        # exigir o header CSRF -- ver routes_usuarios.py:criar para o mesmo
        # padrão), o htmx por padrão só faz swap em respostas 2xx. Um 429
        # aqui faria o clique no botão parecer que não fez nada, sem
        # mostrar a mensagem de "muitas tentativas" pro usuário.
        return templates.TemplateResponse(
            request, "esqueci_senha.html",
            {"usuario": None, "enviado": False, "erro": f"Muitas tentativas. Tente de novo em {int(restante) + 1} segundos."},
        )

    pool = request.app.state.pool
    # Mesma lógica de api/v1/auth.py:esqueci_senha -- prefere a URL pública
    # fixa, só cai para o Host (client-controlled) fora de produção.
    url_base = request.app.state.settings.url_base_publica or str(request.base_url)
    await servico_redefinicao.solicitar_redefinicao(pool, email, url_base)
    return templates.TemplateResponse(request, "esqueci_senha.html", {"usuario": None, "enviado": True})


@router.get("/redefinir-senha")
async def formulario_redefinir_senha(request: Request, token: str = ""):
    return templates.TemplateResponse(
        request, "redefinir_senha.html", {"usuario": None, "token": token, "erro": None, "sucesso": False}
    )


@router.post("/redefinir-senha", dependencies=[Depends(exigir_csrf_header)])
async def submeter_redefinir_senha(request: Request, token: str = Form(...), senha_nova: str = Form(...)):
    # Todo retorno de erro aqui é 200 (não 422/400): este formulário é
    # hx-post (precisa ser, para poder exigir o header CSRF -- ver
    # esqueci_senha.html) e o htmx só faz swap em respostas 2xx por padrão;
    # um status de erro faria a mensagem nunca aparecer no navegador. Ver o
    # mesmo padrão, com o mesmo motivo, em routes_usuarios.py:criar. A API
    # JSON (api/v1/auth.py) continua devolvendo 400/422 de verdade -- quem
    # consome ali é código (React), não uma troca de HTML no navegador.
    if len(senha_nova) < 12:
        return templates.TemplateResponse(
            request, "redefinir_senha.html",
            {"usuario": None, "token": token, "erro": "A senha precisa ter pelo menos 12 caracteres.", "sucesso": False},
        )
    if len(senha_nova.encode("utf-8")) > 72:
        return templates.TemplateResponse(
            request, "redefinir_senha.html",
            {"usuario": None, "token": token, "erro": "A senha não pode ter mais de 72 caracteres.", "sucesso": False},
        )
    pool = request.app.state.pool
    ok = await servico_redefinicao.confirmar_redefinicao(pool, token, senha_nova)
    if not ok:
        return templates.TemplateResponse(
            request, "redefinir_senha.html",
            {"usuario": None, "token": token, "erro": "Link inválido ou expirado. Solicite um novo.", "sucesso": False},
        )
    return templates.TemplateResponse(
        request, "redefinir_senha.html", {"usuario": None, "token": token, "erro": None, "sucesso": True}
    )
