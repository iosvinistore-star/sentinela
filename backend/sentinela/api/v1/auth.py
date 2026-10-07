# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Endpoints /api/v1/auth/* — login, logout, "quem sou eu", redefinição de senha, e (Fase C) o desafio de MFA/TOTP."""
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

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
from sentinela.db.pool import superadmin_scoped_connection, tenant_scoped_connection
from sentinela.services import mfa as servico_mfa
from sentinela.services import refresh_tokens as servico_refresh
from sentinela.services import redefinicao_senha as servico_redefinicao
from sentinela.util import obter_ip_cliente

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: str
    senha: str


class MfaVerificarRequest(BaseModel):
    pre_auth_token: str
    codigo: str | None = None
    recovery_code: str | None = None


class UsuarioSessao(BaseModel):
    id: str
    email: str
    papel: str
    empresa_id: str | None = None


class SolicitarRedefinicaoRequest(BaseModel):
    email: str


class ConfirmarRedefinicaoRequest(BaseModel):
    token: str
    # 72 bytes: limite físico do bcrypt (ver auth/security.py) -- validar
    # aqui evita que uma senha maior derrube hash_senha com um 500 (o
    # handler global de ValueError em main.py também cobriria isso, mas um
    # 422 de schema é mais barato e mais claro que deixar chegar ao serviço).
    senha_nova: str = Field(min_length=12, max_length=72)


def _refresh_cookie_kwargs(settings):
    return dict(key=NOME_COOKIE_REFRESH, httponly=True, secure=settings.cookie_seguro, samesite="lax", path="/api/v1/auth", max_age=servico_refresh.REFRESH_DIAS * 86400)


def _cookie_kwargs(settings):
    return dict(
        key=NOME_COOKIE_SESSAO,
        httponly=True,
        secure=settings.cookie_seguro,
        samesite="lax",
        path="/",
        max_age=settings.sessao_horas * 3600,
    )


def _montar_payload_sessao(credenciais: dict) -> dict:
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
    return payload


async def _registrar_evento_login(pool, *, empresa_id, usuario_id, acao: str, detalhes: dict):
    """
    Best-effort (nunca deve derrubar o fluxo de login por uma falha de
    auditoria). Usa `superadmin_scoped_connection` (BYPASSRLS) porque, no
    momento do login, ainda NÃO existe uma sessão/conexão tenant-scoped --
    autenticar-se É o que está sendo tentado. Mesmo padrão que
    `api/v1/admin.py` já usa para inserir em `usuarios` de uma empresa
    arbitrária a partir de uma sessão de superadmin.
    """
    try:
        from sentinela.services import auditoria as servico_auditoria

        async with superadmin_scoped_connection(pool) as conn:
            await servico_auditoria.registrar_evento(
                conn, empresa_id, acao, detalhes,
                ator_usuario_id=usuario_id if empresa_id else None,
                ator_superadmin_id=usuario_id if not empresa_id else None,
            )
    except Exception:
        pass


@router.post("/login")
async def login(dados: LoginRequest, request: Request, response: Response):
    settings = request.app.state.settings
    pool = request.app.state.pool
    limitador = request.app.state.limitador_login
    ip_cliente = obter_ip_cliente(request, settings.proxies_confiaveis)
    chave = f"login:{ip_cliente}"

    restante = await limitador.reservar_tentativa(chave)
    if restante > 0:
        raise HTTPException(
            status_code=429, detail=f"muitas tentativas -- tente de novo em {int(restante) + 1} segundos",
            headers={"Retry-After": str(int(restante) + 1)},
        )

    try:
        credenciais = await autenticar(pool, dados.email, dados.senha)
    except ContaEmpresaInativaError as exc:
        await limitador.registrar_sucesso(chave)  # senha certa -- não é força bruta
        raise HTTPException(status_code=403, detail=f"empresa {exc.status} -- acesso bloqueado")
    if credenciais is None:
        await _registrar_evento_login(
            pool, empresa_id=None, usuario_id=None, acao="LOGIN_FAILURE",
            detalhes={"email": dados.email.strip().lower(), "ip": ip_cliente},
        )
        raise HTTPException(status_code=401, detail="email ou senha inválidos")
    await limitador.registrar_sucesso(chave)

    payload = _montar_payload_sessao(credenciais)

    # Fase C (C6) -- senha válida NÃO basta se MFA está habilitado: emite
    # só um token intermediário de curta duração, sem cookie de sessão
    # nenhum ainda. O front-end chama /auth/mfa/verificar com este token
    # + o código TOTP (ou um recovery code) para completar o login.
    if credenciais.get("mfa_habilitado"):
        pre_auth_payload = {**payload, "purpose": PROPOSITO_PRE_AUTH_MFA}
        pre_auth_token = emitir_token_sessao(
            pre_auth_payload, settings.jwt_secret, PRE_AUTH_MFA_TTL_SEGUNDOS / 3600,
        )
        return {"mfa_necessario": True, "pre_auth_token": pre_auth_token}

    token = emitir_token_sessao(payload, settings.jwt_secret, settings.sessao_horas)
    response.set_cookie(value=token, **_cookie_kwargs(settings))
    async with superadmin_scoped_connection(pool) as conn_refresh:
        refresh, _ = await servico_refresh.criar(conn_refresh, credenciais["tipo"], credenciais["id"], credenciais["token_version"])
    response.set_cookie(value=refresh, **_refresh_cookie_kwargs(settings))
    await _registrar_evento_login(
        pool, empresa_id=payload["empresa_id"], usuario_id=payload["sub"], acao="LOGIN_SUCCESS",
        detalhes={"email": payload["email"], "ip": ip_cliente},
    )

    return {"usuario": {**payload, "id": payload["sub"]}}


@router.post("/mfa/verificar")
async def mfa_verificar(dados: MfaVerificarRequest, request: Request, response: Response):
    """
    Segundo passo do login quando `/auth/login` devolveu `mfa_necessario`.
    Recebe o `pre_auth_token` (nunca um cookie -- ver `usuario_atual`, que
    recusa explicitamente qualquer token com a claim "purpose") mais um
    código TOTP OU um recovery code, e só então emite a sessão completa.
    """
    settings = request.app.state.settings
    pool = request.app.state.pool

    try:
        pre_auth = decodificar_token_sessao(dados.pre_auth_token, settings.jwt_secret)
    except Exception:
        raise HTTPException(status_code=401, detail="token de pré-autenticação inválido ou expirado")
    if pre_auth.get("purpose") != PROPOSITO_PRE_AUTH_MFA:
        raise HTTPException(status_code=401, detail="token de pré-autenticação inválido")

    usuario_id = pre_auth["sub"]
    empresa_id = pre_auth.get("empresa_id")

    limitador = request.app.state.limitador_mfa
    chave = f"mfa-login:{usuario_id}"
    restante = await limitador.reservar_tentativa(chave)
    if restante > 0:
        raise HTTPException(
            status_code=429, detail=f"muitas tentativas -- tente de novo em {int(restante) + 1} segundos",
            headers={"Retry-After": str(int(restante) + 1)},
        )

    if pre_auth.get("papel") == "superadmin":
        async with superadmin_scoped_connection(pool) as conn:
            ok = await servico_mfa.verificar_no_login_superadmin(
                conn, settings.mfa_encryption_key, usuario_id, codigo=dados.codigo, recovery_code=dados.recovery_code,
            )
    else:
        async with tenant_scoped_connection(pool, empresa_id) as conn:
            ok = await servico_mfa.verificar_no_login(
                conn, settings.mfa_encryption_key, empresa_id, usuario_id, codigo=dados.codigo, recovery_code=dados.recovery_code,
            )
    if not ok:
        raise HTTPException(status_code=401, detail="código ou recovery code inválido")
    await limitador.registrar_sucesso(chave)

    payload = {k: v for k, v in pre_auth.items() if k not in ("purpose", "iat", "exp")}
    token = emitir_token_sessao(payload, settings.jwt_secret, settings.sessao_horas)
    response.set_cookie(value=token, **_cookie_kwargs(settings))
    async with superadmin_scoped_connection(pool) as conn_refresh:
        refresh, _ = await servico_refresh.criar(conn_refresh, "superadmin" if payload.get("papel") == "superadmin" else "usuario", payload["sub"], payload["tv"])
    response.set_cookie(value=refresh, **_refresh_cookie_kwargs(settings))
    await _registrar_evento_login(
        pool, empresa_id=payload["empresa_id"], usuario_id=payload["sub"], acao="LOGIN_SUCCESS",
        detalhes={"email": payload["email"], "mfa": True},
    )
    return {"usuario": {**payload, "id": payload["sub"]}}


@router.post("/refresh", dependencies=[Depends(exigir_csrf_header)])
async def refresh(request: Request, response: Response):
    settings = request.app.state.settings
    pool = request.app.state.pool
    token = request.cookies.get(NOME_COOKIE_REFRESH)
    if not token:
        raise HTTPException(status_code=401, detail="refresh token ausente")
    async with superadmin_scoped_connection(pool) as conn:
        resultado, erro = await servico_refresh.rotacionar(conn, token)
        if erro:
            raise HTTPException(status_code=401, detail="refresh token inválido, expirado ou reutilizado")
        if resultado["conta_tipo"] == "superadmin":
            row = await conn.fetchrow("SELECT id,email,papel,token_version,mfa_habilitado FROM superadmins WHERE id=$1", resultado["conta_id"])
            if row is None or row["token_version"] != resultado["token_version"]:
                raise HTTPException(status_code=401, detail="sessão inválida")
            payload={"sub":str(row["id"]),"empresa_id":None,"papel":"superadmin","email":row["email"],"tv":row["token_version"],"papel_saas":row["papel"]}
        else:
            row = await conn.fetchrow("SELECT id,empresa_id,email,papel,token_version,ativo FROM usuarios WHERE id=$1", resultado["conta_id"])
            if row is None or not row["ativo"] or row["token_version"] != resultado["token_version"]:
                raise HTTPException(status_code=401, detail="sessão inválida")
            payload={"sub":str(row["id"]),"empresa_id":str(row["empresa_id"]),"papel":row["papel"],"email":row["email"],"tv":row["token_version"]}
        access=emitir_token_sessao(payload, settings.jwt_secret, settings.sessao_horas)
        response.set_cookie(value=access, **_cookie_kwargs(settings))
        response.set_cookie(value=resultado["novo_token"], **_refresh_cookie_kwargs(settings))
        return {"ok":True,"usuario":{**payload,"id":payload["sub"]}}


@router.post("/logout", dependencies=[Depends(exigir_csrf_header)])
async def logout(request: Request, response: Response):
    settings = request.app.state.settings
    response.delete_cookie(NOME_COOKIE_SESSAO, path="/", samesite="lax", secure=settings.cookie_seguro)
    response.delete_cookie(NOME_COOKIE_REFRESH, path="/api/v1/auth", samesite="lax", secure=settings.cookie_seguro)
    return {"ok": True}


@router.get("/me")
async def me(usuario: dict | None = Depends(usuario_atual)):
    if usuario is None:
        raise HTTPException(status_code=401, detail="não autenticado")
    return {
        "usuario": {
            "id": usuario["sub"],
            "email": usuario["email"],
            "papel": usuario["papel"],
            "empresa_id": usuario.get("empresa_id"),
            # Fase C -- só presente para superadmins (ver auth/rbac.py).
            "papel_saas": usuario.get("papel_saas"),
        }
    }


@router.post("/esqueci-senha", dependencies=[Depends(exigir_csrf_header)])
async def esqueci_senha(dados: SolicitarRedefinicaoRequest, request: Request):
    """
    Sempre 200 com a mesma mensagem, o email exista ou não (ver
    services/redefinicao_senha.py -- evita enumeração de contas). Passa
    pelo mesmo limitador do login, em namespace separado, pra não virar um
    jeito grátis de floodar a caixa de entrada de alguém.
    """
    limitador = request.app.state.limitador_login
    chave = f"esqueci-senha:{obter_ip_cliente(request, request.app.state.settings.proxies_confiaveis)}"
    restante = await limitador.reservar_tentativa(chave)
    if restante > 0:
        raise HTTPException(
            status_code=429, detail=f"muitas tentativas -- tente de novo em {int(restante) + 1} segundos",
            headers={"Retry-After": str(int(restante) + 1)},
        )

    pool = request.app.state.pool
    # Prefere a URL pública fixa (SENTINELA_URL_BASE_PUBLICA) -- só cai para
    # `request.base_url` (derivado do cabeçalho Host, controlado pelo
    # cliente) quando ela não está configurada, o que só acontece fora de
    # produção (ver Settings.validar() em config.py). Ver o comentário do
    # campo `url_base_publica` para o porquê disto ser necessário.
    url_base = request.app.state.settings.url_base_publica or str(request.base_url)
    await servico_redefinicao.solicitar_redefinicao(pool, dados.email, url_base)
    return {"ok": True}


@router.post("/redefinir-senha", dependencies=[Depends(exigir_csrf_header)])
async def redefinir_senha(dados: ConfirmarRedefinicaoRequest, request: Request):
    pool = request.app.state.pool
    ok = await servico_redefinicao.confirmar_redefinicao(pool, dados.token, dados.senha_nova)
    if not ok:
        raise HTTPException(status_code=400, detail="link inválido ou expirado")
    return {"ok": True}
