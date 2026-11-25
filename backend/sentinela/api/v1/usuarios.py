# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
/api/v1/usuarios -- gestão dos usuários da PRÓPRIA empresa (admin-only,
exceto a troca da própria senha, que qualquer usuário logado pode fazer).
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from sentinela.auth.dependencies import NOME_COOKIE_SESSAO, conexao_tenant, exigir_csrf_header, exigir_login, exigir_papel
from sentinela.auth.rbac import PERM_MFA_RESET_OTHERS, exigir_permissao, validar_troca_de_papel_nao_e_autopromocao
from sentinela.auth.security import emitir_token_sessao
from sentinela.services import mfa as servico_mfa
from sentinela.services import usuarios as servico

router = APIRouter(prefix="/usuarios", tags=["usuarios"])

# Fase C -- "viewer" adicionado (RBAC, ver auth/rbac.py) -- usuário
# read-only, sem nenhuma permissão de escrita (ver ROLE_PERMISSIONS).
_PAPEIS_VALIDOS = {"admin", "analista", "viewer"}
# 72 bytes: limite físico do bcrypt (ver auth/security.py e
# services/usuarios.py:_validar_senha, que faz a checagem autoritativa em
# BYTES -- este max_length em caracteres é só a primeira linha de defesa).
_SENHA_MAX_LENGTH = 72


class CriarUsuarioRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    papel: str
    senha: str = Field(min_length=12, max_length=_SENHA_MAX_LENGTH)


class AtualizarUsuarioRequest(BaseModel):
    papel: str | None = None
    ativo: bool | None = None


class TrocarSenhaRequest(BaseModel):
    senha_atual: str
    senha_nova: str = Field(min_length=12, max_length=_SENHA_MAX_LENGTH)


class ConfirmarMfaRequest(BaseModel):
    codigo: str = Field(min_length=6, max_length=6)


class DesativarMfaRequest(BaseModel):
    """Exige PROVA de posse do segundo fator para desativar (TOTP ou um
    recovery code) -- nunca só a senha, que já foi comprometida em muitos
    dos cenários que o MFA existe para mitigar. Perder o autenticador E os
    recovery codes ao mesmo tempo é o caso do reset administrativo (C8),
    não deste endpoint de self-service."""
    codigo: str | None = None
    recovery_code: str | None = None


@router.get("")
async def listar_usuarios(usuario: dict = Depends(exigir_papel("admin")), sessao=Depends(conexao_tenant)):
    return {"usuarios": await servico.listar_usuarios(sessao)}


@router.post("", dependencies=[Depends(exigir_csrf_header)])
async def criar_usuario(dados: CriarUsuarioRequest, usuario: dict = Depends(exigir_papel("admin")),
                          sessao=Depends(conexao_tenant)):
    if dados.papel not in _PAPEIS_VALIDOS:
        raise HTTPException(status_code=422, detail=f"papel inválido -- use um de {sorted(_PAPEIS_VALIDOS)}")
    try:
        criado = await servico.criar_usuario(
            sessao, usuario["empresa_id"], dados.email, dados.papel, dados.senha, ator_usuario_id=usuario["sub"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if criado is None:
        raise HTTPException(status_code=409, detail="já existe um usuário com este email")
    return {"usuario": criado}


@router.patch("/me/senha", dependencies=[Depends(exigir_csrf_header)])
async def trocar_propria_senha(dados: TrocarSenhaRequest, request: Request, response: Response,
                                 usuario: dict = Depends(exigir_login), sessao=Depends(conexao_tenant)):
    limitador = request.app.state.limitador_login
    # Chave por USUÁRIO (não por IP): quem já tem uma sessão válida deste
    # usuário pode estar em qualquer IP (cookie sequestrado) -- o que se
    # quer limitar é quantas vezes alguém pode tentar adivinhar a senha
    # ATUAL deste usuário específico, não tentativas de login por origem.
    chave = f"trocar-senha:{usuario['sub']}"
    restante = await limitador.reservar_tentativa(chave)
    if restante > 0:
        raise HTTPException(
            status_code=429, detail=f"muitas tentativas -- tente de novo em {int(restante) + 1} segundos",
            headers={"Retry-After": str(int(restante) + 1)},
        )
    novo_tv = await servico.trocar_propria_senha(sessao, usuario["sub"], dados.senha_atual, dados.senha_nova)
    if novo_tv is None:
        raise HTTPException(status_code=401, detail="senha atual incorreta")
    await limitador.registrar_sucesso(chave)
    # Reemite o cookie de sessão com o token_version novo -- senão a troca
    # de senha derrubaria a PRÓPRIA sessão que a fez na próxima requisição
    # (ver services/usuarios.py:trocar_propria_senha e
    # auth/dependencies.py:conexao_tenant, que comparam "tv" contra o
    # banco a cada requisição). Sessões em QUALQUER OUTRO dispositivo
    # continuam com o "tv" antigo -- essas, sim, são derrubadas.
    settings = request.app.state.settings
    payload_novo = {
        "sub": usuario["sub"], "empresa_id": usuario.get("empresa_id"),
        "papel": usuario["papel"], "email": usuario["email"], "tv": novo_tv,
    }
    token = emitir_token_sessao(payload_novo, settings.jwt_secret, settings.sessao_horas)
    response.set_cookie(
        key=NOME_COOKIE_SESSAO, value=token, httponly=True, secure=settings.cookie_seguro,
        samesite="lax", path="/", max_age=settings.sessao_horas * 3600,
    )
    return {"ok": True}


@router.patch("/{usuario_id}", dependencies=[Depends(exigir_csrf_header)])
async def atualizar_usuario(
    # uuid.UUID (não str): antes, um path param não-UUID (ex.:
    # "/usuarios/abc") chegava intacto na query SQL e virava um
    # `asyncpg.DataError` cru (não é subclasse de ValueError -- não cai no
    # handler genérico de main.py) -- 500 em vez de um 422 claro. Tipar
    # aqui faz o FastAPI validar o formato antes mesmo de a rota rodar.
    usuario_id: uuid.UUID,
    dados: AtualizarUsuarioRequest,
    usuario: dict = Depends(exigir_papel("admin")), sessao=Depends(conexao_tenant),
):
    if dados.papel is not None and dados.papel not in _PAPEIS_VALIDOS:
        raise HTTPException(status_code=422, detail=f"papel inválido -- use um de {sorted(_PAPEIS_VALIDOS)}")
    # Fase C / C11 -- proteção contra escalação de privilégio: um usuário
    # NUNCA pode alterar o próprio papel, nem através desta rota
    # administrativa (mesmo sendo admin). Ver auth/rbac.py.
    if dados.papel is not None:
        validar_troca_de_papel_nao_e_autopromocao(usuario, str(usuario_id))
    atualizado = await servico.atualizar_usuario(
        sessao, usuario["empresa_id"], str(usuario_id), papel=dados.papel, ativo=dados.ativo,
        ator_usuario_id=usuario["sub"],
    )
    if atualizado is None:
        raise HTTPException(status_code=404, detail="usuário não encontrado")
    return {"usuario": atualizado}


# ---------------------------------------------------------------------------
# Fase C -- MFA/TOTP self-service (C6/C7). Qualquer usuário logado (admin,
# analista OU viewer) pode gerir o PRÓPRIO MFA -- não é uma "permissão"
# RBAC, é uma capacidade de self-service disponível a qualquer sessão
# autenticada, do mesmo jeito que `trocar_propria_senha` acima já é.
# ---------------------------------------------------------------------------

def _chave_limitador_mfa(usuario_id) -> str:
    return f"mfa:{usuario_id}"


async def _aplicar_limite_mfa(request: Request, usuario_id):
    limitador = request.app.state.limitador_mfa
    chave = _chave_limitador_mfa(usuario_id)
    restante = await limitador.reservar_tentativa(chave)
    if restante > 0:
        raise HTTPException(
            status_code=429, detail=f"muitas tentativas -- tente de novo em {int(restante) + 1} segundos",
            headers={"Retry-After": str(int(restante) + 1)},
        )
    return limitador, chave


@router.get("/me/mfa/status")
async def status_mfa(usuario: dict = Depends(exigir_login), sessao=Depends(conexao_tenant)):
    return await servico_mfa.obter_status_mfa(sessao, usuario["sub"])


@router.post("/me/mfa/setup", dependencies=[Depends(exigir_csrf_header)])
async def iniciar_mfa(usuario: dict = Depends(exigir_login), sessao=Depends(conexao_tenant), request: Request = None):
    """
    Gera um segredo TOTP novo (ainda NÃO ativa MFA -- ver
    services/mfa.py:iniciar_configuracao) e devolve a URI de provisionamento
    para o front-end desenhar o QR Code, mais o segredo em texto para
    digitação manual como alternativa. Chamar de novo antes de confirmar
    simplesmente substitui o segredo pendente (seguro -- nada foi ativado
    ainda).
    """
    settings = request.app.state.settings
    try:
        resultado = await servico_mfa.iniciar_configuracao(sessao, settings.mfa_encryption_key, usuario["sub"], usuario["email"])
    except servico_mfa.MfaJaHabilitadoError:
        raise HTTPException(status_code=409, detail="MFA já está ativado -- desative antes de reconfigurar")
    return resultado


@router.post("/me/mfa/confirmar", dependencies=[Depends(exigir_csrf_header)])
async def confirmar_mfa(dados: ConfirmarMfaRequest, usuario: dict = Depends(exigir_login),
                          sessao=Depends(conexao_tenant), request: Request = None):
    """Devolve os recovery codes em CLARO -- única vez que isto acontece (C7).
    O front-end deve exibi-los uma vez e orientar o usuário a salvá-los com segurança."""
    limitador, chave = await _aplicar_limite_mfa(request, usuario["sub"])
    settings = request.app.state.settings
    try:
        codigos = await servico_mfa.confirmar_configuracao(
            sessao, settings.mfa_encryption_key, usuario["empresa_id"], usuario["sub"], dados.codigo,
        )
    except servico_mfa.MfaNaoConfiguradoError:
        raise HTTPException(status_code=400, detail="nenhuma configuração de MFA pendente -- inicie o setup primeiro")
    except servico_mfa.MfaJaHabilitadoError:
        raise HTTPException(status_code=409, detail="MFA já está ativado")
    except servico_mfa.CodigoInvalidoError:
        raise HTTPException(status_code=401, detail="código inválido")
    await limitador.registrar_sucesso(chave)
    return {"recovery_codes": codigos}


@router.post("/me/mfa/desativar", dependencies=[Depends(exigir_csrf_header)])
async def desativar_mfa(dados: DesativarMfaRequest, usuario: dict = Depends(exigir_login),
                          sessao=Depends(conexao_tenant), request: Request = None):
    limitador, chave = await _aplicar_limite_mfa(request, usuario["sub"])
    ok = await servico_mfa.verificar_no_login(
        sessao, request.app.state.settings.mfa_encryption_key, usuario["empresa_id"], usuario["sub"],
        codigo=dados.codigo, recovery_code=dados.recovery_code,
    )
    if not ok:
        raise HTTPException(status_code=401, detail="código ou recovery code inválido")
    await limitador.registrar_sucesso(chave)
    await servico_mfa.desativar(sessao, usuario["empresa_id"], usuario["sub"], ator_usuario_id=usuario["sub"])
    return {"ok": True}


@router.post("/me/mfa/recovery-codes/regenerar", dependencies=[Depends(exigir_csrf_header)])
async def regenerar_recovery_codes(dados: ConfirmarMfaRequest, usuario: dict = Depends(exigir_login),
                                     sessao=Depends(conexao_tenant), request: Request = None):
    """Exige um código TOTP válido (prova de posse do autenticador) antes de
    invalidar o conjunto anterior de recovery codes -- ver C7."""
    limitador, chave = await _aplicar_limite_mfa(request, usuario["sub"])
    ok = await servico_mfa.verificar_no_login(
        sessao, request.app.state.settings.mfa_encryption_key, usuario["empresa_id"], usuario["sub"],
        codigo=dados.codigo,
    )
    if not ok:
        raise HTTPException(status_code=401, detail="código inválido")
    await limitador.registrar_sucesso(chave)
    codigos = await servico_mfa.regenerar_recovery_codes(sessao, usuario["empresa_id"], usuario["sub"])
    return {"recovery_codes": codigos}


@router.post("/{usuario_id}/mfa/reset", dependencies=[Depends(exigir_csrf_header)])
async def resetar_mfa(
    usuario_id: uuid.UUID,
    # Fase C / C8 -- reset administrativo: exige a permissão
    # "mfa.reset_others" (COMPANY_ADMIN e acima -- ver auth/rbac.py), NUNCA
    # um simples POST sem proteção extra. A RLS de `conexao_tenant` garante
    # que `usuario_id` pertence à MESMA empresa de quem chama.
    ator: dict = Depends(exigir_permissao(PERM_MFA_RESET_OTHERS)),
    sessao=Depends(conexao_tenant),
):
    # Nunca permite resetar o PRÓPRIO MFA por este caminho -- isso seria um
    # bypass do fator de posse exigido por `desativar_mfa` acima (uma
    # sessão comprometida não pode se auto-conceder a remoção do segundo
    # fator só porque também tem a permissão administrativa).
    if str(ator["sub"]) == str(usuario_id):
        raise HTTPException(status_code=403, detail="use o fluxo de desativação self-service para o próprio MFA")
    try:
        await servico_mfa.resetar_mfa_admin(sessao, ator["empresa_id"], str(usuario_id), ator["sub"])
    except servico_mfa.MfaNaoConfiguradoError:
        raise HTTPException(status_code=404, detail="usuário não encontrado nesta empresa")
    return {"ok": True}
