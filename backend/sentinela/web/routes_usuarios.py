# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""/usuarios -- gestão dos usuários da PRÓPRIA empresa (admin-only) e
/minha-conta -- troca da própria senha (qualquer usuário logado)."""
from fastapi import APIRouter, Depends, Form, HTTPException, Request

from sentinela.auth.dependencies import NOME_COOKIE_SESSAO, exigir_csrf_header
from sentinela.auth.security import emitir_token_sessao
from sentinela.services import usuarios as servico
from sentinela.web.deps import conexao_tenant_web, exigir_login_web, exigir_papel_web, templates

router = APIRouter()

_PAPEIS_VALIDOS = {"admin", "analista"}


@router.get("/usuarios")
async def listar(request: Request, usuario: dict = Depends(exigir_papel_web("admin")), sessao=Depends(conexao_tenant_web)):
    usuarios = await servico.listar_usuarios(sessao)
    return templates.TemplateResponse(request, "usuarios/lista.html", {"usuario": usuario, "usuarios": usuarios, "erro": None})


@router.post("/usuarios", dependencies=[Depends(exigir_csrf_header)])
async def criar(request: Request, email: str = Form(...), papel: str = Form(...), senha: str = Form(...),
                  usuario: dict = Depends(exigir_papel_web("admin")), sessao=Depends(conexao_tenant_web)):
    if papel not in _PAPEIS_VALIDOS:
        raise HTTPException(status_code=422, detail="papel inválido")
    try:
        criado = await servico.criar_usuario(sessao, usuario["empresa_id"], email, papel, senha, ator_usuario_id=usuario["sub"])
        erro_validacao = None
    except ValueError as exc:
        criado = None
        erro_validacao = str(exc)
    usuarios = await servico.listar_usuarios(sessao)
    # Sempre 200 aqui (mesmo em erro de validação) -- por padrão o htmx NÃO
    # troca o DOM em respostas fora da faixa 2xx, então um 409 faria a
    # mensagem de erro nunca aparecer pro usuário. A API JSON
    # (api/v1/usuarios.py) continua devolvendo 409 de verdade -- lá quem
    # consome é código (React), não uma troca de HTML no navegador.
    erro = erro_validacao or (None if criado is not None else "já existe um usuário com este email")
    return templates.TemplateResponse(request, "usuarios/_tabela.html", {"usuario": usuario, "usuarios": usuarios, "erro": erro})


@router.patch("/usuarios/{usuario_id}", dependencies=[Depends(exigir_csrf_header)])
async def atualizar(usuario_id: str, request: Request, papel: str = Form(...), ativo: str = Form(...),
                      usuario: dict = Depends(exigir_papel_web("admin")), sessao=Depends(conexao_tenant_web)):
    if papel not in _PAPEIS_VALIDOS:
        raise HTTPException(status_code=422, detail="papel inválido")
    await servico.atualizar_usuario(
        sessao, usuario["empresa_id"], usuario_id, papel=papel, ativo=(ativo == "true"), ator_usuario_id=usuario["sub"],
    )
    usuarios = await servico.listar_usuarios(sessao)
    return templates.TemplateResponse(request, "usuarios/_tabela.html", {"usuario": usuario, "usuarios": usuarios})


@router.get("/minha-conta")
async def minha_conta(request: Request, usuario: dict = Depends(exigir_login_web), sessao=Depends(conexao_tenant_web)):
    """Correção de bug encontrado em revisão crítica (2026-09, achado 6) --
    espelha routes_admin.py:minha_conta (ver o comentário lá para o
    cenário completo). Esta rota só de leitura dependia SÓ de
    `exigir_login_web` (decodifica o JWT, sem tocar o banco), diferente de
    toda outra rota autenticada -- que sempre passa também por
    `conexao_tenant_web` (re-checagem por requisição de
    token_version/ativo/empresa suspensa). Uma sessão revogada/desativada/
    rebaixada continuava vendo esta página normalmente até submeter o
    formulário de troca de senha ou navegar para outra rota. `conn` não é
    usado no corpo -- o ponto é só forçar a dependência."""
    return templates.TemplateResponse(request, "usuarios/minha_conta.html", {"usuario": usuario, "erro": None, "sucesso": False})


@router.post("/minha-conta/senha", dependencies=[Depends(exigir_csrf_header)])
async def trocar_minha_senha(request: Request, senha_atual: str = Form(...), senha_nova: str = Form(...),
                               usuario: dict = Depends(exigir_login_web), sessao=Depends(conexao_tenant_web)):
    limitador = request.app.state.limitador_login
    # Chave por USUÁRIO (não por IP, ao contrário do login): quem já tem
    # uma sessão válida desse usuário pode estar em qualquer IP (cookie
    # sequestrado, rede diferente) -- o que queremos limitar aqui é
    # quantas vezes ALGUÉM pode tentar adivinhar a senha atual DESTE
    # usuário, não quantas tentativas de login vêm de um IP.
    # Todo retorno de erro aqui é 200, não 429/422: este formulário é
    # hx-post (só assim dá pra exigir o header CSRF, ver
    # usuarios/minha_conta.html) e o htmx só troca o DOM em respostas 2xx
    # por padrão -- um status de erro faria a mensagem nunca aparecer.
    chave = f"trocar-senha:{usuario['sub']}"
    restante = await limitador.reservar_tentativa(chave)
    if restante > 0:
        return templates.TemplateResponse(request, "usuarios/minha_conta.html", {
            "usuario": usuario, "sucesso": False,
            "erro": f"Muitas tentativas. Tente de novo em {int(restante) + 1} segundos.",
        })
    if len(senha_nova) < 12:
        return templates.TemplateResponse(request, "usuarios/minha_conta.html", {
            "usuario": usuario, "sucesso": False, "erro": "A senha nova precisa ter pelo menos 12 caracteres.",
        })
    if len(senha_nova.encode("utf-8")) > 72:
        return templates.TemplateResponse(request, "usuarios/minha_conta.html", {
            "usuario": usuario, "sucesso": False, "erro": "A senha nova não pode ter mais de 72 caracteres.",
        })

    novo_tv = await servico.trocar_propria_senha(sessao, usuario["sub"], senha_atual, senha_nova)
    if novo_tv is not None:
        await limitador.registrar_sucesso(chave)
    erro = None if novo_tv is not None else "Senha atual incorreta."
    resposta = templates.TemplateResponse(request, "usuarios/minha_conta.html", {
        "usuario": usuario, "erro": erro, "sucesso": novo_tv is not None,
    })
    if novo_tv is not None:
        # Reemite o cookie com o token_version novo -- mesmo motivo de
        # api/v1/usuarios.py:trocar_propria_senha: sem isso, a PRÓPRIA
        # sessão que trocou a senha seria derrubada na requisição seguinte.
        settings = request.app.state.settings
        payload_novo = {
            "sub": usuario["sub"], "empresa_id": usuario.get("empresa_id"),
            "papel": usuario["papel"], "email": usuario["email"], "tv": novo_tv,
        }
        token = emitir_token_sessao(payload_novo, settings.jwt_secret, settings.sessao_horas)
        resposta.set_cookie(
            key=NOME_COOKIE_SESSAO, value=token, httponly=True, secure=settings.cookie_seguro,
            samesite="lax", path="/", max_age=settings.sessao_horas * 3600,
        )
    return resposta
