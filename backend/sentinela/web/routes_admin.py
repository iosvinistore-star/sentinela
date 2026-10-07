# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""/admin/empresas, /admin/empresas/{id}/usuarios, /admin/minha-conta --
restrito a superadmin."""
from fastapi import APIRouter, Depends, Form, HTTPException, Request

from sentinela.auth.dependencies import NOME_COOKIE_SESSAO, exigir_csrf_header
from sentinela.auth.security import emitir_token_sessao
from sentinela.services import empresas as servico_empresas
from sentinela.services import superadmins as servico_superadmins
from sentinela.services import usuarios as servico_usuarios
from sentinela.web.deps import conexao_superadmin_web, exigir_superadmin_web, templates

router = APIRouter()

_PAPEIS_VALIDOS = {"admin", "analista"}


@router.get("/admin/empresas")
async def listar_empresas(request: Request, su: dict = Depends(exigir_superadmin_web), conn=Depends(conexao_superadmin_web)):
    empresas = await servico_empresas.listar_empresas(conn)
    return templates.TemplateResponse(request, "admin/empresas.html", {"usuario": su, "empresas": empresas})


@router.post("/admin/empresas", dependencies=[Depends(exigir_csrf_header)])
async def criar_empresa(request: Request,
                          # max_length: mesmo motivo de CriarEmpresaRequest em
                          # api/v1/admin.py -- empresas.nome/plano são `text` sem teto.
                          nome: str = Form(..., min_length=1, max_length=200),
                          plano: str = Form("padrao", max_length=50),
                          su: dict = Depends(exigir_superadmin_web), conn=Depends(conexao_superadmin_web)):
    await servico_empresas.criar_empresa(conn, nome, plano, ator_superadmin_id=su["sub"])
    empresas = await servico_empresas.listar_empresas(conn)
    # Partial só (a tabela) -- o form usa hx-target="#tabela-empresas" com
    # outerHTML; devolver a página inteira (que estende base.html) faria o
    # htmx tentar inserir <html>/<head>/<body> dentro daquela div.
    return templates.TemplateResponse(request, "admin/_tabela_empresas.html", {"usuario": su, "empresas": empresas})


@router.post("/admin/empresas/{empresa_id}/status", dependencies=[Depends(exigir_csrf_header)])
async def atualizar_status_empresa(empresa_id: str, request: Request, status: str = Form(...),
                                     su: dict = Depends(exigir_superadmin_web), conn=Depends(conexao_superadmin_web)):
    if status not in servico_empresas.STATUS_VALIDOS:
        raise HTTPException(status_code=422, detail=f"status inválido -- use um de {sorted(servico_empresas.STATUS_VALIDOS)}")
    empresa = await servico_empresas.atualizar_empresa(conn, empresa_id, status=status, ator_superadmin_id=su["sub"])
    if empresa is None:
        raise HTTPException(status_code=404, detail="empresa não encontrada")
    empresas = await servico_empresas.listar_empresas(conn)
    # Mesmo motivo do partial em criar_empresa: hx-target aponta pra
    # #tabela-empresas com outerHTML.
    return templates.TemplateResponse(request, "admin/_tabela_empresas.html", {"usuario": su, "empresas": empresas})


@router.post("/admin/empresas/{empresa_id}/modo-firewall", dependencies=[Depends(exigir_csrf_header)])
async def atualizar_modo_firewall_empresa(empresa_id: str, request: Request, modo_firewall: str = Form(...),
                                            su: dict = Depends(exigir_superadmin_web), conn=Depends(conexao_superadmin_web)):
    """Item 8 do plano de endurecimento -- kill-switch/modo de firewall POR
    TENANT (ver migrations/0012_...sql e services/resposta_incidentes.py)."""
    if modo_firewall not in servico_empresas.MODOS_FIREWALL_VALIDOS:
        raise HTTPException(
            status_code=422,
            detail=f"modo_firewall inválido -- use um de {sorted(servico_empresas.MODOS_FIREWALL_VALIDOS)}",
        )
    empresa = await servico_empresas.atualizar_empresa(
        conn, empresa_id, modo_firewall=modo_firewall, ator_superadmin_id=su["sub"],
    )
    if empresa is None:
        raise HTTPException(status_code=404, detail="empresa não encontrada")
    empresas = await servico_empresas.listar_empresas(conn)
    return templates.TemplateResponse(request, "admin/_tabela_empresas.html", {"usuario": su, "empresas": empresas})


@router.post("/admin/empresas/{empresa_id}/autonomia", dependencies=[Depends(exigir_csrf_header)])
async def atualizar_autonomia_empresa(empresa_id: str, request: Request,
                                        modo_firewall_auto: bool = Form(False),
                                        auto_triagem_incidentes: bool = Form(False),
                                        su: dict = Depends(exigir_superadmin_web), conn=Depends(conexao_superadmin_web)):
    """Modo autônomo (ver migrations/0014_autonomia_operacional.sql e
    services/automacao.py) -- as duas chaves opt-in por tenant.
    Checkbox HTML desmarcado não envia o campo, por isso `Form(False)` (não
    `Form(...)`) -- um POST sem o campo é interpretado como "desligar",
    igual qualquer form de checkbox."""
    empresa = await servico_empresas.atualizar_empresa(
        conn, empresa_id, modo_firewall_auto=modo_firewall_auto,
        auto_triagem_incidentes=auto_triagem_incidentes, ator_superadmin_id=su["sub"],
    )
    if empresa is None:
        raise HTTPException(status_code=404, detail="empresa não encontrada")
    empresas = await servico_empresas.listar_empresas(conn)
    return templates.TemplateResponse(request, "admin/_tabela_empresas.html", {"usuario": su, "empresas": empresas})


@router.get("/admin/empresas/{empresa_id}/usuarios")
async def listar_usuarios_da_empresa(empresa_id: str, request: Request,
                                       su: dict = Depends(exigir_superadmin_web), conn=Depends(conexao_superadmin_web)):
    empresa = await servico_empresas.obter_empresa(conn, empresa_id)
    if empresa is None:
        raise HTTPException(status_code=404, detail="empresa não encontrada")
    usuarios = await servico_usuarios.listar_usuarios_por_empresa(conn, empresa_id)
    return templates.TemplateResponse(request, "admin/usuarios_empresa.html", {
        "usuario": su, "empresa": empresa, "usuarios": usuarios, "erro": None,
    })


@router.post("/admin/empresas/{empresa_id}/usuarios", dependencies=[Depends(exigir_csrf_header)])
async def criar_usuario_da_empresa(empresa_id: str, request: Request, email: str = Form(...),
                                     papel: str = Form(...), senha: str = Form(...),
                                     su: dict = Depends(exigir_superadmin_web), conn=Depends(conexao_superadmin_web)):
    if papel not in _PAPEIS_VALIDOS:
        raise HTTPException(status_code=422, detail="papel inválido")
    empresa = await servico_empresas.obter_empresa(conn, empresa_id)
    if empresa is None:
        raise HTTPException(status_code=404, detail="empresa não encontrada")

    try:
        criado = await servico_usuarios.criar_usuario(conn, empresa_id, email, papel, senha, ator_superadmin_id=su["sub"])
    except ValueError as exc:
        criado = None
        erro_validacao = str(exc)
    else:
        erro_validacao = None
    usuarios = await servico_usuarios.listar_usuarios_por_empresa(conn, empresa_id)
    # Partial só, e sempre 200 -- mesmo motivo de usuarios/_tabela.html:
    # htmx não troca o DOM em respostas fora de 2xx por padrão, e a página
    # inteira não pode ser jogada dentro do hx-target parcial.
    erro = erro_validacao or (None if criado is not None else "já existe um usuário com este email")
    return templates.TemplateResponse(request, "admin/_tabela_usuarios_empresa.html", {
        "usuario": su, "empresa": empresa, "usuarios": usuarios, "erro": erro,
    })


@router.get("/admin/minha-conta")
async def minha_conta(request: Request, su: dict = Depends(exigir_superadmin_web), conn=Depends(conexao_superadmin_web)):
    """
    Correção de bug encontrado em revisão crítica (2026-09, achado 6): esta
    rota (só leitura, renderiza a própria página de conta) dependia SÓ de
    `exigir_superadmin_web` -- que apenas decodifica o JWT do cookie, sem
    nenhuma consulta ao banco -- ao contrário de TODA outra rota
    autenticada do sistema, que sempre passa também por
    `conexao_superadmin_web`/`conexao_tenant_web` (a re-checagem POR
    REQUISIÇÃO de `token_version`/flag de ativo, ver SessaoInvalidaError
    acima). Na prática: revogar/desativar/rebaixar este superadmin em outra
    aba, ou de outra sessão admin, não derrubava esta página específica --
    ela continuava renderizando normalmente com os dados do JWT antigo até
    o usuário submeter o formulário de troca de senha (a ÚNICA outra rota
    aqui que já passava por `conexao_superadmin_web`) ou navegar para
    qualquer outra página do painel. `conn` não é usado no corpo da função
    -- o ponto é só forçar a dependência (que already levanta
    SessaoInvalidaError/redireciona para o login se a sessão foi
    revogada), igual a toda outra rota já faz.
    """
    return templates.TemplateResponse(request, "admin/minha_conta.html", {"usuario": su, "erro": None, "sucesso": False})


@router.post("/admin/minha-conta/senha", dependencies=[Depends(exigir_csrf_header)])
async def trocar_minha_senha(request: Request, senha_atual: str = Form(...), senha_nova: str = Form(...),
                               su: dict = Depends(exigir_superadmin_web), conn=Depends(conexao_superadmin_web)):
    """Espelha web/routes_usuarios.py:trocar_minha_senha -- ver
    services/superadmins.py:trocar_propria_senha e
    migrations/0013_token_version_superadmin.sql para o porquê desta rota
    não existir até agora."""
    limitador = request.app.state.limitador_login
    chave = f"trocar-senha-superadmin:{su['sub']}"
    restante = await limitador.reservar_tentativa(chave)
    if restante > 0:
        return templates.TemplateResponse(request, "admin/minha_conta.html", {
            "usuario": su, "sucesso": False,
            "erro": f"Muitas tentativas. Tente de novo em {int(restante) + 1} segundos.",
        })
    if len(senha_nova) < 12:
        return templates.TemplateResponse(request, "admin/minha_conta.html", {
            "usuario": su, "sucesso": False, "erro": "A senha nova precisa ter pelo menos 12 caracteres.",
        })
    if len(senha_nova.encode("utf-8")) > 72:
        return templates.TemplateResponse(request, "admin/minha_conta.html", {
            "usuario": su, "sucesso": False, "erro": "A senha nova não pode ter mais de 72 caracteres.",
        })

    novo_tv = await servico_superadmins.trocar_propria_senha(conn, su["sub"], senha_atual, senha_nova)
    if novo_tv is not None:
        await limitador.registrar_sucesso(chave)
    erro = None if novo_tv is not None else "Senha atual incorreta."
    resposta = templates.TemplateResponse(request, "admin/minha_conta.html", {
        "usuario": su, "erro": erro, "sucesso": novo_tv is not None,
    })
    if novo_tv is not None:
        # Reemite o cookie com o token_version novo -- mesmo motivo de
        # web/routes_usuarios.py:trocar_minha_senha.
        settings = request.app.state.settings
        payload_novo = {"sub": su["sub"], "empresa_id": None, "papel": "superadmin", "email": su["email"], "tv": novo_tv}
        token = emitir_token_sessao(payload_novo, settings.jwt_secret, settings.sessao_horas)
        resposta.set_cookie(
            key=NOME_COOKIE_SESSAO, value=token, httponly=True, secure=settings.cookie_seguro,
            samesite="lax", path="/", max_age=settings.sessao_horas * 3600,
        )
    return resposta
