# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
/api/v1/admin/... -- gestão GLOBAL, restrita a superadmin: criar/editar
empresas (tenants), criar o admin inicial de uma empresa nova, e a própria
conta do superadmin (troca de senha). Usa `conexao_superadmin` (BYPASSRLS)
em vez de `conexao_tenant` -- por definição, um superadmin não tem
`empresa_id` próprio.
"""
import re
import secrets
import uuid

from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from sentinela.auth.dependencies import NOME_COOKIE_SESSAO, conexao_superadmin, exigir_csrf_header, exigir_superadmin
from sentinela.auth.rbac import exigir_saas_owner
from sentinela.auth.security import emitir_token_sessao
from sentinela.services import auditoria as servico_auditoria
from sentinela.services import chave_ativacao
from sentinela.services import empresas as servico_empresas
from sentinela.services import enrollment as servico_enrollment
from sentinela.services import mfa as servico_mfa
from sentinela.services import superadmins as servico_superadmins
from sentinela.services import usuarios as servico_usuarios
from sentinela.services.empresas import ModoFirewallInvalidoError, StatusEmpresaInvalidoError

router = APIRouter(prefix="/admin", tags=["admin"])

# Fase C -- "viewer" adicionado (RBAC, ver auth/rbac.py).
_PAPEIS_VALIDOS = {"admin", "analista", "viewer"}
_SENHA_MAX_LENGTH = 72  # limite físico do bcrypt -- ver services/usuarios.py:_validar_senha


class MfaCodigoRequest(BaseModel):
    codigo: str | None = Field(default=None, min_length=6, max_length=6)
    recovery_code: str | None = Field(default=None, min_length=8, max_length=32)


class TrocarSenhaSuperadminRequest(BaseModel):
    senha_atual: str
    senha_nova: str = Field(min_length=12, max_length=_SENHA_MAX_LENGTH)


class CriarEmpresaRequest(BaseModel):
    # empresas.nome/plano são `text` no banco (sem teto) -- limite de
    # aplicação evita um valor de tamanho arbitrário armazenado só porque
    # um superadmin (ou uma sessão de superadmin comprometida) mandou.
    nome: str = Field(min_length=1, max_length=200)
    plano: str = Field(default="padrao", max_length=50)


class AtualizarEmpresaRequest(BaseModel):
    nome: str | None = Field(default=None, max_length=200)
    plano: str | None = Field(default=None, max_length=50)
    status: str | None = None
    # Ver migrations/0012_firewall_modo_e_incidente.sql e
    # services/resposta_incidentes.py -- item 8 do plano de endurecimento
    # (kill-switch/modo de firewall POR TENANT).
    modo_firewall: str | None = None
    # Ver migrations/0014_autonomia_operacional.sql e services/automacao.py
    # -- as duas chaves opt-in do modo autônomo.
    modo_firewall_auto: bool | None = None
    auto_triagem_incidentes: bool | None = None
    # Ver migrations/0016_agentes_endpoint.sql e services/agentes.py --
    # opt-in do Sentinela Endpoint (agente local instalado na máquina do
    # cliente). Uma vez ligado aqui, o admin da PRÓPRIA empresa cria e
    # revoga os tokens de agente em /api/v1/agentes (self-service).
    agentes_endpoint_habilitado: bool | None = None


class CriarUsuarioEmpresaRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    papel: str = "admin"
    senha: str = Field(min_length=12, max_length=_SENHA_MAX_LENGTH)


class CriarSaasAdminRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    papel_saas: str = "saas_admin"
    senha: str = Field(min_length=12, max_length=_SENHA_MAX_LENGTH)


# ---------------------------------------------------------------------------
# Fase C / C4 -- gestão de contas de SaaS (Owner + Admin). EXCLUSIVO de
# SAAS_OWNER (auth/rbac.py:exigir_saas_owner) -- um SaaS Admin não pode
# criar OUTRO SaaS Admin nem a si mesmo promover-se a Owner por aqui.
# ---------------------------------------------------------------------------

@router.get("/saas-admins")
async def listar_saas_admins(su: dict = Depends(exigir_saas_owner), sessao=Depends(conexao_superadmin)):
    return {"contas": await servico_superadmins.listar_saas_admins(sessao)}


@router.post("/saas-admins", dependencies=[Depends(exigir_csrf_header)])
async def criar_saas_admin(dados: CriarSaasAdminRequest, su: dict = Depends(exigir_saas_owner),
                             sessao=Depends(conexao_superadmin)):
    try:
        criado = await servico_superadmins.criar_saas_admin(
            sessao, dados.email, dados.senha, dados.papel_saas, ator_superadmin_id=su["sub"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if criado is None:
        raise HTTPException(status_code=409, detail="já existe uma conta com este email")
    return {"conta": criado}


@router.get("/mfa")
async def status_mfa_saas(su: dict = Depends(exigir_superadmin), sessao=Depends(conexao_superadmin)):
    return await servico_mfa.obter_status_mfa_superadmin(sessao, su["sub"])

@router.post("/mfa/setup", dependencies=[Depends(exigir_csrf_header)])
async def setup_mfa_saas(su: dict = Depends(exigir_superadmin), sessao=Depends(conexao_superadmin), request: Request = None):
    try:
        return await servico_mfa.iniciar_configuracao_superadmin(sessao, request.app.state.settings.mfa_encryption_key, su["sub"], su["email"])
    except servico_mfa.MfaJaHabilitadoError as exc:
        raise HTTPException(status_code=409, detail="MFA já habilitado") from exc

@router.post("/mfa/confirm", dependencies=[Depends(exigir_csrf_header)])
async def confirmar_mfa_saas(dados: MfaCodigoRequest, su: dict = Depends(exigir_superadmin), sessao=Depends(conexao_superadmin), request: Request = None):
    try:
        codes=await servico_mfa.confirmar_configuracao_superadmin(sessao, request.app.state.settings.mfa_encryption_key, su["sub"], dados.codigo)
    except servico_mfa.MfaNaoConfiguradoError as exc:
        raise HTTPException(status_code=409, detail="setup de MFA não iniciado") from exc
    except servico_mfa.CodigoInvalidoError as exc:
        raise HTTPException(status_code=422, detail="código TOTP inválido") from exc
    return {"recovery_codes": codes}

@router.post("/mfa/disable", dependencies=[Depends(exigir_csrf_header)])
async def desativar_mfa_saas(dados: MfaCodigoRequest, su: dict = Depends(exigir_superadmin), sessao=Depends(conexao_superadmin), request: Request = None):
    if not dados.codigo and not dados.recovery_code:
        raise HTTPException(status_code=422, detail="informe código TOTP ou recovery code para desativar MFA")
    ok = await servico_mfa.verificar_no_login_superadmin(
        sessao, request.app.state.settings.mfa_encryption_key, su["sub"],
        codigo=dados.codigo, recovery_code=dados.recovery_code,
    )
    if not ok:
        raise HTTPException(status_code=401, detail="fator MFA inválido")
    await servico_mfa.desativar_superadmin(sessao, su["sub"], su["sub"])
    return {"ok": True}


@router.get("/empresas")
async def listar_empresas(su: dict = Depends(exigir_superadmin), sessao=Depends(conexao_superadmin)):
    return {"empresas": await servico_empresas.listar_empresas(sessao)}


@router.post("/empresas", dependencies=[Depends(exigir_csrf_header)])
async def criar_empresa(dados: CriarEmpresaRequest, su: dict = Depends(exigir_superadmin),
                          sessao=Depends(conexao_superadmin)):
    empresa = await servico_empresas.criar_empresa(sessao, dados.nome, dados.plano, ator_superadmin_id=su["sub"])
    return {"empresa": empresa}


@router.patch("/empresas/{empresa_id}", dependencies=[Depends(exigir_csrf_header)])
async def atualizar_empresa(
    # uuid.UUID -- ver o comentário equivalente em
    # api/v1/usuarios.py:atualizar_usuario (mesmo motivo: sem isso, um
    # empresa_id malformado virava um asyncpg.DataError cru, 500 em vez
    # de 422).
    empresa_id: uuid.UUID,
    dados: AtualizarEmpresaRequest,
    su: dict = Depends(exigir_superadmin), sessao=Depends(conexao_superadmin),
):
    try:
        empresa = await servico_empresas.atualizar_empresa(
            sessao, str(empresa_id), nome=dados.nome, plano=dados.plano, status=dados.status,
            modo_firewall=dados.modo_firewall, modo_firewall_auto=dados.modo_firewall_auto,
            auto_triagem_incidentes=dados.auto_triagem_incidentes,
            agentes_endpoint_habilitado=dados.agentes_endpoint_habilitado, ator_superadmin_id=su["sub"],
        )
    except (StatusEmpresaInvalidoError, ModoFirewallInvalidoError) as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if empresa is None:
        raise HTTPException(status_code=404, detail="empresa não encontrada")
    return {"empresa": empresa}


@router.get("/empresas/{empresa_id}/usuarios")
async def listar_usuarios_da_empresa(empresa_id: uuid.UUID, su: dict = Depends(exigir_superadmin),
                                       sessao=Depends(conexao_superadmin)):
    return {"usuarios": await servico_usuarios.listar_usuarios_por_empresa(sessao, str(empresa_id))}


@router.post("/empresas/{empresa_id}/usuarios", dependencies=[Depends(exigir_csrf_header)])
async def criar_usuario_da_empresa(empresa_id: uuid.UUID, dados: CriarUsuarioEmpresaRequest,
                                     su: dict = Depends(exigir_superadmin), sessao=Depends(conexao_superadmin)):
    if dados.papel not in _PAPEIS_VALIDOS:
        raise HTTPException(status_code=422, detail=f"papel inválido -- use um de {sorted(_PAPEIS_VALIDOS)}")
    # Confere a empresa ANTES do INSERT: sem isso, um empresa_id de formato
    # válido mas inexistente batia direto na FK de `usuarios.empresa_id` e
    # virava um asyncpg.ForeignKeyViolationError cru -- também não é
    # subclasse de ValueError, também vira 500 em vez de um 404 claro.
    if await servico_empresas.obter_empresa(sessao, str(empresa_id)) is None:
        raise HTTPException(status_code=404, detail="empresa não encontrada")
    try:
        criado = await servico_usuarios.criar_usuario(
            sessao, str(empresa_id), dados.email, dados.papel, dados.senha, ator_superadmin_id=su["sub"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if criado is None:
        raise HTTPException(status_code=409, detail="já existe um usuário com este email")
    return {"usuario": criado}


@router.patch("/me/senha", dependencies=[Depends(exigir_csrf_header)])
async def trocar_propria_senha_superadmin(dados: TrocarSenhaSuperadminRequest, request: Request, response: Response,
                                            su: dict = Depends(exigir_superadmin), sessao=Depends(conexao_superadmin)):
    """
    Espelha api/v1/usuarios.py:trocar_propria_senha (mesmo rate limiting
    por chamador, mesma reemissão de cookie) -- ver
    services/superadmins.py:trocar_propria_senha e
    migrations/0013_token_version_superadmin.sql para o porquê desta rota
    não existir até agora.
    """
    limitador = request.app.state.limitador_login
    # Chave por SUPERADMIN (não por IP) -- mesmo raciocínio de
    # api/v1/usuarios.py:trocar_propria_senha: uma sessão válida pode estar
    # em qualquer IP, o que se quer limitar é quantas vezes alguém pode
    # tentar adivinhar a senha ATUAL deste superadmin especificamente.
    chave = f"trocar-senha-superadmin:{su['sub']}"
    restante = await limitador.reservar_tentativa(chave)
    if restante > 0:
        raise HTTPException(
            status_code=429, detail=f"muitas tentativas -- tente de novo em {int(restante) + 1} segundos",
            headers={"Retry-After": str(int(restante) + 1)},
        )
    novo_tv = await servico_superadmins.trocar_propria_senha(sessao, su["sub"], dados.senha_atual, dados.senha_nova)
    if novo_tv is None:
        raise HTTPException(status_code=401, detail="senha atual incorreta")
    await limitador.registrar_sucesso(chave)
    # Reemite o cookie com o token_version novo -- senão a troca de senha
    # derrubaria a PRÓPRIA sessão que a fez na próxima requisição (ver
    # auth/dependencies.py:conexao_superadmin, que compara "tv" contra o
    # banco a cada requisição).
    settings = request.app.state.settings
    payload_novo = {"sub": su["sub"], "empresa_id": None, "papel": "superadmin", "email": su["email"], "tv": novo_tv}
    token = emitir_token_sessao(payload_novo, settings.jwt_secret, settings.sessao_horas)
    response.set_cookie(
        key=NOME_COOKIE_SESSAO, value=token, httponly=True, secure=settings.cookie_seguro,
        samesite="lax", path="/", max_age=settings.sessao_horas * 3600,
    )
    return {"ok": True}


class ChaveAtivacaoRequest(BaseModel):
    validade_horas: int = Field(default=72, ge=1, le=720)
    max_instalacoes: int = Field(default=10, ge=1, le=1000)


# ---------------------------------------------------------------------------
# Cadastro de CLIENTE em uma chamada só (ver migrations/
# 0031_dados_contrato_empresa.sql).
#
# Antes disto, colocar um cliente novo no ar era: criar empresa -> abrir a
# empresa -> ligar "agentes_endpoint_habilitado" -> criar o usuário admin
# dele -> gerar um token de enrollment -> montar a chave de ativação à mão.
# Seis passos em telas diferentes, cada um com o seu jeito de falhar pela
# metade. `POST /admin/clientes` faz os seis dentro de UMA transação: ou o
# cliente nasce inteiro (empresa + contrato + admin + chave pronta para o
# instalador) ou não nasce nada.
# ---------------------------------------------------------------------------

_RE_CNPJ = re.compile(r"\D+")
_RE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _normalizar_cnpj(valor: str | None) -> str | None:
    """Guarda só os 14 dígitos -- assim "12.345.678/0001-95" e
    "12345678000195" são o MESMO cliente para o índice único."""
    if valor is None:
        return None
    digitos = _RE_CNPJ.sub("", valor)
    return digitos or None


def _cnpj_valido(cnpj: str) -> bool:
    """Dígitos verificadores do CNPJ. Rejeitar aqui evita que um erro de
    digitação vire um cadastro duplicado depois (com o CNPJ certo)."""
    if len(cnpj) != 14 or cnpj == cnpj[0] * 14:
        return False
    for tamanho in (12, 13):
        pesos = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2][-tamanho:]
        soma = sum(int(d) * p for d, p in zip(cnpj[:tamanho], pesos))
        resto = soma % 11
        digito = 0 if resto < 2 else 11 - resto
        if int(cnpj[tamanho]) != digito:
            return False
    return True


class DadosContrato(BaseModel):
    cnpj: str | None = Field(default=None, max_length=32)
    responsavel: str | None = Field(default=None, max_length=200)
    email_contato: str | None = Field(default=None, max_length=320)
    telefone: str | None = Field(default=None, max_length=40)
    contrato_numero: str | None = Field(default=None, max_length=60)
    contrato_vigencia: date | None = None
    observacoes: str | None = Field(default=None, max_length=2000)


class NovoClienteRequest(BaseModel):
    nome: str = Field(min_length=1, max_length=200)
    plano: str = Field(default="padrao", max_length=50)
    # E-mail do admin que o CLIENTE vai usar para entrar. A senha é
    # opcional: sem ela, o SaaS sorteia uma e devolve UMA VEZ na resposta,
    # que é o caminho que dá menos chance de alguém reaproveitar uma senha
    # fraca conhecida.
    admin_email: str = Field(min_length=3, max_length=320)
    admin_senha: str | None = Field(default=None, min_length=12, max_length=_SENHA_MAX_LENGTH)
    contrato: DadosContrato = Field(default_factory=DadosContrato)
    validade_horas: int = Field(default=72, ge=1, le=720)
    max_instalacoes: int = Field(default=10, ge=1, le=1000)


def _gerar_senha_inicial() -> str:
    """Senha inicial legível ao telefone (sem 0/O/1/l) e com entropia de
    sobra -- 4 grupos de 5 caracteres de um alfabeto de 32 ~= 100 bits."""
    alfabeto = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
    grupos = ["".join(secrets.choice(alfabeto) for _ in range(5)) for _ in range(4)]
    return "-".join(grupos)


def _texto_para_cliente(nome: str, url: str, email: str, senha: str, chave: str) -> str:
    """Bloco pronto para o provedor copiar e mandar ao cliente -- o motivo
    de existir é que, sem ele, cada implantação virava um e-mail escrito na
    hora, e a chave de ativação (longa) era a parte mais fácil de errar."""
    return (
        f"Sentinela SOC -- acesso de {nome}\n\n"
        f"Painel:  {url}/app\n"
        f"Usuario: {email}\n"
        f"Senha:   {senha}   (troque no primeiro acesso)\n\n"
        f"Para instalar o agente nas maquinas, use esta chave de ativacao:\n"
        f"{chave}\n\n"
        f"Windows: rode INSTALAR-AGENTE.bat e cole a chave quando for pedida.\n"
        f"Linux:   sudo ./install.sh --chave-ativacao \"{chave}\"\n"
    )


@router.post("/clientes", dependencies=[Depends(exigir_csrf_header)], status_code=201)
async def cadastrar_cliente(dados: NovoClienteRequest, request: Request,
                            su: dict = Depends(exigir_superadmin), sessao=Depends(conexao_superadmin)):
    """Cadastra um cliente inteiro: empresa + contrato + admin + chave de ativação.

    Devolve a senha inicial e a chave de ativação EM TEXTO CLARO uma única
    vez -- elas não são recuperáveis depois (a senha é hash, o token só
    existe hasheado). Por isso a resposta traz também `texto_para_cliente`,
    já formatado para o provedor repassar.
    """
    if not _RE_EMAIL.match(dados.admin_email.strip()):
        raise HTTPException(status_code=422, detail="e-mail do administrador inválido")
    cnpj = _normalizar_cnpj(dados.contrato.cnpj)
    if cnpj is not None and not _cnpj_valido(cnpj):
        raise HTTPException(status_code=422, detail="CNPJ inválido -- confira os dígitos")
    if dados.contrato.email_contato and not _RE_EMAIL.match(dados.contrato.email_contato.strip()):
        raise HTTPException(status_code=422, detail="e-mail de contato inválido")
    if cnpj is not None:
        nome_existente = await servico_empresas.nome_da_empresa_com_cnpj(sessao, cnpj)
        if nome_existente is not None:
            raise HTTPException(status_code=409, detail=f"já existe um cliente com este CNPJ: {nome_existente}")

    senha = dados.admin_senha or _gerar_senha_inicial()
    expira_em = datetime.now(timezone.utc) + timedelta(hours=dados.validade_horas)

    # UMA transação para os cinco passos. Um cliente "meio criado" (empresa
    # sem admin, ou admin sem chave) é pior do que nenhum: alguém teria de
    # descobrir em que ponto parou antes de tentar de novo.
    async with sessao.begin_nested():
        empresa = await servico_empresas.criar_empresa(
            sessao, dados.nome.strip(), dados.plano, ator_superadmin_id=su["sub"],
        )
        empresa_id = empresa["id"]
        atualizada = await servico_empresas.gravar_dados_contrato(
            sessao, uuid.UUID(empresa_id), cnpj,
            {
                "responsavel": dados.contrato.responsavel, "email_contato": dados.contrato.email_contato,
                "telefone": dados.contrato.telefone, "contrato_numero": dados.contrato.contrato_numero,
                "contrato_vigencia": dados.contrato.contrato_vigencia, "observacoes": dados.contrato.observacoes,
            },
            habilitar_agentes=True,
        )
        try:
            admin = await servico_usuarios.criar_usuario(
                sessao, empresa_id, dados.admin_email.strip(), "admin", senha, ator_superadmin_id=su["sub"],
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if admin is None:
            raise HTTPException(status_code=409, detail="já existe um usuário com este e-mail")
        _, token = await servico_enrollment.criar_token_enrollment(
            sessao, empresa_id, expira_em, max_usos=dados.max_instalacoes, ator_superadmin_id=su["sub"],
        )
        await servico_auditoria.registrar_evento(
            sessao, empresa_id, "cliente.cadastrado",
            {"nome": dados.nome, "plano": dados.plano, "admin_email": dados.admin_email,
             "contrato_numero": dados.contrato.contrato_numero},
            ator_superadmin_id=su["sub"],
        )

    backend_url = chave_ativacao.endereco_publico(request.app.state.settings.url_base_publica, str(request.base_url))
    chave = chave_ativacao.gerar(backend_url, token)
    return {
        "empresa": atualizada,
        "admin": {"email": dados.admin_email.strip(), "senha_inicial": senha,
                  "senha_gerada": dados.admin_senha is None},
        "chave_ativacao": chave,
        "backend_url": backend_url,
        "expira_em": expira_em.isoformat(),
        "max_instalacoes": dados.max_instalacoes,
        "aviso": chave_ativacao.aviso_endereco(backend_url),
        "texto_para_cliente": _texto_para_cliente(
            dados.nome.strip(), backend_url, dados.admin_email.strip(), senha, chave,
        ),
    }


@router.patch("/empresas/{empresa_id}/contrato", dependencies=[Depends(exigir_csrf_header)])
async def atualizar_contrato(empresa_id: uuid.UUID, dados: DadosContrato,
                             su: dict = Depends(exigir_superadmin), sessao=Depends(conexao_superadmin)):
    """Edita só os dados comerciais -- separado de `PATCH /empresas/{id}`,
    que mexe em capacidades operacionais (firewall, automação, agentes)."""
    cnpj = _normalizar_cnpj(dados.cnpj)
    if cnpj is not None and not _cnpj_valido(cnpj):
        raise HTTPException(status_code=422, detail="CNPJ inválido -- confira os dígitos")
    if dados.email_contato and not _RE_EMAIL.match(dados.email_contato.strip()):
        raise HTTPException(status_code=422, detail="e-mail de contato inválido")
    if cnpj is not None:
        conflito = await servico_empresas.nome_da_empresa_com_cnpj(sessao, cnpj, exceto_id=empresa_id)
        if conflito is not None:
            raise HTTPException(status_code=409, detail=f"este CNPJ já pertence a: {conflito}")
    atualizada = await servico_empresas.gravar_dados_contrato(
        sessao, empresa_id, cnpj,
        {
            "responsavel": dados.responsavel, "email_contato": dados.email_contato, "telefone": dados.telefone,
            "contrato_numero": dados.contrato_numero, "contrato_vigencia": dados.contrato_vigencia,
            "observacoes": dados.observacoes,
        },
    )
    if atualizada is None:
        raise HTTPException(status_code=404, detail="empresa não encontrada")
    await servico_auditoria.registrar_evento(
        sessao, str(empresa_id), "empresa.contrato_atualizado",
        {"contrato_numero": dados.contrato_numero, "responsavel": dados.responsavel},
        ator_superadmin_id=su["sub"],
    )
    return {"empresa": atualizada}


@router.post("/empresas/{empresa_id}/chave-ativacao", dependencies=[Depends(exigir_csrf_header)])
async def gerar_chave_ativacao(empresa_id: uuid.UUID, dados: ChaveAtivacaoRequest, request: Request,
                               su: dict = Depends(exigir_superadmin), sessao=Depends(conexao_superadmin)):
    """Provedor gera a chave de ativação dos agentes de uma empresa cliente.

    A chave junta o endereço do SaaS e um token de instalação da empresa; o
    cliente cola no instalador e o agente se registra sozinho. Se a empresa
    ainda não tinha a capacidade "Agentes", ela é habilitada aqui (gerar uma
    chave para uma empresa sem agentes não teria efeito) e isso fica auditado.
    """
    empresa = await servico_empresas.obter_empresa(sessao, empresa_id)
    if empresa is None:
        raise HTTPException(status_code=404, detail="empresa não encontrada")
    if empresa["status"] != "ativa":
        raise HTTPException(status_code=409, detail=f"empresa com status '{empresa['status']}': reative antes de gerar chaves")
    habilitou_agora = False
    async with sessao.begin_nested():
        if not empresa["agentes_endpoint_habilitado"]:
            await servico_empresas.habilitar_agentes_endpoint(sessao, empresa_id)
            await servico_auditoria.registrar_evento(
                sessao, str(empresa_id), "empresa.agentes_habilitados",
                {"motivo": "chave de ativação gerada pelo provedor"}, ator_superadmin_id=su["sub"],
            )
            habilitou_agora = True
        expira_em = datetime.now(timezone.utc) + timedelta(hours=dados.validade_horas)
        token_publico, token = await servico_enrollment.criar_token_enrollment(
            sessao, str(empresa_id), expira_em, max_usos=dados.max_instalacoes, ator_superadmin_id=su["sub"],
        )
    backend_url = chave_ativacao.endereco_publico(request.app.state.settings.url_base_publica, str(request.base_url))
    return {
        "empresa": {"id": str(empresa["id"]), "nome": empresa["nome"]},
        "chave_ativacao": chave_ativacao.gerar(backend_url, token),
        "backend_url": backend_url,
        "expira_em": expira_em.isoformat(),
        "max_instalacoes": dados.max_instalacoes,
        "enrollment": token_publico,
        "agentes_habilitados_agora": habilitou_agora,
        "aviso": chave_ativacao.aviso_endereco(backend_url),
    }
