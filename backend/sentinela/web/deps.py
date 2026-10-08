# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Dependências e helpers compartilhados pelas rotas HTML (HTMX). Espelham as
de `auth/dependencies.py` (mesmo vocabulário: exigir_login/exigir_papel),
mas devolvem um REDIRECT para /login em vez de uma resposta JSON 401 --
essa é a diferença de UX entre "consumidor de API" (React) e "usuário num
navegador" (HTMX). A autorização de verdade (JWT, RLS) é exatamente a
mesma dos dois lados -- só a forma de recusar acesso muda.
"""
import os

from fastapi import Depends, HTTPException, Request
from fastapi.templating import Jinja2Templates

from sentinela.auth.dependencies import usuario_atual
from sentinela.repositories.empresas import EmpresaRepositorio
from sentinela.repositories.superadmins import SuperadminRepositorio
from sentinela.repositories.usuarios import UsuarioRepositorio
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=TEMPLATES_DIR)


class RedirecionarParaLogin(Exception):
    """
    Levantada por `exigir_login_web` quando não há sessão válida. Capturada
    por um exception handler registrado em `main.py`, que devolve um
    redirect 303 para /login?proxima=<url original> -- não dá pra devolver
    um RedirectResponse direto de dentro de uma dependência do FastAPI sem
    reescrever cada rota individualmente para checar isso na mão.
    """
    def __init__(self, proxima: str = "/"):
        self.proxima = proxima


class AcessoEmpresaSuspensaError(Exception):
    """
    Levantada por `conexao_tenant_web` quando a sessão (cookie) é válida
    mas a empresa foi suspensa/cancelada DEPOIS que o cookie foi emitido
    -- ex.: o superadmin suspende a empresa enquanto o usuário ainda tem
    uma aba aberta. Capturada por um exception handler em main.py que
    derruba o cookie de sessão e redireciona para /login com uma
    mensagem -- mesma técnica de `RedirecionarParaLogin` (não dá pra
    devolver um RedirectResponse direto de dentro de uma dependência).
    """
    def __init__(self, status: str):
        self.status = status


async def exigir_login_web(request: Request) -> dict:
    usuario = await usuario_atual(request)
    if usuario is None or usuario.get("papel") == "superadmin":
        raise RedirecionarParaLogin(str(request.url.path))
    return usuario


def exigir_papel_web(*papeis_permitidos: str):
    """Uso: `Depends(exigir_papel_web("admin"))` -- encadeia sobre exigir_login_web."""
    async def dependencia(usuario: dict = Depends(exigir_login_web)) -> dict:
        if usuario["papel"] not in papeis_permitidos:
            raise HTTPException(status_code=403, detail="sem permissão para esta ação")
        return usuario
    return dependencia


async def exigir_superadmin_web(request: Request) -> dict:
    usuario = await usuario_atual(request)
    if usuario is None or usuario.get("papel") != "superadmin":
        raise RedirecionarParaLogin(str(request.url.path))
    return usuario


class SessaoInvalidaError(Exception):
    """
    Levantada por `conexao_tenant_web` quando o cookie de sessão ainda é
    válido (assinatura/expiração OK), mas o usuário foi desativado ou teve
    o papel alterado DEPOIS que o token foi emitido -- mesma classe de
    problema que `AcessoEmpresaSuspensaError`, só que no nível do usuário
    em vez da empresa inteira. Sem isto, um admin que desativa outro
    usuário (ou rebaixa um admin pra analista) não revoga nada de
    verdade -- a sessão já aberta continua com o papel ANTIGO até o
    cookie expirar sozinho. Ver o mesmo reforço, com o mesmo motivo, em
    auth/dependencies.py:conexao_tenant.
    """


async def conexao_tenant_web(usuario: dict = Depends(exigir_login_web), request: Request = None):
    """Ver AcessoEmpresaSuspensaError/SessaoInvalidaError -- reforço em tempo real que espelha auth/dependencies.py:conexao_tenant,
    incluindo a checagem de token_version ("tv") contra troca de senha (migrations/0011_token_version.sql) e de
    `empresa_id = $2` contra adulteração dessa claim no JWT (ver o comentário longo em auth/dependencies.py:conexao_tenant)."""
    async with request.app.state.db.tenant_session(usuario["empresa_id"]) as sessao:
        status = await EmpresaRepositorio(sessao).obter_status(usuario["empresa_id"])
        if status != "ativa":
            raise AcessoEmpresaSuspensaError(status)
        linha = await UsuarioRepositorio(sessao).obter_para_sessao(usuario["sub"], usuario["empresa_id"])
        if (
            linha is None
            or not linha.ativo
            or linha.papel != usuario["papel"]
            or linha.token_version != usuario.get("tv")
        ):
            raise SessaoInvalidaError()
        yield sessao


async def conexao_superadmin_web(su: dict = Depends(exigir_superadmin_web), request: Request = None):
    """Ver auth/dependencies.py:conexao_superadmin -- mesmo reforço em tempo real (token_version, "tv",
    e a partir da Fase C também `papel` / "papel_saas"), espelhado aqui pelo mesmo motivo que
    conexao_tenant_web espelha conexao_tenant (redirect em vez de 401 JSON)."""
    async with request.app.state.db.superadmin_session() as sessao:
        linha = await SuperadminRepositorio(sessao).obter_para_sessao(su["sub"])
        papel_saas_no_token = su.get("papel_saas") or "saas_owner"
        if (
            linha is None
            or linha.token_version != su.get("tv")
            or linha.papel != papel_saas_no_token
        ):
            raise SessaoInvalidaError()
        yield sessao
