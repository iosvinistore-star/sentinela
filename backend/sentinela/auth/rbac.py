# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Fase C -- RBAC (Role-Based Access Control) centralizado.

Este módulo é a ÚNICA fonte de verdade para "quem pode fazer o quê" no
sistema. Antes da Fase C, autorização fina era feita ad-hoc, espalhada em
checagens como `if usuario["papel"] == "admin"` dentro de rotas individuais
(ver `web/routes_logs.py:analisar`, `pode_bloquear = ... usuario["papel"]
== "admin"`) -- funcional, mas sem um lugar único para auditar "o que cada
papel pode fazer", e fácil de esquecer numa rota nova.

Fluxo conceitual (pedido explicitamente pelo spec da Fase C):

    usuário -> tenant -> papel -> permissão -> política de autorização -> endpoint/serviço -> RLS

Este módulo cobre "papel -> permissão -> política" (as camadas
`exigir_permissao`/`exigir_saas_owner`). As camadas antes (tenant já vem do
JWT + é reconferido contra o banco em `conexao_tenant`) e depois (RLS no
Postgres) já existiam e continuam intactas -- este módulo se ENCAIXA nelas,
não as substitui. Ver C3 no spec: autorização de aplicação nunca substitui
RLS, as duas camadas continuam ativas ao mesmo tempo.

## Os 5 papéis conceituais e como mapeiam para o schema existente

O spec da Fase C pede exatamente 5 papéis: SAAS_OWNER, SAAS_ADMIN,
COMPANY_ADMIN, SECURITY_ANALYST, VIEWER -- mas também diz explicitamente
para EVOLUIR o sistema atual em vez de criar um segundo sistema paralelo
(REGRA PRINCIPAL) e para não quebrar a API existente (C15). O sistema atual
já tinha 3 "papéis" espalhados por 2 conceitos independentes:

  - `usuarios.papel` (CHECK IN 'admin', 'analista') -- usuário de EMPRESA
    (tenant), sempre com `empresa_id` não-nulo.
  - a tabela `superadmins`, sem coluna de papel nenhuma até a migration
    0020 -- ou seja, todo superadmin tinha o MESMO poder (equivalente a um
    único papel implícito).

Em vez de renomear essas colunas (o que quebraria o JWT claim `papel` já
consumido por `auth/dependencies.py`, `web/deps.py`, templates HTML etc.),
a migration 0020_rbac_mfa.sql fez a extensão MÍNIMA e ADITIVA:

  - `usuarios.papel` ganhou um terceiro valor possível: 'viewer'.
  - `superadmins` ganhou uma coluna NOVA, `papel`, com dois valores
    possíveis: 'saas_owner' (default -- superadmins existentes viram Owner
    na migração, o nível de acesso que já tinham) e 'saas_admin'.

O resolvedor de papel abaixo (`resolver_papel_conceitual`) é o único lugar
que faz esse mapeamento -- ele lê a claim `papel` do JWT (para usuários de
empresa) OU a nova claim `papel_saas` (para superadmins, emitida a partir
de Fase C -- ver auth/login.py e api/v1/auth.py/web/routes_auth.py) e
devolve um dos 5 nomes conceituais abaixo. Nenhuma rota deveria mais
comparar `usuario["papel"] == "admin"` diretamente para decidir uma
permissão fina -- só para decidir "é usuário de empresa ou superadmin",
que é uma distinção estrutural diferente (e continua válida, é a mesma
distinção que `exigir_login` x `exigir_superadmin` já faziam).

## Permissões e retrocompatibilidade

`exigir_papel(*papeis)` (auth/dependencies.py) e `exigir_papel_web`
(web/deps.py) continuam existindo e sendo usados nas rotas que já usavam
--- não foram removidos nem preteridos por completo (isso quebraria C15).
O que este módulo adiciona é uma camada MAIS FINA, baseada em permissão em
vez de nome de papel bruto, para as rotas novas da Fase C (MFA
administrativo, gestão de SaaS admins, etc.) e para os pontos identificados
como precisando de controle mais granular (ex.: revogar/suspender licença
agora exige SAAS_OWNER, não qualquer superadmin).
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request

from sentinela.auth.dependencies import exigir_superadmin
from sentinela.web.deps import exigir_superadmin_web

# ---------------------------------------------------------------------------
# Os 5 papéis conceituais (nomes exigidos pelo spec da Fase C, C1).
# ---------------------------------------------------------------------------
SAAS_OWNER = "SAAS_OWNER"
SAAS_ADMIN = "SAAS_ADMIN"
COMPANY_ADMIN = "COMPANY_ADMIN"
SECURITY_ANALYST = "SECURITY_ANALYST"
VIEWER = "VIEWER"

TODOS_OS_PAPEIS = (SAAS_OWNER, SAAS_ADMIN, COMPANY_ADMIN, SECURITY_ANALYST, VIEWER)

# Papéis de SaaS (sem empresa_id -- administram a plataforma) vs. papéis de
# tenant (sempre escopados a uma empresa via RLS). Usado por quem precisa
# decidir isso sem repetir a lista toda vez (ex.: guarda contra
# auto-promoção -- ver C11/`validar_troca_de_papel_nao_e_autopromocao`).
PAPEIS_SAAS = frozenset({SAAS_OWNER, SAAS_ADMIN})
PAPEIS_TENANT = frozenset({COMPANY_ADMIN, SECURITY_ANALYST, VIEWER})


# ---------------------------------------------------------------------------
# Catálogo de permissões.
#
# O spec (C2) sugere nomes mas diz explicitamente que não é obrigatório
# usar exatamente esses -- os nomes abaixo seguem o sugerido, com dois
# grupos adicionados para cobrir a Fase C (mfa.* e saas.*, que não
# existiam no sistema anterior à RBAC).
# ---------------------------------------------------------------------------
PERM_USERS_READ = "users.read"
PERM_USERS_CREATE = "users.create"
PERM_USERS_UPDATE = "users.update"
PERM_USERS_DELETE = "users.delete"

PERM_TENANTS_READ = "tenants.read"
PERM_TENANTS_CREATE = "tenants.create"
PERM_TENANTS_UPDATE = "tenants.update"
PERM_TENANTS_DELETE = "tenants.delete"

PERM_EVENTS_READ = "events.read"

PERM_INCIDENTS_READ = "incidents.read"
PERM_INCIDENTS_MANAGE = "incidents.manage"

PERM_AGENTS_READ = "agents.read"
PERM_AGENTS_REGISTER = "agents.register"
PERM_AGENTS_REVOKE = "agents.revoke"
PERM_AGENTS_UPDATE = "agents.update"

PERM_LICENSES_READ = "licenses.read"
PERM_LICENSES_MANAGE = "licenses.manage"
PERM_LICENSES_REVOKE = "licenses.revoke"

PERM_AUDIT_READ = "audit.read"

PERM_SECURITY_BLOCK_IP = "security.block_ip"
PERM_SECURITY_UNBLOCK_IP = "security.unblock_ip"

PERM_SETTINGS_READ = "settings.read"
PERM_SETTINGS_UPDATE = "settings.update"

# MFA administrativo -- resetar o MFA de OUTRO usuário (C8). Gerir o
# PRÓPRIO MFA (ativar/desativar/regenerar recovery codes) não é uma
# "permissão" no sentido RBAC -- é uma ação de self-service disponível a
# qualquer sessão autenticada (`exigir_login`/`exigir_login_web`), do
# mesmo jeito que `trocar_propria_senha` já é hoje.
PERM_MFA_RESET_OTHERS = "mfa.reset_others"

# Exclusivo de SAAS_OWNER -- criar/gerir outras contas de SaaS Admin (C4:
# "nunca deve permitir que um usuário comum assuma privilégios de SaaS
# manipulando... "). Ver `exigir_saas_owner` abaixo.
PERM_SAAS_MANAGE_ADMINS = "saas.manage_admins"

# Trocar o papel de OUTRO usuário/superadmin (C11) -- deliberadamente
# separado de users.update: um COMPANY_ADMIN pode editar dados de um
# usuário (ex.: nome) sem necessariamente poder promovê-lo/rebaixá-lo.
PERM_USERS_CHANGE_ROLE = "users.change_role"


# ---------------------------------------------------------------------------
# Matriz de permissões (C2). `frozenset` -- imutável de propósito: nenhuma
# rota deveria mutar isto em runtime.
# ---------------------------------------------------------------------------
ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    # SAAS_OWNER: acesso total à plataforma -- todas as permissões,
    # incluindo as exclusivas de Owner (revogar licença, gerir SaaS Admins).
    SAAS_OWNER: frozenset({
        PERM_USERS_READ, PERM_USERS_CREATE, PERM_USERS_UPDATE, PERM_USERS_DELETE,
        PERM_USERS_CHANGE_ROLE,
        PERM_TENANTS_READ, PERM_TENANTS_CREATE, PERM_TENANTS_UPDATE, PERM_TENANTS_DELETE,
        PERM_EVENTS_READ,
        PERM_INCIDENTS_READ, PERM_INCIDENTS_MANAGE,
        PERM_AGENTS_READ, PERM_AGENTS_REGISTER, PERM_AGENTS_REVOKE, PERM_AGENTS_UPDATE,
        PERM_LICENSES_READ, PERM_LICENSES_MANAGE, PERM_LICENSES_REVOKE,
        PERM_AUDIT_READ,
        PERM_SECURITY_BLOCK_IP, PERM_SECURITY_UNBLOCK_IP,
        PERM_SETTINGS_READ, PERM_SETTINGS_UPDATE,
        PERM_MFA_RESET_OTHERS,
        PERM_SAAS_MANAGE_ADMINS,
    }),
    # SAAS_ADMIN: admin operacional da plataforma -- NÃO herda
    # automaticamente os privilégios exclusivos de Owner (C1: "o SaaS Admin
    # NÃO deve herdar automaticamente privilégios exclusivos do Owner").
    # Sem: tenants.delete, licenses.revoke, saas.manage_admins,
    # users.delete (cross-tenant), users.change_role.
    SAAS_ADMIN: frozenset({
        PERM_USERS_READ,
        PERM_TENANTS_READ, PERM_TENANTS_CREATE, PERM_TENANTS_UPDATE,
        PERM_EVENTS_READ,
        PERM_INCIDENTS_READ,
        PERM_AGENTS_READ,
        PERM_LICENSES_READ, PERM_LICENSES_MANAGE,
        PERM_AUDIT_READ,
        PERM_SETTINGS_READ,
    }),
    # COMPANY_ADMIN: administra SOMENTE o próprio tenant (usuários, config,
    # Agents, incidentes/eventos) -- o escopo de tenant em si é imposto por
    # RLS + `conexao_tenant`, não por este módulo; aqui só decidimos QUAIS
    # ações um Company Admin pode fazer, nunca EM QUAL empresa.
    COMPANY_ADMIN: frozenset({
        PERM_USERS_READ, PERM_USERS_CREATE, PERM_USERS_UPDATE, PERM_USERS_DELETE,
        PERM_USERS_CHANGE_ROLE,
        PERM_EVENTS_READ,
        PERM_INCIDENTS_READ, PERM_INCIDENTS_MANAGE,
        PERM_AGENTS_READ, PERM_AGENTS_REGISTER, PERM_AGENTS_REVOKE, PERM_AGENTS_UPDATE,
        PERM_AUDIT_READ,
        PERM_SECURITY_BLOCK_IP, PERM_SECURITY_UNBLOCK_IP,
        PERM_SETTINGS_READ, PERM_SETTINGS_UPDATE,
        PERM_MFA_RESET_OTHERS,
    }),
    # SECURITY_ANALYST: investiga eventos/incidentes, ações de segurança
    # explicitamente autorizadas (bloquear/desbloquear IP) -- não administra
    # usuários nem configurações (C1: "não pode administrar SaaS nem alterar
    # configurações administrativas de usuários sem permissão explícita").
    SECURITY_ANALYST: frozenset({
        PERM_EVENTS_READ,
        PERM_INCIDENTS_READ, PERM_INCIDENTS_MANAGE,
        PERM_AGENTS_READ,
        PERM_AUDIT_READ,
        PERM_SECURITY_BLOCK_IP, PERM_SECURITY_UNBLOCK_IP,
    }),
    # VIEWER: somente leitura sobre recursos explicitamente permitidos.
    # Deliberadamente SEM users.read/audit.read/settings.read -- dados de
    # outros usuários e trilha de auditoria não são "recursos explicitamente
    # permitidos" por padrão (C1: nunca pode criar/editar/excluir/
    # bloquear/desbloquear/alterar permissões/licenciamento/administrar
    # usuários ou Agents -- e a lista de LEITURA permitida também é
    # deliberadamente mínima, não "tudo que não seja escrita").
    VIEWER: frozenset({
        PERM_EVENTS_READ,
        PERM_INCIDENTS_READ,
        PERM_AGENTS_READ,
    }),
}


def resolver_papel_conceitual(sessao: dict) -> str:
    """
    Mapeia uma sessão decodificada do JWT (dict com as claims de
    `usuario_atual`/`exigir_superadmin`) para um dos 5 papéis conceituais.

    Superadmin: usa a claim `papel_saas` (nova, Fase C) -- 'saas_owner' ou
    'saas_admin'. Uma sessão de superadmin SEM essa claim (token emitido
    antes da Fase C, ainda não expirado) é tratada como SAAS_OWNER -- o
    nível de acesso que TODO superadmin tinha antes da distinção existir,
    preservando compatibilidade (C15: nenhuma sessão já aberta perde
    acesso por causa de uma migração aditiva).

    Usuário de empresa: usa a claim `papel` existente -- 'admin',
    'analista' ou 'viewer' (este último só possível a partir da migration
    0020, então nenhum token pré-existente pode ter um valor inesperado
    aqui).

    Levanta ValueError para qualquer claim fora do esperado -- nunca
    devolve um papel "default" silencioso para uma claim desconhecida
    (fail-closed, não fail-open).
    """
    if sessao.get("papel") == "superadmin":
        papel_saas = sessao.get("papel_saas") or "saas_owner"
        if papel_saas == "saas_owner":
            return SAAS_OWNER
        if papel_saas == "saas_admin":
            return SAAS_ADMIN
        raise ValueError(f"papel_saas desconhecido na sessão: {papel_saas!r}")

    papel = sessao.get("papel")
    if papel == "admin":
        return COMPANY_ADMIN
    if papel == "analista":
        return SECURITY_ANALYST
    if papel == "viewer":
        return VIEWER
    raise ValueError(f"papel desconhecido na sessão: {papel!r}")


def papel_tem_permissao(papel_conceitual: str, permissao: str) -> bool:
    return permissao in ROLE_PERMISSIONS.get(papel_conceitual, frozenset())


def _permissoes_negadas_ao_papel(papel_conceitual: str) -> str:
    return f"o papel {papel_conceitual} não tem a permissão exigida para esta ação"


# ---------------------------------------------------------------------------
# Dependências FastAPI -- lado API (JSON).
# ---------------------------------------------------------------------------

def exigir_permissao(*permissoes_exigidas: str):
    """
    Uso: `Depends(exigir_permissao("licenses.revoke"))`. Encadeia sobre
    `usuario_atual`, aceitando tanto sessão de usuário de empresa quanto de
    superadmin (ao contrário de `exigir_login`/`exigir_superadmin`, que são
    mutuamente exclusivos) -- a checagem de QUEM pode fazer o quê passa a
    ser só a permissão, não a "família" de conta.

    Todas as permissões passadas precisam estar presentes (AND, não OR) --
    nenhum chamador atual precisa de OR: se isso mudar no futuro, um
    segundo helper (`exigir_qualquer_permissao`) deve ser adicionado em vez
    de sobrecarregar este.

    Emite PERMISSION_DENIED via auditoria (C10) quando a checagem falha,
    para que tentativas de escalação de privilégio fiquem registradas
    mesmo quando bem-sucedidas em nenhuma outra rota fazem isso sozinhas.
    """
    async def dependencia(request: Request) -> dict:
        from sentinela.auth.dependencies import usuario_atual

        sessao = await usuario_atual(request)
        if sessao is None:
            raise HTTPException(status_code=401, detail="login necessário")
        try:
            papel_conceitual = resolver_papel_conceitual(sessao)
        except ValueError:
            raise HTTPException(status_code=401, detail="sessão inválida -- faça login novamente")

        faltando = [p for p in permissoes_exigidas if not papel_tem_permissao(papel_conceitual, p)]
        if faltando:
            await _auditar_permissao_negada(request, sessao, papel_conceitual, faltando)
            raise HTTPException(status_code=403, detail=_permissoes_negadas_ao_papel(papel_conceitual))

        sessao["papel_conceitual"] = papel_conceitual
        return sessao
    return dependencia


async def _auditar_permissao_negada(request: Request, sessao: dict, papel_conceitual: str, faltando: list[str]):
    """
    Best-effort: uma falha ao auditar nunca deve impedir o 403 de ser
    devolvido (o 403 em si já é a proteção -- a auditoria é só rastro).
    Import local para evitar import circular (services.auditoria não
    importa nada deste módulo, mas mantém o padrão já usado no resto do
    código de imports tardios em dependências).

    Abre a conexão RLS-scoped correta conforme o TIPO de sessão -- uma
    sessão de superadmin não tem `empresa_id` (RLS de `auditoria` não se
    aplicaria), então usa `superadmin_scoped_connection`; uma sessão de
    usuário de empresa usa `tenant_scoped_connection` (mesma conexão
    RLS-scoped que qualquer outra escrita em `auditoria` usaria).
    """
    try:
        from sentinela.db.pool import superadmin_scoped_connection, tenant_scoped_connection
        from sentinela.services import auditoria as servico_auditoria

        pool = request.app.state.pool
        detalhes = {
            "papel": papel_conceitual,
            "permissoes_faltando": faltando,
            "rota": str(request.url.path),
            "metodo": request.method,
        }
        if sessao.get("papel") == "superadmin":
            async with superadmin_scoped_connection(pool) as conn:
                await servico_auditoria.registrar_evento(
                    conn, None, "PERMISSION_DENIED", detalhes, ator_superadmin_id=sessao.get("sub"),
                )
        else:
            empresa_id = sessao.get("empresa_id")
            async with tenant_scoped_connection(pool, empresa_id) as conn:
                await servico_auditoria.registrar_evento(
                    conn, empresa_id, "PERMISSION_DENIED", detalhes, ator_usuario_id=sessao.get("sub"),
                )
    except Exception:
        pass


async def exigir_saas_owner(usuario: dict = Depends(exigir_superadmin)) -> dict:
    """
    Uso em operações EXCLUSIVAS de SAAS_OWNER (C4): revogar/suspender
    licença, criar/gerir outras contas de SaaS Admin. Encadeia sobre
    `exigir_superadmin` (já garante que é uma sessão de superadmin) e
    adiciona a checagem de `papel_saas`.
    """
    papel_saas = usuario.get("papel_saas") or "saas_owner"
    if papel_saas != "saas_owner":
        raise HTTPException(status_code=403, detail="ação exclusiva do SaaS Owner")
    return usuario


# ---------------------------------------------------------------------------
# Dependências FastAPI -- lado Web (HTMX). Espelham as de cima, mas
# devolvem 403 real (não redirect) quando é permissão insuficiente numa
# sessão já autenticada -- mesmo padrão que `exigir_papel_web` já usa hoje
# (só a AUSÊNCIA de sessão vira redirect via RedirecionarParaLogin).
# ---------------------------------------------------------------------------

def exigir_permissao_web(*permissoes_exigidas: str):
    async def dependencia(request: Request) -> dict:
        from sentinela.web.deps import RedirecionarParaLogin, usuario_atual

        sessao = await usuario_atual(request)
        if sessao is None:
            raise RedirecionarParaLogin(str(request.url.path))
        try:
            papel_conceitual = resolver_papel_conceitual(sessao)
        except ValueError:
            raise RedirecionarParaLogin(str(request.url.path))

        faltando = [p for p in permissoes_exigidas if not papel_tem_permissao(papel_conceitual, p)]
        if faltando:
            await _auditar_permissao_negada(request, sessao, papel_conceitual, faltando)
            raise HTTPException(status_code=403, detail=_permissoes_negadas_ao_papel(papel_conceitual))

        sessao["papel_conceitual"] = papel_conceitual
        return sessao
    return dependencia


async def exigir_saas_owner_web(usuario: dict = Depends(exigir_superadmin_web)) -> dict:
    papel_saas = usuario.get("papel_saas") or "saas_owner"
    if papel_saas != "saas_owner":
        raise HTTPException(status_code=403, detail="ação exclusiva do SaaS Owner")
    return usuario


# ---------------------------------------------------------------------------
# Guarda contra auto-promoção (C11): "um usuário nunca pode alterar o
# próprio papel para obter privilégios maiores". Usado pelos endpoints de
# troca de papel/promoção antes de aplicar a mudança.
# ---------------------------------------------------------------------------

def validar_troca_de_papel_nao_e_autopromocao(sessao_atual: dict, id_alvo: str):
    """
    Levanta HTTPException 403 se o alvo da troca de papel é a PRÓPRIA
    sessão -- independente de qual papel está sendo pedido (mesmo pedir um
    papel "menor" via este caminho é recusado: a única forma seguro de um
    usuário mudar o próprio nível de acesso é outra pessoa autorizada
    fazer isso por ele, nunca ele mesmo). `id_alvo` é comparado como string
    porque `sessao_atual["sub"]` já vem como string (claim de JWT).
    """
    if str(sessao_atual.get("sub")) == str(id_alvo):
        raise HTTPException(status_code=403, detail="não é permitido alterar o próprio papel")
