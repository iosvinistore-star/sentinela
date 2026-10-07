# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testes de unidade de sentinela.auth.rbac -- lógica pura (resolução de papel,
matriz de permissões, guarda de auto-promoção), sem precisar de Postgres.
Os testes de INTEGRAÇÃO (dependências FastAPI de verdade, contra rotas
reais) ficam em tests/security/test_rbac_privilege_escalation.py e nos
testes de MFA/isolamento -- este arquivo cobre só o "cérebro" da RBAC.
"""
import pytest
from fastapi import HTTPException

from sentinela.auth import rbac


# ---------------------------------------------------------------------------
# resolver_papel_conceitual -- mapeamento de sessão -> um dos 5 papéis.
# ---------------------------------------------------------------------------

def test_usuario_admin_mapeia_para_company_admin():
    assert rbac.resolver_papel_conceitual({"papel": "admin"}) == rbac.COMPANY_ADMIN


def test_usuario_analista_mapeia_para_security_analyst():
    assert rbac.resolver_papel_conceitual({"papel": "analista"}) == rbac.SECURITY_ANALYST


def test_usuario_viewer_mapeia_para_viewer():
    assert rbac.resolver_papel_conceitual({"papel": "viewer"}) == rbac.VIEWER


def test_superadmin_com_papel_saas_owner_mapeia_para_saas_owner():
    assert rbac.resolver_papel_conceitual({"papel": "superadmin", "papel_saas": "saas_owner"}) == rbac.SAAS_OWNER


def test_superadmin_com_papel_saas_admin_mapeia_para_saas_admin():
    assert rbac.resolver_papel_conceitual({"papel": "superadmin", "papel_saas": "saas_admin"}) == rbac.SAAS_ADMIN


def test_superadmin_sem_claim_papel_saas_e_tratado_como_owner_para_compatibilidade():
    """Token emitido ANTES da Fase C (sem a claim nova) -- ver
    auth/rbac.py:resolver_papel_conceitual e a mesma regra em
    auth/dependencies.py:conexao_superadmin/web/deps.py:conexao_superadmin_web."""
    assert rbac.resolver_papel_conceitual({"papel": "superadmin"}) == rbac.SAAS_OWNER


def test_papel_desconhecido_levanta_value_error():
    with pytest.raises(ValueError):
        rbac.resolver_papel_conceitual({"papel": "engenheiro-chefe"})


def test_papel_saas_desconhecido_levanta_value_error():
    with pytest.raises(ValueError):
        rbac.resolver_papel_conceitual({"papel": "superadmin", "papel_saas": "saas_deus"})


# ---------------------------------------------------------------------------
# Matriz de permissões -- cobertura dos 5 papéis (C1/C2).
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("papel", rbac.TODOS_OS_PAPEIS)
def test_todo_papel_tem_uma_entrada_na_matriz(papel):
    assert papel in rbac.ROLE_PERMISSIONS


def test_saas_owner_tem_todas_as_permissoes_exclusivas():
    permissoes_owner = rbac.ROLE_PERMISSIONS[rbac.SAAS_OWNER]
    assert rbac.PERM_LICENSES_REVOKE in permissoes_owner
    assert rbac.PERM_SAAS_MANAGE_ADMINS in permissoes_owner
    assert rbac.PERM_TENANTS_DELETE in permissoes_owner


def test_saas_admin_nao_herda_privilegios_exclusivos_do_owner():
    """C1: 'o SaaS Admin NÃO deve herdar automaticamente privilégios exclusivos do Owner'."""
    permissoes_admin = rbac.ROLE_PERMISSIONS[rbac.SAAS_ADMIN]
    assert rbac.PERM_LICENSES_REVOKE not in permissoes_admin
    assert rbac.PERM_SAAS_MANAGE_ADMINS not in permissoes_admin
    assert rbac.PERM_TENANTS_DELETE not in permissoes_admin


def test_company_admin_nao_tem_permissoes_de_saas():
    permissoes = rbac.ROLE_PERMISSIONS[rbac.COMPANY_ADMIN]
    assert rbac.PERM_TENANTS_CREATE not in permissoes
    assert rbac.PERM_LICENSES_REVOKE not in permissoes
    assert rbac.PERM_SAAS_MANAGE_ADMINS not in permissoes


def test_security_analyst_nao_administra_usuarios_nem_settings():
    permissoes = rbac.ROLE_PERMISSIONS[rbac.SECURITY_ANALYST]
    assert rbac.PERM_USERS_CREATE not in permissoes
    assert rbac.PERM_USERS_DELETE not in permissoes
    assert rbac.PERM_USERS_CHANGE_ROLE not in permissoes
    assert rbac.PERM_SETTINGS_UPDATE not in permissoes
    # Mas PODE agir em segurança (bloquear/desbloquear IP) e ver/gerir incidentes.
    assert rbac.PERM_SECURITY_BLOCK_IP in permissoes
    assert rbac.PERM_INCIDENTS_MANAGE in permissoes


def test_viewer_e_estritamente_somente_leitura():
    """C1: Viewer NUNCA pode criar/editar/excluir/bloquear/desbloquear/
    alterar permissões/licenciamento/administrar usuários ou Agents."""
    permissoes = rbac.ROLE_PERMISSIONS[rbac.VIEWER]
    permissoes_de_escrita = {p for p in permissoes if not p.endswith(".read")}
    assert permissoes_de_escrita == set()
    assert rbac.PERM_USERS_CREATE not in permissoes
    assert rbac.PERM_USERS_DELETE not in permissoes
    assert rbac.PERM_SECURITY_BLOCK_IP not in permissoes
    assert rbac.PERM_SECURITY_UNBLOCK_IP not in permissoes
    assert rbac.PERM_AGENTS_REGISTER not in permissoes
    assert rbac.PERM_AGENTS_REVOKE not in permissoes
    assert rbac.PERM_LICENSES_MANAGE not in permissoes
    assert rbac.PERM_USERS_CHANGE_ROLE not in permissoes


def test_papel_tem_permissao_helper():
    assert rbac.papel_tem_permissao(rbac.COMPANY_ADMIN, rbac.PERM_USERS_CREATE) is True
    assert rbac.papel_tem_permissao(rbac.VIEWER, rbac.PERM_USERS_CREATE) is False
    assert rbac.papel_tem_permissao("PAPEL_INEXISTENTE", rbac.PERM_USERS_CREATE) is False


# ---------------------------------------------------------------------------
# Guarda contra auto-promoção (C11).
# ---------------------------------------------------------------------------

def test_alterar_o_proprio_papel_e_recusado():
    sessao = {"sub": "11111111-1111-1111-1111-111111111111"}
    with pytest.raises(HTTPException) as exc_info:
        rbac.validar_troca_de_papel_nao_e_autopromocao(sessao, "11111111-1111-1111-1111-111111111111")
    assert exc_info.value.status_code == 403


def test_alterar_papel_de_outro_usuario_e_permitido_por_esta_guarda():
    """Esta guarda só bloqueia AUTO-promoção -- a autorização de alterar o
    papel de OUTRO usuário é decisão de uma camada diferente (RBAC/RLS)."""
    sessao = {"sub": "11111111-1111-1111-1111-111111111111"}
    rbac.validar_troca_de_papel_nao_e_autopromocao(sessao, "22222222-2222-2222-2222-222222222222")  # não levanta
