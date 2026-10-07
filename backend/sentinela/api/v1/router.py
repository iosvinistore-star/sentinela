# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Agrega todos os sub-routers de /api/v1."""
from fastapi import APIRouter

from sentinela.api.v1 import admin as admin_router
from sentinela.api.v1 import agentes as agentes_router
from sentinela.api.v1 import auditoria as auditoria_router
from sentinela.api.v1 import auth as auth_router
from sentinela.api.v1 import firewall as firewall_router
from sentinela.api.v1 import dashboard as dashboard_router
from sentinela.api.v1 import incidentes as incidentes_router
from sentinela.api.v1 import licencas as licencas_router
from sentinela.api.v1 import logs as logs_router
from sentinela.api.v1 import push as push_router
from sentinela.api.v1 import reputacao as reputacao_router
from sentinela.api.v1 import setup as setup_router
from sentinela.api.v1 import siem as siem_router
from sentinela.api.v1 import siem_fontes as siem_fontes_router
from sentinela.api.v1 import siem_dashboard as siem_dashboard_router
from sentinela.api.v1 import cti as cti_router
from sentinela.api.v1 import soar as soar_router
from sentinela.api.v1 import ueba as ueba_router
from sentinela.api.v1 import sigma as sigma_router
from sentinela.api.v1 import edr as edr_router
from sentinela.api.v1 import cti_feed as cti_feed_router
from sentinela.api.v1 import usuarios as usuarios_router

router = APIRouter()
# Primeiro acesso: precisa vir ANTES de tudo que exige login -- ver api/v1/setup.py.
router.include_router(setup_router.router)
router.include_router(auth_router.router)
router.include_router(logs_router.router)
router.include_router(incidentes_router.router)
router.include_router(firewall_router.router)
router.include_router(dashboard_router.router)
router.include_router(reputacao_router.router)
router.include_router(siem_router.router)
router.include_router(siem_fontes_router.router)
router.include_router(siem_dashboard_router.router)
router.include_router(cti_router.router)
router.include_router(soar_router.router)
router.include_router(ueba_router.router)
router.include_router(sigma_router.router)
router.include_router(edr_router.router)
router.include_router(cti_feed_router.router)
router.include_router(push_router.router)
router.include_router(usuarios_router.router)
router.include_router(auditoria_router.router)
router.include_router(admin_router.router)
router.include_router(agentes_router.router)
# Sentinela SaaS -- licenciamento (ver ARQUITETURA_LICENCIAMENTO.md). Dois
# routers no mesmo módulo: `router` (agent-facing, prefix "/licencas") e
# `admin_router` (superadmin, prefix "/admin" -- coexiste com o admin_router
# de api/v1/admin.py acima sem colisão: paths internos diferentes, ex.
# "/admin/planos", "/admin/empresas/{id}/licencas", "/admin/licencas/{id}/...").
router.include_router(licencas_router.router)
router.include_router(licencas_router.admin_router)
