# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Agrega todos os sub-routers HTML (HTMX) servidos em `/`."""
from fastapi import APIRouter

from sentinela.web import routes_admin, routes_auth, routes_firewall, routes_incidentes, routes_logs, routes_usuarios

router = APIRouter()
router.include_router(routes_auth.router)
router.include_router(routes_incidentes.router)
router.include_router(routes_firewall.router)
router.include_router(routes_logs.router)
router.include_router(routes_usuarios.router)
router.include_router(routes_admin.router)
