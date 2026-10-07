# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""GET /api/v1/auditoria -- admin-only; populado automaticamente por ações
administrativas sensíveis (ver services/firewall.py, services/usuarios.py)."""
from unittest.mock import MagicMock, patch

import pytest

from sentinela.core import firewall as core_firewall
from tests.api.conftest_api import logar

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_analista_nao_acessa_auditoria(client, analista_de_teste):
    await logar(client, analista_de_teste["email"], analista_de_teste["senha"])
    resp = await client.get("/api/v1/auditoria")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_bloqueio_de_firewall_gera_entrada_de_auditoria(client, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])

    with patch.object(core_firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(core_firewall.subprocess, "run", return_value=MagicMock(returncode=1, stdout="")):
        await client.post(
            "/api/v1/firewall/bloqueios",
            json={"ip": "203.0.113.95", "motivo": "auditoria teste", "dry_run": False},
            headers={"X-Sentinela-CSRF": "1"},
        )

    resp = await client.get("/api/v1/auditoria")
    assert resp.status_code == 200
    acoes = [a["acao"] for a in resp.json()["auditoria"]]
    assert "firewall.bloqueio_registrado" in acoes
