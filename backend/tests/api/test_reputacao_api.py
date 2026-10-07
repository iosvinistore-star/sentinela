# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""GET /api/v1/reputacao/{ip}"""
from unittest.mock import patch

import pytest

from sentinela.core import reputacao as core_reputacao
from tests.api.conftest_api import logar

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_consultar_reputacao_requer_login(client):
    resp = await client.get("/api/v1/reputacao/203.0.113.90")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_consultar_reputacao_com_login(client, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    with patch.object(core_reputacao, "consultar_abuseipdb", return_value={"score_abuso": 90}), \
         patch.object(core_reputacao, "consultar_virustotal", return_value={"maliciosos": 8}):
        resp = await client.get("/api/v1/reputacao/203.0.113.91")
    assert resp.status_code == 200
    assert resp.json()["classificacao"] == "ALTO RISCO"
