# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""services.reputacao: cache em Postgres isolado por tenant, com TTL."""
from unittest.mock import patch

import pytest

from sentinela.core import reputacao as core_reputacao
from sentinela.services import reputacao as servico
from tests.sql_cru import buscar_um, executar

pytestmark = pytest.mark.integration

_IPS_DE_TESTE = ["203.0.113.30", "203.0.113.31", "203.0.113.32"]


@pytest.fixture(autouse=True)
async def _limpar_cache_reputacao_postgres(db):
    """
    reputacao_cache é isolado por empresa e protegido por RLS; a limpeza usa o
    superadmin para garantir que entradas de testes anteriores não interfiram.
    Sem isso, uma execução anterior da suíte (que cacheou um dos IPs fixos
    usados aqui, dentro do TTL) faz um teste seguinte ver 0 chamadas de rede
    onde esperava 1 -- um falso positivo de "cache funcionando", não uma
    verificação de verdade.
    """
    async with db.superadmin_session() as conn:
        await executar(conn, "DELETE FROM reputacao_cache WHERE ip = ANY($1::inet[])", _IPS_DE_TESTE)
    yield
    async with db.superadmin_session() as conn:
        await executar(conn, "DELETE FROM reputacao_cache WHERE ip = ANY($1::inet[])", _IPS_DE_TESTE)


@pytest.mark.asyncio
async def test_consulta_grava_no_cache_postgres(db, empresa_factory):
    empresa_id = await empresa_factory("Empresa Reputacao")

    with patch.object(core_reputacao, "consultar_abuseipdb", return_value={"score_abuso": 90}), \
         patch.object(core_reputacao, "consultar_virustotal", return_value={"maliciosos": 8}):
        async with db.tenant_session(empresa_id) as conn:
            resultado = await servico.consultar_reputacao_ip(conn, empresa_id, "203.0.113.30")

    assert resultado["classificacao"] == "ALTO RISCO"

    async with db.tenant_session(empresa_id) as conn:
        linha = await buscar_um(conn, "SELECT classificacao FROM reputacao_cache WHERE ip = '203.0.113.30'")
    assert linha["classificacao"] == "ALTO RISCO"


@pytest.mark.asyncio
async def test_segunda_consulta_dentro_do_ttl_usa_cache_nao_bate_de_novo_na_rede(db, empresa_factory):
    empresa_id = await empresa_factory("Empresa Reputacao Cache Hit")

    with patch.object(core_reputacao, "consultar_abuseipdb", return_value={"score_abuso": 10}) as abuse_mock, \
         patch.object(core_reputacao, "consultar_virustotal", return_value={"maliciosos": 0}) as vt_mock:
        async with db.tenant_session(empresa_id) as conn:
            await servico.consultar_reputacao_ip(conn, empresa_id, "203.0.113.31", ttl_horas=24)
            await servico.consultar_reputacao_ip(conn, empresa_id, "203.0.113.31", ttl_horas=24)

    abuse_mock.assert_called_once()
    vt_mock.assert_called_once()


@pytest.mark.asyncio
async def test_cache_expirado_bate_na_rede_de_novo(db, empresa_factory):
    empresa_id = await empresa_factory("Empresa Reputacao Cache Expirado")

    with patch.object(core_reputacao, "consultar_abuseipdb", return_value={"score_abuso": 10}) as abuse_mock, \
         patch.object(core_reputacao, "consultar_virustotal", return_value={"maliciosos": 0}):
        async with db.tenant_session(empresa_id) as conn:
            await servico.consultar_reputacao_ip(conn, empresa_id, "203.0.113.32", ttl_horas=0)
            await servico.consultar_reputacao_ip(conn, empresa_id, "203.0.113.32", ttl_horas=0)

    assert abuse_mock.call_count == 2
