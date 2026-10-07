# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Caminho SIEM completo contra Postgres REAL (V8.2).

Até a V8.1 não existia nenhum teste de integração da camada SIEM -- e ela não
funcionava em Postgres real (policies com GUC errado). Estes testes provam:
RLS funcionando nas tabelas SIEM, isolamento entre tenants, correlação CTI/
Sigma/UEBA/SOAR persistida, batcher do Syslog e retenção.
"""
import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from sentinela.db.pool import superadmin_scoped_connection, tenant_scoped_connection
from sentinela.siem.correlacao_siem import correlacionar_lote
from sentinela.siem.retencao import executar_retencao_siem
from sentinela.siem.servico import SIEMBatcher, persistir_eventos_com_ids

pytestmark = pytest.mark.integration


def _ev(**kw):
    base = {"timestamp": datetime.now(timezone.utc), "source": "teste", "source_type": "generic",
            "event_type": "log", "severity": "INFO", "message": "evento de teste"}
    base.update(kw)
    return base


@pytest.mark.asyncio
async def test_tabelas_siem_aceitam_escrita_e_isolam_tenants(pool, empresa_factory):
    """Regressão V8.1: com app.empresa_id na policy, este INSERT falhava com RLS."""
    a = await empresa_factory("SIEM A")
    b = await empresa_factory("SIEM B")
    async with tenant_scoped_connection(pool, a) as conn:
        ids = await persistir_eventos_com_ids(conn, a, [_ev(message="so do A")])
        assert len(ids) == 1
        await conn.execute("INSERT INTO cti_indicadores (empresa_id, stix_id, indicator_type, valor) VALUES ($1,'indicator--a','ipv4-addr','1.2.3.4')", a)
        await conn.execute("INSERT INTO edr_telemetria (empresa_id, tipo) VALUES ($1, 'teste')", a)
    async with tenant_scoped_connection(pool, b) as conn:
        for tabela in ("eventos_siem", "cti_indicadores", "edr_telemetria"):
            assert await conn.fetchval(f"SELECT count(*) FROM {tabela}") == 0, tabela
        with pytest.raises(Exception, match="row-level security"):
            await conn.execute("INSERT INTO edr_telemetria (empresa_id, tipo) VALUES ($1, 'cruzado')", a)
    async with tenant_scoped_connection(pool, a) as conn:
        assert await conn.fetchval("SELECT count(*) FROM eventos_siem") == 1


@pytest.mark.asyncio
async def test_correlacao_cti_sigma_soar_persistida(pool, empresa_factory):
    emp = await empresa_factory("SIEM Correlacao")
    async with tenant_scoped_connection(pool, emp) as conn:
        await conn.execute(
            "INSERT INTO cti_indicadores (empresa_id, stix_id, indicator_type, valor) VALUES ($1,'indicator--c1','ipv4-addr','203.0.113.66')", emp)
        await conn.execute(
            """INSERT INTO sigma_regras (empresa_id, nome, titulo, nivel, logsource, detection)
               VALUES ($1, 'enc_ps', 'PowerShell codificado', 'high', '{"product":"windows"}'::jsonb,
                       '{"sel":{"message|contains":"-enc"},"filtro":{"User":"svc_backup"},"condition":"sel and not filtro"}'::jsonb)""", emp)
        pb = await conn.fetchval(
            "INSERT INTO soar_playbooks (empresa_id, nome, gatilho, acoes) VALUES ($1,'bloquear','cti_match','[{\"tipo\":\"bloquear_ip\"}]'::jsonb) RETURNING id", emp)
        eventos = [
            _ev(source_type="netflow", source_ip="10.0.0.1", destination_ip="203.0.113.66"),   # CTI
            _ev(source_type="windows_event_log", message="powershell -enc AAA", username="joao"),   # Sigma
            _ev(source_type="windows_event_log", message="powershell -enc AAA", username="svc_backup"),  # filtrado
            _ev(source_type="netflow", source_ip="10.0.0.1", destination_ip="198.51.100.1"),   # ruído
        ]
        ids = await persistir_eventos_com_ids(conn, emp, eventos)
        r = await correlacionar_lote(conn, str(emp), list(zip(ids, eventos)))
        assert r["correlacoes"] == 2, r
        assert r["sigma_alertas"] == 1
        assert r["playbooks"] == 1
        regras = {row["regra"]: row for row in await conn.fetch("SELECT regra, cti_match, playbook_id, evento_ids FROM siem_correlacoes")}
        assert regras["cti_match"]["cti_match"] is True and regras["cti_match"]["playbook_id"] == pb
        assert regras["sigma_match"]["evento_ids"] == [ids[1]]
        assert await conn.fetchval("SELECT count(*) FROM soar_execucoes WHERE playbook_id=$1", pb) == 1
        # Reprocessar não duplica alerta Sigma.
        await correlacionar_lote(conn, str(emp), [(ids[1], eventos[1])])
        assert await conn.fetchval("SELECT count(*) FROM sigma_alertas") == 1


@pytest.mark.asyncio
async def test_ueba_pico_por_entidade_gera_uma_anomalia(pool, empresa_factory):
    emp = await empresa_factory("SIEM UEBA")
    async with tenant_scoped_connection(pool, emp) as conn:
        agora = datetime.now(timezone.utc)
        # linha de base: 1 evento/hora nas 24h anteriores para 'maria'
        historico = [_ev(username="maria", timestamp=agora - timedelta(hours=h, minutes=5)) for h in range(1, 25)]
        await persistir_eventos_com_ids(conn, emp, historico)
        pico = [_ev(username="maria", source_type="windows_event_log", event_type="4625") for _ in range(40)]
        normal = [_ev(username="pedro") for _ in range(3)]
        ids = await persistir_eventos_com_ids(conn, emp, pico + normal)
        await correlacionar_lote(conn, str(emp), list(zip(ids, pico + normal)))
        await correlacionar_lote(conn, str(emp), list(zip(ids, pico + normal)))  # reavaliação
        linhas = await conn.fetch("SELECT chave, score, motivo FROM ueba_anomalias")
        assert [r["chave"] for r in linhas] == ["usuario:maria"]
        assert "falhas de autenticação" in linhas[0]["motivo"]


@pytest.mark.asyncio
async def test_batcher_syslog_grava_com_escopo_de_tenant(pool, empresa_factory):
    """Regressão V8.1: o batcher usava pool.acquire() sem SET ROLE -> nada era gravado."""
    emp = await empresa_factory("SIEM Syslog")
    batcher = SIEMBatcher(pool, batch_size=10, flush_interval=0.05)
    await batcher.start()
    for i in range(3):
        assert batcher.put_nowait(str(emp), _ev(source_type="syslog", message=f"linha {i}"))
    await asyncio.sleep(0.4)
    await batcher.stop()
    assert batcher.falhas == 0 and batcher.persistidos == 3
    async with tenant_scoped_connection(pool, emp) as conn:
        assert await conn.fetchval("SELECT count(*) FROM eventos_siem WHERE source_type='syslog'") == 3


@pytest.mark.asyncio
async def test_retencao_arquiva_e_expira(pool, empresa_factory):
    """Regressão V8.1: a retenção rodava sem privilégio e nunca apagava nada."""
    emp = await empresa_factory("SIEM Retencao")
    agora = datetime.now(timezone.utc)
    async with tenant_scoped_connection(pool, emp) as conn:
        await persistir_eventos_com_ids(conn, emp, [
            _ev(message="recente", timestamp=agora - timedelta(days=1)),
            _ev(message="morno", timestamp=agora - timedelta(days=100)),
            _ev(message="velho", timestamp=agora - timedelta(days=400)),
        ])
    async with superadmin_scoped_connection(pool) as conn:
        r = await executar_retencao_siem(conn, 90, 365, tamanho_fatia=1)
    assert r["arquivados"] >= 1 and r["expirados"] >= 1
    async with tenant_scoped_connection(pool, emp) as conn:
        assert [x["message"] for x in await conn.fetch("SELECT message FROM eventos_siem")] == ["recente"]
        assert [x["message"] for x in await conn.fetch("SELECT message FROM eventos_siem_cold")] == ["morno"]


@pytest.mark.asyncio
async def test_lotes_concorrentes_com_mesmas_entidades_nao_dao_deadlock(pool, empresa_factory):
    """Regressão encontrada no benchmark V8.2: upserts de ueba_anomalias em
    ordens diferentes em lotes concorrentes -> DeadlockDetectedError (500)."""
    import random
    emp = await empresa_factory("SIEM Concorrencia")
    agora = datetime.now(timezone.utc)
    usuarios = [f"u{i}" for i in range(30)]
    async with tenant_scoped_connection(pool, emp) as conn:
        await persistir_eventos_com_ids(conn, emp, [_ev(username=u, timestamp=agora - timedelta(hours=2)) for u in usuarios])

    async def lote(seed):
        rng = random.Random(seed)
        evs = [_ev(username=rng.choice(usuarios)) for _ in range(400)]
        rng.shuffle(evs)
        async with tenant_scoped_connection(pool, emp) as conn:
            ids = await persistir_eventos_com_ids(conn, emp, evs)
            await correlacionar_lote(conn, str(emp), list(zip(ids, evs)))

    resultados = await asyncio.gather(*(lote(s) for s in range(6)), return_exceptions=True)
    assert not [r for r in resultados if isinstance(r, Exception)], resultados
