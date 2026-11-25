# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Rotas de consulta/CRUD do SIEM que passaram a usar repositórios: painéis, fontes, UEBA, EDR, filtros de eventos,
Sigma/SOAR (listagens) e CTI (feed). Cada teste confere o contrato HTTP de ponta a ponta (RLS incluída).
"""
import pytest

from tests.api.conftest_api import logar

CSRF = {"X-Sentinela-CSRF": "1"}


async def _logar(client, usuario):
    r = await logar(client, usuario["email"], usuario["senha"])
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_eventos_ingestao_individual_e_filtros(client, usuario_de_teste):
    await _logar(client, usuario_de_teste)
    r = await client.post("/api/v1/siem/eventos", headers=CSRF, json={
        "source": "fw1", "source_type": "firewall", "message": "negado", "severity": "high", "source_ip": "198.51.100.7",
        "tags": ["a"],
    })
    assert r.status_code == 200, r.text
    assert r.json()["recebidos"] == 1 and isinstance(r.json()["evento_id"], int)
    await client.post("/api/v1/siem/eventos", headers=CSRF, json={"source": "srv", "source_type": "syslog", "message": "ok"})

    todos = (await client.get("/api/v1/siem/eventos")).json()
    assert len(todos) == 2
    altos = (await client.get("/api/v1/siem/eventos?severidade=high")).json()
    assert [e["source"] for e in altos] == ["fw1"]
    assert altos[0]["source_ip"] == "198.51.100.7" and altos[0]["tags"] == ["a"]
    por_tipo = (await client.get("/api/v1/siem/eventos?source_type=syslog")).json()
    assert [e["source"] for e in por_tipo] == ["srv"]

    assert (await client.post("/api/v1/siem/eventos/lote", headers=CSRF, json=[])).status_code == 422


@pytest.mark.asyncio
async def test_paineis_resumo_fontes_e_soc_executivo(client, usuario_de_teste):
    await _logar(client, usuario_de_teste)
    lote = [
        {"source": "dc01", "source_type": "windows_event_log", "event_type": "4625", "severity": "CRITICAL",
         "message": "falha", "username": "ana"},
        {"source": "dc01", "source_type": "windows_event_log", "message": "info", "severity": "INFO"},
        {"source": "sw1", "source_type": "snmp", "message": "trap", "severity": "WARNING"},
    ]
    assert (await client.post("/api/v1/siem/eventos/lote", headers=CSRF, json=lote)).status_code == 200

    r = await client.get("/api/v1/siem/dashboard/resumo?horas=24")
    assert r.status_code == 200, r.text
    corpo = r.json()
    assert corpo["total_eventos"] == 3 and corpo["criticos"] == 1 and corpo["janela_horas"] == 24
    assert {f["source_type"]: f["eventos"] for f in corpo["fontes"]} == {"windows_event_log": 2, "snmp": 1}
    assert {s["severity"]: s["eventos"] for s in corpo["severidades"]} == {"CRITICAL": 1, "INFO": 1, "WARNING": 1}
    assert sum(m["eventos"] for m in corpo["por_minuto"]) == 3

    fontes = (await client.get("/api/v1/siem/dashboard/fontes")).json()
    assert {f["source"] for f in fontes} == {"dc01", "sw1"}
    assert all(f["eventos_15m"] >= 1 for f in fontes)

    soc = (await client.get("/api/v1/siem/dashboard/soc-executivo")).json()
    assert soc["janela"] == "24h" and soc["eventos"] == 3 and soc["alto_risco"] == 1
    assert set(soc) >= {"correlacoes", "ueba_anomalias", "sigma_alertas", "edr_telemetria"}


@pytest.mark.asyncio
async def test_fontes_siem_crud_e_nome_duplicado(client, usuario_de_teste):
    await _logar(client, usuario_de_teste)
    corpo = {"nome": "Firewall Matriz", "tipo": "SYSLOG", "configuracao": {"porta": 514}, "ativo": True}
    r = await client.post("/api/v1/siem/fontes", headers=CSRF, json=corpo)
    assert r.status_code == 200, r.text
    fonte = r.json()
    assert fonte["tipo"] == "syslog" and fonte["configuracao"] == {"porta": 514}

    # nome repetido (sem distinguir maiúsculas) é 409 -- e a sessão continua utilizável depois do erro
    r = await client.post("/api/v1/siem/fontes", headers=CSRF, json={**corpo, "nome": "FIREWALL MATRIZ"})
    assert r.status_code == 409
    assert [f["nome"] for f in (await client.get("/api/v1/siem/fontes")).json()] == ["Firewall Matriz"]

    r = await client.patch(f"/api/v1/siem/fontes/{fonte['id']}", headers=CSRF, json={**corpo, "ativo": False})
    assert r.status_code == 200 and r.json()["ativo"] is False
    assert (await client.patch("/api/v1/siem/fontes/999999", headers=CSRF, json=corpo)).status_code == 404

    assert (await client.delete(f"/api/v1/siem/fontes/{fonte['id']}", headers=CSRF)).status_code == 200
    assert (await client.delete(f"/api/v1/siem/fontes/{fonte['id']}", headers=CSRF)).status_code == 404
    assert (await client.get("/api/v1/siem/fontes")).json() == []


@pytest.mark.asyncio
async def test_ueba_pico_gera_anomalia_e_reavaliar_e_idempotente(client, usuario_de_teste):
    await _logar(client, usuario_de_teste)
    # volume bem acima do mínimo para uma entidade nova (VOLUME_MINIMO * FATOR_ENTIDADE_NOVA eventos na última hora)
    lote = [{"source": "dc", "source_type": "windows_event_log", "message": f"logon {i}", "username": "rogerio",
             "event_type": "failed_logon", "severity": "WARNING"} for i in range(250)]
    r = await client.post("/api/v1/siem/eventos/lote", headers=CSRF, json=lote)
    assert r.status_code == 200, r.text

    anomalias = (await client.get("/api/v1/ueba/anomalias")).json()
    assert len(anomalias) == 1
    a = anomalias[0]
    assert a["chave"] == "usuario:rogerio" and a["tipo"] == "usuario" and a["score"] > 0
    assert a["evidencias"]["total_hora"] >= 250

    r = await client.post("/api/v1/ueba/reavaliar", headers=CSRF)
    assert r.status_code == 200, r.text
    assert r.json()["avaliados"] >= 250 and r.json()["entidades_anomalas"] >= 1
    # no máximo uma anomalia por entidade por hora
    assert r.json()["anomalias_criadas"] == 0
    assert len((await client.get("/api/v1/ueba/anomalias")).json()) == 1


@pytest.mark.asyncio
async def test_edr_ingestao_listagem_e_resumo(client, usuario_de_teste):
    await _logar(client, usuario_de_teste)
    r = await client.post("/api/v1/edr/telemetria", headers=CSRF, json={
        "tipo": "conexao", "hostname": "ws-01", "processo": "curl", "pid": 77, "destino_ip": "203.0.113.5",
        "destino_porta": 443, "protocolo": "tcp", "severidade": "high", "detalhes": {"k": "v"},
    })
    assert r.status_code == 200, r.text
    assert {"id", "criado_em"} <= set(r.json())
    await client.post("/api/v1/edr/telemetria", headers=CSRF, json={"tipo": "conexao"})
    await client.post("/api/v1/edr/telemetria", headers=CSRF, json={"tipo": "processo"})

    itens = (await client.get("/api/v1/edr/telemetria")).json()
    assert len(itens) == 3
    completo = next(i for i in itens if i["processo"] == "curl")
    assert completo["destino_ip"] == "203.0.113.5" and completo["severidade"] == "HIGH" and completo["detalhes"] == {"k": "v"}

    resumo = (await client.get("/api/v1/edr/resumo")).json()["24h"]
    assert {i["tipo"]: i["total"] for i in resumo} == {"conexao": 2, "processo": 1}

    assert (await client.post("/api/v1/edr/telemetria", headers=CSRF,
                              json={"tipo": "x", "detalhes": {"a": "x" * 40_000}})).status_code == 413


@pytest.mark.asyncio
async def test_sigma_listagem_alertas_e_regra_atualizada_por_nome(client, usuario_de_teste):
    await _logar(client, usuario_de_teste)
    regra = {"nome": "login_falho", "titulo": "Login falho", "nivel": "high",
             "detection": {"sel": {"event_type": "failed_logon"}, "condition": "sel"}}
    r1 = await client.post("/api/v1/sigma/regras", headers=CSRF, json=regra)
    assert r1.status_code == 200, r1.text
    # mesma empresa + mesmo nome = atualiza (upsert), não duplica
    r2 = await client.post("/api/v1/sigma/regras", headers=CSRF, json={**regra, "titulo": "Login falho v2"})
    assert r2.json()["id"] == r1.json()["id"] and r2.json()["titulo"] == "Login falho v2"
    assert len((await client.get("/api/v1/sigma/regras")).json()) == 1

    await client.post("/api/v1/siem/eventos", headers=CSRF, json={
        "source": "dc", "source_type": "windows_event_log", "event_type": "failed_logon", "message": "x",
    })
    alertas = (await client.get("/api/v1/sigma/alertas")).json()
    assert len(alertas) == 1 and alertas[0]["regra"] == "login_falho" and alertas[0]["evidencias"]["automatico"] is True

    assert (await client.post("/api/v1/sigma/avaliar-evento/987654321", headers=CSRF)).status_code == 404


@pytest.mark.asyncio
async def test_soar_listagem_de_playbooks_e_execucoes_por_correlacao(client, usuario_de_teste):
    await _logar(client, usuario_de_teste)
    r = await client.post("/api/v1/soar/playbooks", headers=CSRF, json={
        "nome": "Alta severidade", "gatilho": "high_severity", "acoes": [{"tipo": "notificar"}]})
    assert r.status_code == 200, r.text
    assert [p["nome"] for p in (await client.get("/api/v1/soar/playbooks")).json()] == ["Alta severidade"]

    # evento HIGH dispara a correlação "high_severity" -> execução registrada (sem ação destrutiva)
    await client.post("/api/v1/siem/eventos", headers=CSRF, json={"source": "x", "message": "m", "severity": "HIGH"})
    execucoes = (await client.get("/api/v1/soar/execucoes")).json()
    assert [e["status"] for e in execucoes] == ["CORRELACIONADO"]
    assert execucoes[0]["playbook"] == "Alta severidade" and execucoes[0]["regra"] == "high_severity"


@pytest.mark.asyncio
async def test_cti_feed_taxii_pagina_com_next(client, usuario_de_teste):
    await _logar(client, usuario_de_teste)
    objetos = [
        {"type": "indicator", "id": f"indicator--{i:08d}-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "pattern_type": "stix",
         "pattern": f"[ipv4-addr:value = '203.0.113.{i}']"} for i in range(1, 4)
    ]
    r = await client.post("/api/v1/cti/stix/bundle", headers=CSRF, json={"type": "bundle", "objects": objetos})
    assert r.json()["importados"] == 3
    # reimportar o mesmo bundle atualiza (upsert por stix_id), não duplica
    await client.post("/api/v1/cti/stix/bundle", headers=CSRF, json={"type": "bundle", "objects": objetos})
    assert len((await client.get("/api/v1/cti/indicadores")).json()) == 3

    base = "/api/v1/cti/taxii/collections/sentinela-indicators/objects"
    pag1 = (await client.get(f"{base}?limite=2")).json()
    assert pag1["more"] is True and len(pag1["objects"]) == 2
    pag2 = (await client.get(f"{base}?limite=2&next={pag1['next']}")).json()
    assert pag2["more"] is False and len(pag2["objects"]) == 1


@pytest.mark.asyncio
async def test_correlacao_cti_marca_match(client, usuario_de_teste):
    await _logar(client, usuario_de_teste)
    await client.post("/api/v1/cti/stix/bundle", headers=CSRF, json={"type": "bundle", "objects": [
        {"type": "indicator", "id": "indicator--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "pattern_type": "stix",
         "pattern": "[ipv4-addr:value = '203.0.113.200']", "valid_until": "2099-01-01T00:00:00Z"}]})
    await client.post("/api/v1/siem/eventos", headers=CSRF, json={
        "source": "fw", "message": "conexao", "source_ip": "203.0.113.200"})
    c = (await client.get("/api/v1/siem/dashboard/correlacoes")).json()
    assert c and c[0]["regra"] == "cti_match"
