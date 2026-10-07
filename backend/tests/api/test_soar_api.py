# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""SOAR: validação de gatilho, edição, execuções e acionamento manual honesto (V8.2)."""
import pytest

from tests.api.conftest_api import logar

CSRF = {"X-Sentinela-CSRF": "1"}


@pytest.mark.asyncio
async def test_gatilho_invalido_e_recusado(client, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    r = await client.post("/api/v1/soar/playbooks", headers=CSRF, json={"nome": "pb", "gatilho": "cti_macth"})
    assert r.status_code == 422
    r = await client.post("/api/v1/soar/playbooks", headers=CSRF,
                          json={"nome": "pb", "gatilho": "cti_match", "acoes": [{"fila": "sem tipo"}]})
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_editar_desativar_e_acionar(client, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    r = await client.post("/api/v1/soar/playbooks", headers=CSRF,
                          json={"nome": "Conter IOC", "gatilho": "cti_match", "acoes": [{"tipo": "bloquear_ip"}]})
    assert r.status_code == 200, r.text
    pb = r.json()
    assert pb["acoes"] == [{"tipo": "bloquear_ip"}]

    r = await client.post(f"/api/v1/soar/playbooks/{pb['id']}/executar", headers=CSRF)
    assert r.status_code == 200 and r.json()["status"] == "ACIONADO_MANUAL" and r.json()["registrado"] is True

    r = await client.patch(f"/api/v1/soar/playbooks/{pb['id']}", headers=CSRF, json={"ativo": False, "nome": "Conter IOC v2"})
    assert r.status_code == 200 and r.json()["ativo"] is False and r.json()["nome"] == "Conter IOC v2"

    r = await client.post(f"/api/v1/soar/playbooks/{pb['id']}/executar", headers=CSRF)
    assert r.status_code == 404

    execs = (await client.get("/api/v1/soar/execucoes")).json()
    assert [e["status"] for e in execs] == ["ACIONADO_MANUAL"] and execs[0]["playbook"] == "Conter IOC v2"
    assert (await client.patch("/api/v1/soar/playbooks/999999", headers=CSRF, json={"ativo": True})).status_code == 404
    assert len((await client.get("/api/v1/soar/gatilhos")).json()) == 7
