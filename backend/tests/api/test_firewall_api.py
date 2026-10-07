# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
/api/v1/firewall/bloqueios -- listar é para qualquer usuário logado;
bloquear/desbloquear é admin-only (ação host-wide, ver services/firewall.py).
"""
from unittest.mock import MagicMock, patch

import pytest

from sentinela.core import firewall as core_firewall
from tests.api.conftest_api import logar

pytestmark = pytest.mark.integration


def _resultado(returncode=0, stdout=""):
    r = MagicMock()
    r.returncode = returncode
    r.stdout = stdout
    return r


def _fake_subprocess_run(cmd, **kwargs):
    if cmd[:2] == ["ipset", "test"]:
        return _resultado(returncode=1)
    if cmd[:2] == ["ipset", "save"] or (cmd and cmd[0] in ("iptables-save", "ip6tables-save")):
        return _resultado(stdout="# mock\n")
    if len(cmd) >= 2 and cmd[1] == "-C":
        return _resultado(returncode=0)
    return _resultado()


@pytest.mark.asyncio
async def test_analista_nao_pode_bloquear_ip(client, analista_de_teste):
    await logar(client, analista_de_teste["email"], analista_de_teste["senha"])
    resp = await client.post(
        "/api/v1/firewall/bloqueios",
        json={"ip": "203.0.113.80", "motivo": "teste", "dry_run": True},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_admin_bloqueia_e_lista_e_remove(client, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])

    with patch.object(core_firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(core_firewall.subprocess, "run", side_effect=_fake_subprocess_run):
        resp_bloquear = await client.post(
            "/api/v1/firewall/bloqueios",
            json={"ip": "203.0.113.81", "motivo": "teste admin", "dry_run": False, "duracao_horas": 1},
            headers={"X-Sentinela-CSRF": "1"},
        )
        assert resp_bloquear.status_code == 200
        assert resp_bloquear.json()["resultado"]["status"] == "bloqueado"

        resp_lista = await client.get("/api/v1/firewall/bloqueios")
        ips = [b["ip"] for b in resp_lista.json()["bloqueios"]]
        assert "203.0.113.81" in ips

        resp_remover = await client.delete(
            "/api/v1/firewall/bloqueios/203.0.113.81", headers={"X-Sentinela-CSRF": "1"}
        )
        assert resp_remover.status_code == 200
        assert resp_remover.json()["resultado"]["status"] == "desbloqueado"


# Capacidade 4 do modo autônomo -- curadoria de IPs protegidos (ver
# services/automacao.py e migrations/0014_autonomia_operacional.sql).

@pytest.mark.asyncio
async def test_analista_nao_pode_proteger_ip_mas_pode_listar(client, analista_de_teste):
    await logar(client, analista_de_teste["email"], analista_de_teste["senha"])
    resp_proteger = await client.post(
        "/api/v1/firewall/ips-protegidos",
        json={"ip": "203.0.113.82", "motivo": "teste"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_proteger.status_code == 403

    resp_listar = await client.get("/api/v1/firewall/ips-protegidos")
    assert resp_listar.status_code == 200
    assert resp_listar.json()["ips_protegidos"] == []


@pytest.mark.asyncio
async def test_admin_protege_lista_e_remove_ip(client, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])

    resp_proteger = await client.post(
        "/api/v1/firewall/ips-protegidos",
        json={"ip": "203.0.113.83", "motivo": "IP do escritório"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_proteger.status_code == 200
    assert resp_proteger.json()["ip_protegido"]["ip"] == "203.0.113.83"
    assert resp_proteger.json()["ip_protegido"]["origem"] == "manual"

    resp_lista = await client.get("/api/v1/firewall/ips-protegidos")
    ips = [p["ip"] for p in resp_lista.json()["ips_protegidos"]]
    assert "203.0.113.83" in ips

    resp_remover = await client.delete(
        "/api/v1/firewall/ips-protegidos/203.0.113.83", headers={"X-Sentinela-CSRF": "1"}
    )
    assert resp_remover.status_code == 200

    resp_lista_depois = await client.get("/api/v1/firewall/ips-protegidos")
    assert resp_lista_depois.json()["ips_protegidos"] == []


@pytest.mark.asyncio
async def test_remover_ip_protegido_inexistente_e_404(client, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    resp = await client.delete(
        "/api/v1/firewall/ips-protegidos/203.0.113.84", headers={"X-Sentinela-CSRF": "1"}
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_ip_protegido_nao_e_bloqueado_de_novo(client, usuario_de_teste):
    """Fim a fim: um IP protegido via API nunca é bloqueado por uma
    chamada subsequente a /firewall/bloqueios, mesmo sem o chamador passar
    whitelist."""
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])

    resp_proteger = await client.post(
        "/api/v1/firewall/ips-protegidos",
        json={"ip": "203.0.113.85", "motivo": "teste"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp_proteger.status_code == 200

    with patch.object(core_firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(core_firewall.subprocess, "run", side_effect=_fake_subprocess_run) as run_mock:
        resp_bloquear = await client.post(
            "/api/v1/firewall/bloqueios",
            json={"ip": "203.0.113.85", "motivo": "teste", "dry_run": False},
            headers={"X-Sentinela-CSRF": "1"},
        )
    assert resp_bloquear.status_code == 200
    assert resp_bloquear.json()["resultado"]["status"] == "ignorado"
    run_mock.assert_not_called()
