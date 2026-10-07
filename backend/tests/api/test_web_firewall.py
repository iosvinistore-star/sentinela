# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Testes das rotas HTML /firewall (HTMX)."""
from unittest.mock import MagicMock, patch

import pytest

from sentinela.core import firewall as core_firewall

pytestmark = pytest.mark.integration


def _fake_run(cmd, **kwargs):
    if cmd[:2] == ["ipset", "test"]:
        return MagicMock(returncode=1, stdout="")
    return MagicMock(returncode=0, stdout="# mock\n")


@pytest.mark.asyncio
async def test_analista_ve_pagina_mas_sem_formulario_de_bloqueio(client, analista_de_teste):
    await client.post("/login", data={"email": analista_de_teste["email"], "senha": analista_de_teste["senha"]})
    resp = await client.get("/firewall")
    assert resp.status_code == 200
    assert 'name="ip"' not in resp.text


@pytest.mark.asyncio
async def test_admin_bloqueia_via_htmx_e_ve_na_tabela(client, usuario_de_teste):
    await client.post("/login", data={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})

    with patch.object(core_firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(core_firewall.subprocess, "run", side_effect=_fake_run):
        resp = await client.post(
            "/firewall/bloqueios",
            data={"ip": "203.0.113.110", "motivo": "teste htmx", "duracao_horas": "1"},
            headers={"X-Sentinela-CSRF": "1"},
        )
    assert resp.status_code == 200
    assert "203.0.113.110" in resp.text
    assert 'id="tabela-bloqueios"' in resp.text

    with patch.object(core_firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(core_firewall.subprocess, "run", side_effect=_fake_run):
        resp_remover = await client.request(
            "DELETE", "/firewall/bloqueios/203.0.113.110", headers={"X-Sentinela-CSRF": "1"}
        )
    assert resp_remover.status_code == 200
    assert "203.0.113.110" not in resp_remover.text


@pytest.mark.asyncio
async def test_analista_nao_pode_bloquear_via_post_direto(client, analista_de_teste):
    await client.post("/login", data={"email": analista_de_teste["email"], "senha": analista_de_teste["senha"]})
    resp = await client.post(
        "/firewall/bloqueios", data={"ip": "203.0.113.111", "motivo": "x"}, headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 403
