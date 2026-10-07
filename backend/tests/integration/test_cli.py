# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Smoke test da CLI (sentinela.cli) contra Postgres real."""
import argparse
from unittest.mock import patch

import pytest

from sentinela.cli import _executar
from sentinela.core import firewall as core_firewall
from sentinela.core import reputacao as core_reputacao
from tests.sql_cru import buscar

pytestmark = pytest.mark.integration


def _args(**overrides):
    base = dict(
        arquivo="servidor.log", empresa_id=None, limite=5, verificar_reputacao=False,
        bloquear=False, dry_run=False, whitelist="", duracao_bloqueio=24,
        limpar_expirados=False, saida_json=None,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


@pytest.mark.asyncio
async def test_cli_cria_incidente_via_empresa_id(tmp_path, monkeypatch, empresa_factory, db):
    from tests.integration.conftest_db import TEST_DATABASE_URL

    monkeypatch.setenv("DATABASE_URL", TEST_DATABASE_URL)
    monkeypatch.setenv("JWT_SECRET", "x")
    monkeypatch.setenv("SENTINELA_MFA_ENCRYPTION_KEY", "FubcIZSMWTNTDq6fxHGe66Wooatc2PzAdSjz14ZmcQM=")
    monkeypatch.setenv("ENV", "test")
    monkeypatch.chdir(tmp_path)

    # Precisa cruzar o limiar HIGH (score >= 60) em risk_engine.calcular_risco:
    # várias linhas + dois tipos de ataque de peso alto (SQLi=25, Command
    # Injection=30) somados à reputação "ALTO RISCO" mockada abaixo dão
    # score bem acima de 60 -- ao contrário de só XSS (peso 15), que fica em
    # MEDIUM mesmo com a reputação mockada, e não cria incidente (ver
    # services/resposta_incidentes.py: só HIGH/CRITICAL viram incidente).
    log = tmp_path / "servidor.log"
    log.write_text(
        "203.0.113.50 - - [01/Sep/2026:10:00:00] "
        "\"GET /vulneravel.php?id=1' UNION SELECT null,username,password FROM users HTTP/1.1\" 200 100\n"
        "203.0.113.50 - - [01/Sep/2026:10:00:01] "
        "\"GET /vulneravel.php?id=2' UNION SELECT null,username,password FROM users HTTP/1.1\" 200 100\n"
        '203.0.113.50 - - [01/Sep/2026:10:00:02] "GET /exec?cmd=;cat /etc/passwd HTTP/1.1" 200 100\n'
        '203.0.113.50 - - [01/Sep/2026:10:00:03] "GET /exec?cmd=;whoami HTTP/1.1" 200 100\n'
        '203.0.113.50 - - [01/Sep/2026:10:00:04] "GET /exec?cmd=;id HTTP/1.1" 200 100\n',
        encoding="utf-8",
    )

    empresa_id = await empresa_factory("Empresa CLI")

    with patch.object(core_reputacao, "consultar_abuseipdb", return_value={"score_abuso": 90}), \
         patch.object(core_reputacao, "consultar_virustotal", return_value={"maliciosos": 8}):
        await _executar(_args(
            arquivo=str(log), empresa_id=str(empresa_id), limite=1, verificar_reputacao=True,
        ))

    async with db.tenant_session(empresa_id) as conn:
        linhas = await buscar(conn, "SELECT ip FROM incidentes WHERE empresa_id = $1", empresa_id)
    assert len(linhas) == 1
    assert str(linhas[0]["ip"]) == "203.0.113.50"


@pytest.mark.asyncio
async def test_cli_sem_empresa_id_da_erro(tmp_path, monkeypatch):
    from tests.integration.conftest_db import TEST_DATABASE_URL

    monkeypatch.setenv("DATABASE_URL", TEST_DATABASE_URL)
    monkeypatch.setenv("JWT_SECRET", "x")
    monkeypatch.setenv("SENTINELA_MFA_ENCRYPTION_KEY", "FubcIZSMWTNTDq6fxHGe66Wooatc2PzAdSjz14ZmcQM=")
    monkeypatch.setenv("ENV", "test")

    with pytest.raises(SystemExit):
        await _executar(_args(empresa_id=None))


@pytest.mark.asyncio
async def test_cli_limpar_expirados_nao_exige_empresa_id(monkeypatch, capsys):
    from tests.integration.conftest_db import TEST_DATABASE_URL

    monkeypatch.setenv("DATABASE_URL", TEST_DATABASE_URL)
    monkeypatch.setenv("JWT_SECRET", "x")
    monkeypatch.setenv("SENTINELA_MFA_ENCRYPTION_KEY", "FubcIZSMWTNTDq6fxHGe66Wooatc2PzAdSjz14ZmcQM=")
    monkeypatch.setenv("ENV", "test")

    with patch.object(core_firewall.subprocess, "run") as run_mock:
        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = "Members:\n"
        await _executar(_args(limpar_expirados=True))

    saida = capsys.readouterr().out
    assert "metadados_kernel_removidos" in saida
