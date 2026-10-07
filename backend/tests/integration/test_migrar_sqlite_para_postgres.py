# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testa scripts/migrar_sqlite_para_postgres.py contra fixtures no formato
REAL do sentinela.db (schema criado por incidents.py) e do
bloqueios_estado.json (escrito por firewall.py) do sistema single-tenant
anterior.
"""
import json
import sqlite3
import uuid

import pytest

from scripts.migrar_sqlite_para_postgres import contar_origem, migrar
from tests.sql_cru import buscar, executar, valor

pytestmark = pytest.mark.integration


def _criar_sqlite_legado(caminho):
    conn = sqlite3.connect(str(caminho))
    conn.execute(
        "CREATE TABLE incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT UNIQUE, "
        "ip TEXT, severity TEXT, risk_score INTEGER, status TEXT, attacks TEXT, created_at TEXT, "
        "updated_at TEXT, notes TEXT)"
    )
    linhas = [
        ("INC-20260901-1130095-100000", "203.0.113.5", "HIGH", 85, "OPEN",
         json.dumps(["SQL Injection (SQLi)"]), "2026-09-01T10:00:00Z", "2026-09-01T10:00:00Z", ""),
        ("INC-20260901-1130095-100500", "203.0.113.6", "CRITICAL", 95, "RESOLVIDO",
         json.dumps(["Command Injection", "Path Traversal"]), "2026-09-01T10:05:00Z", "2026-09-01T11:00:00Z", "revisado"),
    ]
    conn.executemany(
        "INSERT INTO incidents (incident_id, ip, severity, risk_score, status, attacks, created_at, updated_at, notes) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        linhas,
    )
    conn.commit()
    conn.close()


def _criar_estado_firewall(caminho):
    estado = {
        "203.0.113.6": {
            "bloqueado_em": "2026-09-01T10:05:30",
            "expira_em": "2026-09-02T10:05:30",
            "motivo": "2 ataques detectados",
            "origem": "cli",
            "conjunto": "analisador_bloqueios_v4",
        }
    }
    caminho.write_text(json.dumps(estado), encoding="utf-8")


def _criar_auditoria(caminho):
    eventos = [
        {"timestamp": "2026-09-01T10:05:30", "acao": "bloqueio", "ip": "203.0.113.6", "origem": "cli", "motivo": "x"},
    ]
    caminho.write_text("\n".join(json.dumps(e) for e in eventos) + "\n", encoding="utf-8")


def test_contar_origem_le_os_tres_formatos(tmp_path):
    sqlite_path = tmp_path / "sentinela.db"
    estado_path = tmp_path / "bloqueios_estado.json"
    auditoria_path = tmp_path / "auditoria.jsonl"
    _criar_sqlite_legado(sqlite_path)
    _criar_estado_firewall(estado_path)
    _criar_auditoria(auditoria_path)

    contagens = contar_origem(str(sqlite_path), str(estado_path), str(auditoria_path))
    assert contagens == {"incidentes": 2, "bloqueios_ativos": 1, "eventos_auditoria": 1}


@pytest.mark.asyncio
async def test_dry_run_nao_escreve_nada(tmp_path):
    sqlite_path = tmp_path / "sentinela.db"
    _criar_sqlite_legado(sqlite_path)

    resultado = await migrar(
        sqlite_path=str(sqlite_path),
        estado_firewall_path=str(tmp_path / "inexistente.json"),
        auditoria_path=None,
        database_url_admin="postgresql://nao-deveria-conectar/",
        empresa_id=uuid.uuid4(),
        empresa_nome="Não Deveria Ser Criada",
        admin_email="x@example.com",
        admin_senha=None,
        dry_run=True,
    )
    assert resultado["dry_run"] is True
    assert resultado["contagens_origem"]["incidentes"] == 2


@pytest.mark.asyncio
async def test_migracao_live_cria_empresa_admin_e_dados(tmp_path, db, empresa_factory, monkeypatch):
    from tests.integration.conftest_db import TEST_DATABASE_URL_ADMIN

    sqlite_path = tmp_path / "sentinela.db"
    estado_path = tmp_path / "bloqueios_estado.json"
    auditoria_path = tmp_path / "auditoria.jsonl"
    _criar_sqlite_legado(sqlite_path)
    _criar_estado_firewall(estado_path)
    _criar_auditoria(auditoria_path)

    empresa_id = uuid.uuid4()  # não usa o ID fixo padrão para não colidir entre execuções de teste
    resultado = await migrar(
        sqlite_path=str(sqlite_path),
        estado_firewall_path=str(estado_path),
        auditoria_path=str(auditoria_path),
        database_url_admin=TEST_DATABASE_URL_ADMIN,
        empresa_id=empresa_id,
        empresa_nome="Empresa Legada Teste",
        admin_email=f"admin-legado-{empresa_id}@example.com",
        admin_senha="senha-forte-123",
    )

    assert resultado["dry_run"] is False
    assert resultado["inseridos"]["incidentes"] == 2
    assert resultado["inseridos"]["bloqueios"] == 1
    assert resultado["inseridos"]["auditoria"] == 1
    assert resultado["validacao"]["passou"] is True

    async with db.tenant_session(empresa_id) as conn:
        incidentes = await buscar(conn, "SELECT incident_id, severidade FROM incidentes ORDER BY incident_id")
        usuarios = await buscar(conn, "SELECT email, papel FROM usuarios")

    assert len(incidentes) == 2
    assert usuarios[0]["papel"] == "admin"

    # Cleanup manual (empresa_factory não sabe desta empresa, criada fora dela)
    async with db.superadmin_session() as conn:
        await executar(conn, "DELETE FROM auditoria WHERE empresa_id = $1", empresa_id)
        await executar(conn, "DELETE FROM bloqueios_firewall WHERE empresa_id = $1", empresa_id)
        await executar(conn, "DELETE FROM incidentes WHERE empresa_id = $1", empresa_id)
        await executar(conn, "DELETE FROM usuarios WHERE empresa_id = $1", empresa_id)
        await executar(conn, "DELETE FROM empresas WHERE id = $1", empresa_id)


@pytest.mark.asyncio
async def test_migracao_e_idempotente_rerun_nao_duplica(tmp_path, db):
    from tests.integration.conftest_db import TEST_DATABASE_URL_ADMIN

    sqlite_path = tmp_path / "sentinela.db"
    _criar_sqlite_legado(sqlite_path)
    empresa_id = uuid.uuid4()
    kwargs = dict(
        sqlite_path=str(sqlite_path),
        estado_firewall_path=str(tmp_path / "sem_estado.json"),
        auditoria_path=None,
        database_url_admin=TEST_DATABASE_URL_ADMIN,
        empresa_id=empresa_id,
        empresa_nome="Empresa Rerun",
        admin_email=f"admin-rerun-{empresa_id}@example.com",
        admin_senha="senha-forte-123",
    )

    primeira = await migrar(**kwargs)
    segunda = await migrar(**kwargs)

    assert primeira["inseridos"]["incidentes"] == 2
    assert segunda["inseridos"]["incidentes"] == 0  # ON CONFLICT DO NOTHING -- rerun não duplica

    async with db.superadmin_session() as conn:
        total = await valor(conn, "SELECT count(*) FROM incidentes WHERE empresa_id = $1", empresa_id)
        assert total == 2
        await executar(conn, "DELETE FROM usuarios WHERE empresa_id = $1", empresa_id)
        await executar(conn, "DELETE FROM incidentes WHERE empresa_id = $1", empresa_id)
        await executar(conn, "DELETE FROM empresas WHERE id = $1", empresa_id)
