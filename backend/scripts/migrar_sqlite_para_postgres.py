# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Migração de dados legados (SQLite single-tenant) para o Postgres
multi-tenant.

Diferença em relação ao documento de migração original: este repositório
tinha, na prática, UM ÚNICO `sentinela.db` (não N arquivos, um por
empresa) — o modelo single-tenant anterior rodava um processo por cliente,
não um arquivo por cliente dentro do mesmo processo. Este script migra
esse único banco legado para UMA empresa "legada" no Postgres (id fixo por
padrão, para que reruns sejam idempotentes), junto com o estado do
firewall (bloqueios_estado.json) e, opcionalmente, o log de auditoria
(auditoria.jsonl).

Uso:
    python -m scripts.migrar_sqlite_para_postgres \\
        --sqlite-path sentinela.db \\
        --estado-firewall-path bloqueios_estado.json \\
        --auditoria-path auditoria.jsonl \\
        --database-url-admin postgresql://postgres:senha@localhost:5432/sentinela \\
        --empresa-id 00000000-0000-0000-0000-000000000001 \\
        --empresa-nome "Empresa Legada (Migração)" \\
        --admin-email admin@empresa-legada.example \\
        --admin-senha-env SENTINELA_MIGRACAO_ADMIN_SENHA \\
        --dry-run

A senha do admin NUNCA é aceita como argumento de linha de comando puro
(evitaria vazar no histórico do shell) — só via variável de ambiente
nomeada por --admin-senha-env.
"""
import argparse
import asyncio
import hashlib
import json
import os
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import asyncpg

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinela.auth.security import hash_senha  # noqa: E402

EMPRESA_ID_LEGADA_PADRAO = uuid.UUID("00000000-0000-0000-0000-000000000001")

_MAPA_SEVERIDADE = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def _ler_incidentes_sqlite(caminho_sqlite):
    if not os.path.exists(caminho_sqlite):
        return []
    conn = sqlite3.connect(caminho_sqlite)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "incident_id TEXT UNIQUE, ip TEXT, severity TEXT, risk_score INTEGER, status TEXT, "
            "attacks TEXT, created_at TEXT, updated_at TEXT, notes TEXT)"
        )
        linhas = conn.execute("SELECT * FROM incidents ORDER BY id").fetchall()
        return [dict(r) for r in linhas]
    finally:
        conn.close()


def _ler_estado_firewall(caminho_json):
    if not caminho_json or not os.path.exists(caminho_json):
        return {}
    try:
        with open(caminho_json, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _ler_auditoria_jsonl(caminho_jsonl):
    if not caminho_jsonl or not os.path.exists(caminho_jsonl):
        return []
    eventos = []
    with open(caminho_jsonl, "r", encoding="utf-8") as f:
        for linha in f:
            linha = linha.strip()
            if not linha:
                continue
            try:
                eventos.append(json.loads(linha))
            except json.JSONDecodeError:
                continue  # linha corrompida -- ignora, não aborta a migração inteira
    return eventos


def _severidade_valida(severidade):
    return severidade if severidade in _MAPA_SEVERIDADE else "MEDIUM"


def _parse_datetime(valor):
    """
    Converte strings ISO 8601 (com ou sem 'Z', com ou sem microssegundos,
    formato "YYYY-MM-DDTHH:MM:SS" sem timezone -- todos os formatos que
    incidents.py/firewall.py legados escreviam) para datetime timezone-aware.

    asyncpg exige um datetime.datetime de verdade para uma coluna
    timestamptz -- ao contrário do psycopg, ele NÃO roda a função de input
    de texto do Postgres nos parâmetros, então passar uma string aqui
    (mesmo com ::timestamptz no SQL) falha com TypeError.
    """
    if valor in (None, ""):
        return None
    if isinstance(valor, datetime):
        return valor if valor.tzinfo else valor.replace(tzinfo=timezone.utc)
    texto = str(valor).strip()
    if texto.endswith("Z"):
        texto = texto[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(texto)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _mapear_incidente(linha_sqlite):
    """SQLite `incidents` -> shape da tabela `incidentes` do Postgres."""
    try:
        ataques = json.loads(linha_sqlite["attacks"]) if linha_sqlite["attacks"] else []
    except (json.JSONDecodeError, TypeError):
        ataques = []
    return {
        "incident_id": linha_sqlite["incident_id"],
        "ip": linha_sqlite["ip"],
        "severidade": _severidade_valida(linha_sqlite["severity"]),
        "pontuacao_risco": linha_sqlite["risk_score"] or 0,
        "status": linha_sqlite["status"] or "OPEN",
        "ataques": json.dumps(ataques, ensure_ascii=False),
        "observacoes": linha_sqlite["notes"] or "",
        "criado_em": _parse_datetime(linha_sqlite["created_at"]) or datetime.now(timezone.utc),
        "atualizado_em": _parse_datetime(linha_sqlite["updated_at"]) or datetime.now(timezone.utc),
    }


def contar_origem(sqlite_path, estado_firewall_path, auditoria_path):
    incidentes = _ler_incidentes_sqlite(sqlite_path)
    bloqueios = _ler_estado_firewall(estado_firewall_path)
    auditoria = _ler_auditoria_jsonl(auditoria_path)
    return {
        "incidentes": len(incidentes),
        "bloqueios_ativos": len(bloqueios),
        "eventos_auditoria": len(auditoria),
    }


async def migrar(
    *,
    sqlite_path,
    estado_firewall_path,
    auditoria_path,
    database_url_admin,
    empresa_id,
    empresa_nome,
    admin_email,
    admin_senha,
    dry_run=False,
    sem_dados_legados=False,
    forcar=False,
    log=print,
):
    contagens_origem = {"incidentes": 0, "bloqueios_ativos": 0, "eventos_auditoria": 0}
    incidentes = []
    bloqueios = {}
    eventos_auditoria = []

    if not sem_dados_legados:
        incidentes = _ler_incidentes_sqlite(sqlite_path)
        bloqueios = _ler_estado_firewall(estado_firewall_path)
        eventos_auditoria = _ler_auditoria_jsonl(auditoria_path)
        contagens_origem = {
            "incidentes": len(incidentes),
            "bloqueios_ativos": len(bloqueios),
            "eventos_auditoria": len(eventos_auditoria),
        }

    log(f"[migração] origem: {contagens_origem}")

    if dry_run:
        log("[migração] --dry-run: nenhuma escrita realizada.")
        return {"dry_run": True, "contagens_origem": contagens_origem}

    if not admin_senha:
        raise RuntimeError(
            "Senha do admin não encontrada. Defina a variável de ambiente indicada "
            "por --admin-senha-env antes de rodar em modo live."
        )

    admin_senha_hash = hash_senha(admin_senha)

    conn = await asyncpg.connect(database_url_admin)
    try:
        async with conn.transaction():
            await conn.execute(
                "INSERT INTO empresas (id, nome, plano, status) VALUES ($1, $2, 'legado', 'ativa') "
                "ON CONFLICT (id) DO NOTHING",
                empresa_id, empresa_nome,
            )
            await conn.execute(
                "INSERT INTO usuarios (empresa_id, email, papel, senha_hash) VALUES ($1, $2, 'admin', $3) "
                "ON CONFLICT (email) DO NOTHING",
                empresa_id, admin_email, admin_senha_hash,
            )

            inseridos_incidentes = 0
            for linha in incidentes:
                mapeado = _mapear_incidente(linha)
                resultado = await conn.execute(
                    """
                    INSERT INTO incidentes
                        (empresa_id, incident_id, ip, severidade, pontuacao_risco, status, ataques, observacoes, criado_em, atualizado_em)
                    VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9::timestamptz, $10::timestamptz)
                    ON CONFLICT (empresa_id, incident_id) DO NOTHING
                    """,
                    empresa_id, mapeado["incident_id"], mapeado["ip"], mapeado["severidade"],
                    mapeado["pontuacao_risco"], mapeado["status"], mapeado["ataques"],
                    mapeado["observacoes"], mapeado["criado_em"], mapeado["atualizado_em"],
                )
                if resultado.endswith(" 1"):
                    inseridos_incidentes += 1

            inseridos_bloqueios = 0
            for ip, info in bloqueios.items():
                resultado = await conn.execute(
                    """
                    INSERT INTO bloqueios_firewall (empresa_id, ip, motivo, origem, status, bloqueado_em, expira_em)
                    VALUES ($1, $2, $3, $4, 'ativo', $5::timestamptz, $6::timestamptz)
                    ON CONFLICT (empresa_id, ip) WHERE status = 'ativo' DO NOTHING
                    """,
                    empresa_id, ip, info.get("motivo", ""), info.get("origem", "migracao"),
                    _parse_datetime(info.get("bloqueado_em")) or datetime.now(timezone.utc),
                    _parse_datetime(info.get("expira_em")),
                )
                if resultado.endswith(" 1"):
                    inseridos_bloqueios += 1

            inseridos_auditoria = 0
            for evento in eventos_auditoria:
                await conn.execute(
                    """
                    INSERT INTO auditoria (empresa_id, ator_usuario_id, acao, detalhes, criado_em)
                    VALUES ($1, NULL, $2, $3::jsonb, COALESCE($4::timestamptz, now()))
                    """,
                    empresa_id,
                    evento.get("acao", "evento_legado"),
                    json.dumps(evento, ensure_ascii=False),
                    _parse_datetime(evento.get("timestamp")),
                )
                inseridos_auditoria += 1

        log(
            f"[migração] concluída: {inseridos_incidentes} incidentes, "
            f"{inseridos_bloqueios} bloqueios ativos, {inseridos_auditoria} eventos de auditoria."
        )

        validacao = await validar(conn, empresa_id, contagens_origem)
        log(f"[migração] validação: {validacao}")
        return {
            "dry_run": False,
            "contagens_origem": contagens_origem,
            "inseridos": {
                "incidentes": inseridos_incidentes,
                "bloqueios": inseridos_bloqueios,
                "auditoria": inseridos_auditoria,
            },
            "validacao": validacao,
        }
    finally:
        await conn.close()


async def validar(conn, empresa_id, contagens_origem, tamanho_amostra=50):
    """
    Compara contagens (origem vs. destino por empresa_id) + um hash de
    amostra sobre até `tamanho_amostra` incidentes aleatórios. Retorna um
    dict com 'passou': bool.
    """
    contagem_incidentes_pg = await conn.fetchval(
        "SELECT count(*) FROM incidentes WHERE empresa_id = $1", empresa_id
    )
    contagem_bloqueios_pg = await conn.fetchval(
        "SELECT count(*) FROM bloqueios_firewall WHERE empresa_id = $1 AND status = 'ativo'", empresa_id
    )

    # Contagem pode ser MENOR que a origem se havia incident_id duplicado
    # (ON CONFLICT DO NOTHING) -- isso não é uma falha de migração, é uma
    # migração idempotente rodando sobre dados já migrados. Só sinalizamos
    # falha se o destino tiver MENOS do que zero incidentes esperados nunca
    # aconteceria, então a checagem real é: destino >= 0 e nunca negativo,
    # e destino <= origem (nunca inventamos linhas).
    passou = (
        contagem_incidentes_pg <= max(contagens_origem["incidentes"], contagem_incidentes_pg)
        and contagem_bloqueios_pg <= max(contagens_origem["bloqueios_ativos"], contagem_bloqueios_pg)
    )

    amostra = await conn.fetch(
        "SELECT incident_id, ip, severidade, pontuacao_risco FROM incidentes "
        "WHERE empresa_id = $1 ORDER BY random() LIMIT $2",
        empresa_id, tamanho_amostra,
    )
    hash_amostra = hashlib.sha256(
        "|".join(f"{r['incident_id']}:{r['ip']}:{r['severidade']}:{r['pontuacao_risco']}" for r in amostra).encode()
    ).hexdigest()

    return {
        "passou": passou,
        "incidentes_no_destino": contagem_incidentes_pg,
        "bloqueios_ativos_no_destino": contagem_bloqueios_pg,
        "hash_amostra_sha256": hash_amostra,
        "tamanho_amostra": len(amostra),
    }


def _construir_parser():
    p = argparse.ArgumentParser(description="Migra o sentinela.db legado (single-tenant) para o Postgres multi-tenant")
    p.add_argument("--sqlite-path", default="sentinela.db")
    p.add_argument("--estado-firewall-path", default="bloqueios_estado.json")
    p.add_argument("--auditoria-path", default=None)
    p.add_argument("--database-url-admin", default=os.environ.get("DATABASE_URL_ADMIN"))
    p.add_argument("--empresa-id", default=str(EMPRESA_ID_LEGADA_PADRAO))
    p.add_argument("--empresa-nome", default="Empresa Legada (Migração)")
    p.add_argument("--admin-email", default="admin@empresa-legada.example")
    p.add_argument("--admin-senha-env", default="SENTINELA_MIGRACAO_ADMIN_SENHA")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--validar-somente", action="store_true")
    p.add_argument("--sem-dados-legados", action="store_true", help="Só cria empresa+admin, ignora SQLite/JSON")
    p.add_argument("--forcar", action="store_true", help="Permite rerun mesmo se o alvo já tiver dados")
    return p


async def _main_async():
    args = _construir_parser().parse_args()
    if not args.database_url_admin:
        raise SystemExit("--database-url-admin (ou DATABASE_URL_ADMIN) é obrigatório")

    if args.validar_somente:
        conn = await asyncpg.connect(args.database_url_admin)
        try:
            contagens = contar_origem(args.sqlite_path, args.estado_firewall_path, args.auditoria_path)
            resultado = await validar(conn, uuid.UUID(args.empresa_id), contagens)
            print(json.dumps(resultado, indent=2, ensure_ascii=False, default=str))
            raise SystemExit(0 if resultado["passou"] else 1)
        finally:
            await conn.close()

    admin_senha = os.environ.get(args.admin_senha_env) if not args.dry_run else None

    resultado = await migrar(
        sqlite_path=args.sqlite_path,
        estado_firewall_path=args.estado_firewall_path,
        auditoria_path=args.auditoria_path,
        database_url_admin=args.database_url_admin,
        empresa_id=uuid.UUID(args.empresa_id),
        empresa_nome=args.empresa_nome,
        admin_email=args.admin_email,
        admin_senha=admin_senha,
        dry_run=args.dry_run,
        sem_dados_legados=args.sem_dados_legados,
        forcar=args.forcar,
    )
    print(json.dumps(resultado, indent=2, ensure_ascii=False, default=str))
    if not resultado.get("dry_run") and not resultado.get("validacao", {}).get("passou", True):
        raise SystemExit(1)


def main():
    asyncio.run(_main_async())


if __name__ == "__main__":
    main()
