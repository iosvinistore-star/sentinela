# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from sentinela.auth.dependencies import conexao_tenant, exigir_csrf_header, exigir_papel
from sentinela.siem.correlacao_siem import correlacionar_lote
from sentinela.siem.modelos import EventoSIEMEntrada
from sentinela.siem.servico import persistir_eventos_com_ids

router = APIRouter(prefix="/siem", tags=["siem"])


@router.post("/eventos", dependencies=[Depends(exigir_csrf_header)])
async def ingerir_evento(
    evento: EventoSIEMEntrada,
    usuario: dict = Depends(exigir_papel("admin", "analista")),
    conn=Depends(conexao_tenant),
):
    normalizado = evento.normalizado(str(usuario["empresa_id"]))
    ids = await persistir_eventos_com_ids(conn, usuario["empresa_id"], [normalizado])
    resultado = await correlacionar_lote(conn, str(usuario["empresa_id"]), [(ids[0], normalizado)])
    return {"recebidos": len(ids), "evento_id": ids[0], "correlacoes": resultado["correlacoes"]}


@router.post("/eventos/lote", dependencies=[Depends(exigir_csrf_header)])
async def ingerir_lote(
    eventos: list[EventoSIEMEntrada],
    usuario: dict = Depends(exigir_papel("admin", "analista")),
    conn=Depends(conexao_tenant),
):
    if not eventos:
        raise HTTPException(status_code=422, detail="lote vazio")
    if len(eventos) > 5000:
        raise HTTPException(status_code=413, detail="lote máximo de 5000 eventos")
    normalizados = [e.normalizado(str(usuario["empresa_id"])) for e in eventos]
    ids = await persistir_eventos_com_ids(conn, usuario["empresa_id"], normalizados)
    resultado = await correlacionar_lote(conn, str(usuario["empresa_id"]), list(zip(ids, normalizados)))
    return {"recebidos": len(ids), "correlacoes": resultado["correlacoes"],
            "playbooks": resultado["playbooks"], "evento_ids": ids}


@router.get("/eventos")
async def consultar_eventos(
    limite: int = Query(100, ge=1, le=1000),
    severidade: str | None = Query(None),
    source_type: str | None = Query(None),
    usuario: dict = Depends(exigir_papel("admin", "analista")),
    conn=Depends(conexao_tenant),
):
    filtros = ["empresa_id = $1"]
    args = [usuario["empresa_id"]]
    n = 2
    if severidade:
        filtros.append(f"severity = ${n}")
        args.append(severidade.upper())
        n += 1
    if source_type:
        filtros.append(f"source_type = ${n}")
        args.append(source_type)
        n += 1
    args.append(limite)
    # Só placeholders ($n) e fragmentos fixos entram na string; valores vão em *args.
    sql = (
        "SELECT id, timestamp, source, source_type, hostname, host(source_ip) AS source_ip, "
        "event_type, action, severity, message, tags, mitre_techniques, iocs "
        f"FROM eventos_siem WHERE {' AND '.join(filtros)} ORDER BY timestamp DESC LIMIT ${n}"  # nosec B608
    )
    rows = await conn.fetch(sql, *args)
    return [dict(r) for r in rows]
