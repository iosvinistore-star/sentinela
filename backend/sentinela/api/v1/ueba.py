# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""UEBA heurística por entidade (ver siem/ueba.py)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from sentinela.auth.dependencies import conexao_tenant, exigir_csrf_header, exigir_papel
from sentinela.siem.ueba import avaliar_lote

router = APIRouter(prefix="/ueba", tags=["ueba"])


@router.get("/anomalias")
async def anomalias(limite: int = Query(100, ge=1, le=1000), usuario=Depends(exigir_papel("admin", "analista")),
                    conn=Depends(conexao_tenant)):
    rows = await conn.fetch(
        """SELECT id, evento_id, chave, tipo, score, motivo, evidencias, janela_hora, criado_em
             FROM ueba_anomalias WHERE empresa_id=$1 ORDER BY criado_em DESC LIMIT $2""",
        usuario["empresa_id"], limite,
    )
    return [dict(r) for r in rows]


@router.post("/reavaliar", dependencies=[Depends(exigir_csrf_header)])
async def reavaliar(limite: int = Query(500, ge=1, le=5000), usuario=Depends(exigir_papel("admin", "analista")),
                    conn=Depends(conexao_tenant)):
    rows = await conn.fetch(
        """SELECT id, source_type, hostname, host(source_ip) AS source_ip, username, event_type, severity
             FROM eventos_siem WHERE empresa_id=$1 AND timestamp >= now() - interval '1 hour'
             ORDER BY id DESC LIMIT $2""",
        usuario["empresa_id"], limite,
    )
    resultado = await avaliar_lote(conn, str(usuario["empresa_id"]), [(r["id"], dict(r)) for r in rows])
    return {"avaliados": len(rows), "entidades_anomalas": len(resultado),
            "anomalias_criadas": sum(1 for a in resultado.values() if a["nova"])}
