# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Query

from sentinela.auth.dependencies import conexao_tenant, exigir_papel

router = APIRouter(prefix="/siem/dashboard", tags=["siem-dashboard"])


@router.get("/resumo")
async def resumo_siem(
    horas: int = Query(24, ge=1, le=168),
    usuario: dict = Depends(exigir_papel("admin", "analista")),
    conn=Depends(conexao_tenant),
):
    empresa = usuario["empresa_id"]
    params = (empresa, horas)
    total = await conn.fetchval(
        "SELECT count(*) FROM eventos_siem WHERE empresa_id=$1 AND timestamp >= now() - ($2::int * interval '1 hour')",
        *params,
    )
    criticos = await conn.fetchval(
        "SELECT count(*) FROM eventos_siem WHERE empresa_id=$1 AND timestamp >= now() - ($2::int * interval '1 hour') AND severity IN ('CRITICAL','EMERGENCY','ALERT')",
        *params,
    )
    fontes = await conn.fetch(
        """
        SELECT source_type, count(*)::bigint AS eventos,
               count(DISTINCT source)::bigint AS fontes
        FROM eventos_siem
        WHERE empresa_id=$1 AND timestamp >= now() - ($2::int * interval '1 hour')
        GROUP BY source_type ORDER BY eventos DESC
        """,
        *params,
    )
    severidades = await conn.fetch(
        """
        SELECT severity, count(*)::bigint AS eventos
        FROM eventos_siem
        WHERE empresa_id=$1 AND timestamp >= now() - ($2::int * interval '1 hour')
        GROUP BY severity ORDER BY eventos DESC
        """,
        *params,
    )
    por_minuto = await conn.fetch(
        """
        SELECT date_trunc('minute', timestamp) AS minuto, count(*)::bigint AS eventos
        FROM eventos_siem
        WHERE empresa_id=$1 AND timestamp >= now() - ($2::int * interval '1 hour')
        GROUP BY 1 ORDER BY 1 DESC LIMIT 120
        """,
        *params,
    )
    return {
        "janela_horas": horas,
        "total_eventos": int(total or 0),
        "criticos": int(criticos or 0),
        "eps_medio": round((float(total or 0) / (horas * 3600)), 3),
        "fontes": [dict(r) for r in fontes],
        "severidades": [dict(r) for r in severidades],
        "por_minuto": [dict(r) for r in por_minuto],
    }


@router.get("/fontes")
async def fontes_siem(
    usuario: dict = Depends(exigir_papel("admin", "analista")),
    conn=Depends(conexao_tenant),
):
    rows = await conn.fetch(
        """
        SELECT source, source_type, max(timestamp) AS ultimo_evento,
               count(*) FILTER (WHERE timestamp >= now() - interval '15 minutes')::bigint AS eventos_15m
        FROM eventos_siem WHERE empresa_id=$1 AND timestamp >= now() - interval '24 hours'
        GROUP BY source, source_type ORDER BY ultimo_evento DESC NULLS LAST
        LIMIT 500
        """,
        usuario["empresa_id"],
    )
    return [dict(r) for r in rows]

@router.get('/soc-executivo')
async def soc_executivo(usuario=Depends(exigir_papel('admin','analista')), conn=Depends(conexao_tenant)):
    e=usuario['empresa_id']
    total=await conn.fetchval("SELECT count(*) FROM eventos_siem WHERE empresa_id=$1 AND timestamp>=now()-interval '24 hours'",e)
    high=await conn.fetchval("SELECT count(*) FROM eventos_siem WHERE empresa_id=$1 AND timestamp>=now()-interval '24 hours' AND severity IN ('HIGH','CRITICAL','EMERGENCY','ALERT')",e)
    corr=await conn.fetchval("SELECT count(*) FROM siem_correlacoes WHERE empresa_id=$1 AND criado_em>=now()-interval '24 hours'",e)
    ueba=await conn.fetchval("SELECT count(*) FROM ueba_anomalias WHERE empresa_id=$1 AND criado_em>=now()-interval '24 hours'",e)
    sigma=await conn.fetchval("SELECT count(*) FROM sigma_alertas WHERE empresa_id=$1 AND criado_em>=now()-interval '24 hours'",e)
    edr=await conn.fetchval("SELECT count(*) FROM edr_telemetria WHERE empresa_id=$1 AND criado_em>=now()-interval '24 hours'",e)
    return {'janela':'24h','eventos':int(total or 0),'alto_risco':int(high or 0),'correlacoes':int(corr or 0),'ueba_anomalias':int(ueba or 0),'sigma_alertas':int(sigma or 0),'edr_telemetria':int(edr or 0)}


@router.get("/correlacoes")
async def correlacoes_recentes(
    limite: int = Query(50, ge=1, le=500),
    usuario: dict = Depends(exigir_papel("admin", "analista")),
    conn=Depends(conexao_tenant),
):
    """Correlações mais recentes com o resumo do evento de origem (V8.2).

    Até a V8.2 as correlações eram gravadas mas não havia rota de leitura --
    nenhuma tela conseguia mostrá-las ao analista.
    """
    rows = await conn.fetch(
        """
        SELECT c.id, c.regra, c.severidade, c.score, c.cti_match, c.playbook_id, c.criado_em,
               c.detalhes->'regras' AS regras, c.detalhes->'sigma' AS sigma,
               e.source_type, e.hostname, e.username, host(e.source_ip) AS source_ip,
               host(e.destination_ip) AS destination_ip, e.event_type, left(e.message, 240) AS message
          FROM siem_correlacoes c
          LEFT JOIN eventos_siem e ON e.id = c.evento_ids[1] AND e.empresa_id = c.empresa_id
         WHERE c.empresa_id = $1
         ORDER BY c.criado_em DESC, c.id DESC
         LIMIT $2
        """,
        usuario["empresa_id"], limite,
    )
    saida = []
    for r in rows:
        d = dict(r)
        for campo in ("regras", "sigma"):
            if isinstance(d.get(campo), str):
                d[campo] = json.loads(d[campo])
        saida.append(d)
    return saida
