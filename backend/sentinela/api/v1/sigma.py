# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Regras Sigma por tenant (ver siem/sigma.py para o subconjunto suportado)."""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from sentinela.auth.dependencies import conexao_tenant, exigir_csrf_header, exigir_papel
from sentinela.siem.sigma import SigmaErro, compilar_regra

router = APIRouter(prefix="/sigma", tags=["sigma"])

NIVEIS = {"informational", "low", "medium", "high", "critical"}


class SigmaIn(BaseModel):
    nome: str = Field(min_length=2, max_length=180, pattern=r"^[A-Za-z0-9_.:\-]+$")
    titulo: str = Field(min_length=2, max_length=255)
    nivel: str = "medium"
    logsource: dict[str, Any] = Field(default_factory=dict)
    detection: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list, max_length=50)
    ativo: bool = True

    @field_validator("nivel")
    @classmethod
    def _nivel(cls, v: str) -> str:
        v = v.lower()
        if v not in NIVEIS:
            raise ValueError(f"nivel deve ser um de {sorted(NIVEIS)}")
        return v


def _serializar(row) -> dict[str, Any]:
    d = dict(row)
    for campo in ("logsource", "detection", "tags"):
        if isinstance(d.get(campo), str):
            d[campo] = json.loads(d[campo])
    return d


@router.post("/regras", dependencies=[Depends(exigir_csrf_header)])
async def criar(data: SigmaIn, usuario=Depends(exigir_papel("admin")), conn=Depends(conexao_tenant)):
    if len(json.dumps(data.detection)) > 64_000:
        raise HTTPException(status_code=413, detail="detection excede 64 KB")
    try:
        compilar_regra({"logsource": data.logsource, "detection": data.detection})
    except SigmaErro as exc:
        # V8.2: regra inválida/não suportada é recusada explicitamente em vez
        # de gravada e depois avaliada de forma errada em silêncio.
        raise HTTPException(status_code=422, detail=f"regra Sigma inválida ou não suportada: {exc}") from exc
    row = await conn.fetchrow(
        """INSERT INTO sigma_regras (empresa_id, nome, titulo, nivel, logsource, detection, tags, ativo)
           VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7::jsonb,$8)
           ON CONFLICT (empresa_id, nome) DO UPDATE SET titulo=EXCLUDED.titulo, nivel=EXCLUDED.nivel,
               logsource=EXCLUDED.logsource, detection=EXCLUDED.detection, tags=EXCLUDED.tags,
               ativo=EXCLUDED.ativo, atualizado_em=now()
           RETURNING *""",
        usuario["empresa_id"], data.nome, data.titulo, data.nivel, json.dumps(data.logsource),
        json.dumps(data.detection), json.dumps(data.tags), data.ativo,
    )
    return _serializar(row)


@router.get("/regras")
async def listar(usuario=Depends(exigir_papel("admin", "analista")), conn=Depends(conexao_tenant)):
    rows = await conn.fetch("SELECT * FROM sigma_regras WHERE empresa_id=$1 ORDER BY id DESC", usuario["empresa_id"])
    return [_serializar(r) for r in rows]


@router.get("/alertas")
async def alertas(limite: int = Query(100, ge=1, le=1000), usuario=Depends(exigir_papel("admin", "analista")),
                  conn=Depends(conexao_tenant)):
    rows = await conn.fetch(
        """SELECT a.id, a.regra_id, r.nome AS regra, a.evento_id, a.severidade, a.evidencias, a.criado_em
             FROM sigma_alertas a JOIN sigma_regras r ON r.id = a.regra_id
            WHERE a.empresa_id=$1 ORDER BY a.criado_em DESC LIMIT $2""",
        usuario["empresa_id"], limite,
    )
    return [dict(r) for r in rows]


@router.post("/avaliar-evento/{evento_id}", dependencies=[Depends(exigir_csrf_header)])
async def avaliar(evento_id: int, usuario=Depends(exigir_papel("admin", "analista")), conn=Depends(conexao_tenant)):
    ev = await conn.fetchrow(
        """SELECT id, timestamp, source, source_type, hostname, host(source_ip) AS source_ip,
                  host(destination_ip) AS destination_ip, source_port, destination_port, protocol, username,
                  event_type, action, severity, message, raw_event
             FROM eventos_siem WHERE id=$1 AND empresa_id=$2""",
        evento_id, usuario["empresa_id"],
    )
    if not ev:
        raise HTTPException(404, "evento não encontrado")
    evento = dict(ev)
    hits = []
    for regra in await conn.fetch("SELECT * FROM sigma_regras WHERE empresa_id=$1 AND ativo=true", usuario["empresa_id"]):
        r = _serializar(regra)
        try:
            casa = compilar_regra(r).casa(evento)
        except SigmaErro:
            continue
        if casa:
            row = await conn.fetchrow(
                """INSERT INTO sigma_alertas (empresa_id, regra_id, evento_id, severidade, evidencias)
                   VALUES ($1,$2,$3,$4,$5::jsonb)
                   ON CONFLICT (regra_id, evento_id) DO UPDATE SET severidade = EXCLUDED.severidade
                   RETURNING id""",
                usuario["empresa_id"], r["id"], evento_id, str(r["nivel"]).upper(),
                json.dumps({"regra": r["nome"], "automatico": False}),
            )
            hits.append({"alerta_id": row["id"], "regra": r["nome"]})
    return {"matches": hits}
