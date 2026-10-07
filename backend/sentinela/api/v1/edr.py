# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Telemetria EDR/XDR (processos, conexões, hashes) por tenant."""
from __future__ import annotations

import ipaddress
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from sentinela.auth.dependencies import conexao_tenant, exigir_csrf_header, exigir_papel

router = APIRouter(prefix="/edr", tags=["edr-xdr"])

SEVERIDADES = {"INFO", "LOW", "MEDIUM", "WARNING", "HIGH", "CRITICAL"}


class TelemetriaIn(BaseModel):
    tipo: str = Field(min_length=1, max_length=80)
    hostname: str | None = Field(default=None, max_length=255)
    processo: str | None = Field(default=None, max_length=512)
    pid: int | None = Field(default=None, ge=0, le=2**31 - 1)
    usuario: str | None = Field(default=None, max_length=255)
    caminho: str | None = Field(default=None, max_length=2048)
    hash_sha256: str | None = Field(default=None, pattern=r"^[A-Fa-f0-9]{64}$")
    parent_pid: int | None = Field(default=None, ge=0, le=2**31 - 1)
    destino_ip: str | None = None
    destino_porta: int | None = Field(default=None, ge=0, le=65535)
    protocolo: str | None = Field(default=None, max_length=16)
    severidade: str = "INFO"
    detalhes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("destino_ip")
    @classmethod
    def _ip(cls, v: str | None) -> str | None:
        if v in (None, ""):
            return None
        try:
            return str(ipaddress.ip_address(v))
        except ValueError as exc:
            raise ValueError("destino_ip inválido") from exc

    @field_validator("severidade")
    @classmethod
    def _sev(cls, v: str) -> str:
        v = v.upper()
        if v not in SEVERIDADES:
            raise ValueError(f"severidade deve ser uma de {sorted(SEVERIDADES)}")
        return v

    @field_validator("hash_sha256")
    @classmethod
    def _hash(cls, v: str | None) -> str | None:
        return v.lower() if v else v


@router.post("/telemetria", dependencies=[Depends(exigir_csrf_header)])
async def ingest(data: TelemetriaIn, usuario=Depends(exigir_papel("admin", "analista")), conn=Depends(conexao_tenant)):
    detalhes = json.dumps(data.detalhes)
    if len(detalhes) > 32_000:
        raise HTTPException(status_code=413, detail="detalhes excede 32 KB")
    row = await conn.fetchrow(
        """INSERT INTO edr_telemetria (empresa_id, tipo, hostname, processo, pid, usuario, caminho, hash_sha256,
                                      parent_pid, destino_ip, destino_porta, protocolo, severidade, detalhes)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::inet,$11,$12,$13,$14::jsonb) RETURNING id, criado_em""",
        usuario["empresa_id"], data.tipo, data.hostname, data.processo, data.pid, data.usuario, data.caminho,
        data.hash_sha256, data.parent_pid, data.destino_ip, data.destino_porta, data.protocolo, data.severidade, detalhes,
    )
    return dict(row)


@router.get("/telemetria")
async def listar(limite: int = Query(100, ge=1, le=1000), usuario=Depends(exigir_papel("admin", "analista")),
                 conn=Depends(conexao_tenant)):
    rows = await conn.fetch(
        """SELECT id, agente_id, tipo, hostname, processo, pid, usuario, caminho, hash_sha256, parent_pid,
                  host(destino_ip) AS destino_ip, destino_porta, protocolo, severidade, detalhes, criado_em
             FROM edr_telemetria WHERE empresa_id=$1 ORDER BY criado_em DESC LIMIT $2""",
        usuario["empresa_id"], limite,
    )
    return [dict(r) for r in rows]


@router.get("/resumo")
async def resumo(usuario=Depends(exigir_papel("admin", "analista")), conn=Depends(conexao_tenant)):
    rows = await conn.fetch(
        """SELECT tipo, count(*)::bigint AS total FROM edr_telemetria
            WHERE empresa_id=$1 AND criado_em >= now() - interval '24 hours'
            GROUP BY tipo ORDER BY total DESC""",
        usuario["empresa_id"],
    )
    return {"24h": [dict(r) for r in rows]}
