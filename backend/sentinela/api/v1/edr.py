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
from sentinela.services import edr as servico_edr

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
async def ingest(data: TelemetriaIn, usuario=Depends(exigir_papel("admin", "analista")), sessao=Depends(conexao_tenant)):
    if len(json.dumps(data.detalhes)) > 32_000:
        raise HTTPException(status_code=413, detail="detalhes excede 32 KB")
    return await servico_edr.registrar_telemetria(sessao, usuario["empresa_id"], **data.model_dump())


@router.get("/telemetria")
async def listar(limite: int = Query(100, ge=1, le=1000), usuario=Depends(exigir_papel("admin", "analista")),
                 sessao=Depends(conexao_tenant)):
    return await servico_edr.listar_telemetria(sessao, usuario["empresa_id"], limite)


@router.get("/resumo")
async def resumo(usuario=Depends(exigir_papel("admin", "analista")), sessao=Depends(conexao_tenant)):
    return await servico_edr.resumo_24h(sessao, usuario["empresa_id"])
