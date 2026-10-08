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
from sentinela.services import sigma as servico_sigma
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


@router.post("/regras", dependencies=[Depends(exigir_csrf_header)])
async def criar(data: SigmaIn, usuario=Depends(exigir_papel("admin")), sessao=Depends(conexao_tenant)):
    if len(json.dumps(data.detection)) > 64_000:
        raise HTTPException(status_code=413, detail="detection excede 64 KB")
    try:
        compilar_regra({"logsource": data.logsource, "detection": data.detection})
    except SigmaErro as exc:
        raise HTTPException(status_code=422, detail=f"regra Sigma inválida ou não suportada: {exc}") from exc
    return await servico_sigma.salvar_regra(sessao, usuario["empresa_id"], data.model_dump())


@router.get("/regras")
async def listar(usuario=Depends(exigir_papel("admin", "analista")), sessao=Depends(conexao_tenant)):
    return await servico_sigma.listar_regras(sessao, usuario["empresa_id"])


@router.get("/alertas")
async def alertas(limite: int = Query(100, ge=1, le=1000), usuario=Depends(exigir_papel("admin", "analista")),
                  sessao=Depends(conexao_tenant)):
    return await servico_sigma.listar_alertas(sessao, usuario["empresa_id"], limite)


@router.post("/avaliar-evento/{evento_id}", dependencies=[Depends(exigir_csrf_header)])
async def avaliar(evento_id: int, usuario=Depends(exigir_papel("admin", "analista")), sessao=Depends(conexao_tenant)):
    try:
        hits = await servico_sigma.avaliar_evento(sessao, usuario["empresa_id"], evento_id)
    except servico_sigma.EventoNaoEncontradoError as exc:
        raise HTTPException(404, "evento não encontrado") from exc
    return {"matches": hits}
