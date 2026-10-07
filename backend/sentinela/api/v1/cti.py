# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""CTI: importação STIX 2.x (bundle) e TAXII 2.1, e listagem de indicadores."""
from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from sentinela.auth.dependencies import conexao_tenant, exigir_csrf_header, exigir_papel
from sentinela.siem.cti import CTIErro, buscar_taxii_collection, extrair_bundle_stix

router = APIRouter(prefix="/cti", tags=["cti"])

_MAX_OBJETOS = 50_000

_UPSERT = """INSERT INTO cti_indicadores
    (empresa_id, stix_id, tipo, indicator_type, valor, pattern, confidence, valid_until, labels, raw)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb)
    ON CONFLICT (empresa_id, stix_id) DO UPDATE SET
        indicator_type=EXCLUDED.indicator_type, valor=EXCLUDED.valor, pattern=EXCLUDED.pattern,
        confidence=EXCLUDED.confidence, valid_until=EXCLUDED.valid_until, labels=EXCLUDED.labels, raw=EXCLUDED.raw"""


class STIXBundle(BaseModel):
    type: str
    id: str | None = None
    objects: list[dict[str, Any]] = Field(default_factory=list, max_length=_MAX_OBJETOS)


class TAXIIImport(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    api_key: str | None = Field(default=None, max_length=512)


async def _gravar(conn, empresa_id, payload: dict[str, Any]) -> int:
    try:
        indicadores = extrair_bundle_stix(payload, str(empresa_id))
    except CTIErro as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if indicadores:
        await conn.executemany(_UPSERT, [
            (empresa_id, i["stix_id"], i["tipo"], i["indicator_type"], i["valor"], i["pattern"],
             i["confidence"], i["valid_until"], i["labels"], i["raw"]) for i in indicadores
        ])
    return len(indicadores)


@router.post("/stix/bundle", dependencies=[Depends(exigir_csrf_header)])
async def importar_stix(bundle: STIXBundle, usuario: dict = Depends(exigir_papel("admin", "analista")),
                        conn=Depends(conexao_tenant)):
    total = await _gravar(conn, usuario["empresa_id"], bundle.model_dump())
    return {"importados": total, "ignorados": len(bundle.objects) - total}


@router.post("/taxii/import", dependencies=[Depends(exigir_csrf_header)])
async def importar_taxii(data: TAXIIImport, usuario: dict = Depends(exigir_papel("admin")),
                         conn=Depends(conexao_tenant)):
    """Busca uma coleção TAXII 2.1 (``.../collections/{id}/objects/``).

    Restrito a admin: é a única rota que faz o servidor abrir conexão para um
    destino escolhido pelo usuário. Destinos internos/reservados, HTTP puro
    (salvo opt-in) e redirects são recusados -- ver siem/cti.py.
    """
    try:
        payload = await asyncio.to_thread(buscar_taxii_collection, data.url, 10.0, data.api_key)
    except CTIErro as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    total = await _gravar(conn, usuario["empresa_id"], payload)
    return {"importados": total}


@router.get("/indicadores")
async def listar_indicadores(limite: int = Query(100, ge=1, le=1000),
                             usuario: dict = Depends(exigir_papel("admin", "analista")),
                             conn=Depends(conexao_tenant)):
    rows = await conn.fetch(
        """SELECT id, stix_id, indicator_type, valor, confidence, valid_until, labels, criado_em
             FROM cti_indicadores WHERE empresa_id=$1 ORDER BY criado_em DESC LIMIT $2""",
        usuario["empresa_id"], limite,
    )
    return [dict(r) for r in rows]
