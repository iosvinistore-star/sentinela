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
from sentinela.services import cti as servico_cti
from sentinela.siem.cti import CTIErro, buscar_taxii_collection, extrair_bundle_stix

router = APIRouter(prefix="/cti", tags=["cti"])

_MAX_OBJETOS = 50_000

class STIXBundle(BaseModel):
    type: str
    id: str | None = None
    objects: list[dict[str, Any]] = Field(default_factory=list, max_length=_MAX_OBJETOS)


class TAXIIImport(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    api_key: str | None = Field(default=None, max_length=512)


async def _gravar(sessao, empresa_id, payload: dict[str, Any]) -> int:
    try:
        indicadores = extrair_bundle_stix(payload, str(empresa_id))
    except CTIErro as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return await servico_cti.gravar_indicadores(sessao, empresa_id, indicadores)


@router.post("/stix/bundle", dependencies=[Depends(exigir_csrf_header)])
async def importar_stix(bundle: STIXBundle, usuario: dict = Depends(exigir_papel("admin", "analista")),
                        sessao=Depends(conexao_tenant)):
    total = await _gravar(sessao, usuario["empresa_id"], bundle.model_dump())
    return {"importados": total, "ignorados": len(bundle.objects) - total}


@router.post("/taxii/import", dependencies=[Depends(exigir_csrf_header)])
async def importar_taxii(data: TAXIIImport, usuario: dict = Depends(exigir_papel("admin")),
                         sessao=Depends(conexao_tenant)):
    """Busca uma coleção TAXII 2.1 (``.../collections/{id}/objects/``).

    Restrito a admin: é a única rota que faz o servidor abrir conexão para um
    destino escolhido pelo usuário. Destinos internos/reservados, HTTP puro
    (salvo opt-in) e redirects são recusados -- ver siem/cti.py.
    """
    try:
        payload = await asyncio.to_thread(buscar_taxii_collection, data.url, 10.0, data.api_key)
    except CTIErro as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    total = await _gravar(sessao, usuario["empresa_id"], payload)
    return {"importados": total}


@router.get("/indicadores")
async def listar_indicadores(limite: int = Query(100, ge=1, le=1000),
                             usuario: dict = Depends(exigir_papel("admin", "analista")),
                             sessao=Depends(conexao_tenant)):
    return await servico_cti.listar_indicadores(sessao, usuario["empresa_id"], limite)
