# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Exportação STIX 2.1 e leitura TAXII 2.1 (somente leitura) dos indicadores do tenant.

V8.2: indicadores exportados agora são STIX 2.1 válidos (``valid_from``
obrigatório, timestamps em UTC com ``Z``, ids determinísticos, valor
escapado no padrão). O endpoint de objetos devolve 404 para coleção
desconhecida (antes qualquer id devolvia tudo), usa o media type TAXII e
pagina com ``next``/``more``.

Limitação conhecida (declarar na matriz do edital): não há Discovery nem
API Root TAXII completos; é um endpoint de leitura compatível com o
formato de envelope, autenticado pela sessão do Sentinela.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse

from sentinela.auth.dependencies import conexao_tenant, exigir_papel
from sentinela.siem.cti import NAMESPACE_STIX, indicador_para_stix

router = APIRouter(prefix="/cti", tags=["cti-feed"])

COLECAO_ID = "sentinela-indicators"
MEDIA_TAXII = "application/taxii+json;version=2.1"
_SQL = """SELECT id, stix_id, indicator_type, valor, pattern, confidence, valid_until, labels, criado_em
            FROM cti_indicadores WHERE empresa_id=$1 AND id > $2 ORDER BY id LIMIT $3"""


@router.get("/stix/export")
async def exportar_stix(limite: int = Query(1000, ge=1, le=5000), usuario=Depends(exigir_papel("admin", "analista")),
                        conn=Depends(conexao_tenant)):
    empresa = str(usuario["empresa_id"])
    rows = await conn.fetch(_SQL, usuario["empresa_id"], 0, limite)
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}",
            "objects": [indicador_para_stix(dict(r), empresa) for r in rows]}


@router.get("/taxii/collections")
async def collections(usuario=Depends(exigir_papel("admin", "analista"))):
    return JSONResponse(
        {"collections": [{"id": COLECAO_ID, "title": "Sentinela Indicators",
                          "description": "Indicadores CTI STIX 2.1 do tenant", "can_read": True,
                          "can_write": False, "media_types": ["application/stix+json;version=2.1"]}]},
        media_type=MEDIA_TAXII,
    )


@router.get("/taxii/collections/{collection_id}/objects")
async def taxii_objects(collection_id: str, limite: int = Query(1000, ge=1, le=5000),
                        cursor: int = Query(0, ge=0, alias="next"),
                        usuario=Depends(exigir_papel("admin", "analista")), conn=Depends(conexao_tenant)):
    if collection_id != COLECAO_ID:
        raise HTTPException(status_code=404, detail="coleção não encontrada")
    empresa = str(usuario["empresa_id"])
    rows = await conn.fetch(_SQL, usuario["empresa_id"], cursor, limite + 1)
    mais = len(rows) > limite
    rows = rows[:limite]
    corpo: dict = {"more": mais, "objects": [indicador_para_stix(dict(r), empresa) for r in rows]}
    if mais:
        corpo["next"] = str(rows[-1]["id"])
    return JSONResponse(corpo, media_type=MEDIA_TAXII)


# Mantido para compatibilidade de import em testes/integrações antigas.
__all__ = ["router", "NAMESPACE_STIX"]
