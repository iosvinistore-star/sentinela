# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from sentinela.auth.dependencies import conexao_tenant, exigir_csrf_header, exigir_papel

router = APIRouter(prefix="/siem/fontes", tags=["siem-fontes"])

class FonteSIEMRequest(BaseModel):
    nome: str = Field(min_length=2, max_length=120)
    tipo: str = Field(min_length=2, max_length=80)
    configuracao: dict[str, Any] = Field(default_factory=dict)
    ativo: bool = True

@router.get("")
async def listar_fontes(usuario: dict = Depends(exigir_papel("admin", "analista")), conn=Depends(conexao_tenant)):
    rows = await conn.fetch("""SELECT id,nome,tipo,configuracao,ativo,criado_em FROM siem_fontes WHERE empresa_id=$1 ORDER BY nome""", usuario["empresa_id"])
    return [dict(r) for r in rows]

@router.post("", dependencies=[Depends(exigir_csrf_header)])
async def criar_fonte(dados: FonteSIEMRequest, usuario: dict = Depends(exigir_papel("admin")), conn=Depends(conexao_tenant)):
    try:
        row = await conn.fetchrow("""INSERT INTO siem_fontes(empresa_id,nome,tipo,configuracao,ativo) VALUES($1,$2,$3,$4::jsonb,$5) RETURNING id,nome,tipo,configuracao,ativo,criado_em""", usuario["empresa_id"], dados.nome, dados.tipo.lower(), __import__("json").dumps(dados.configuracao), dados.ativo)
    except Exception as exc:
        if "uq_siem_fontes_tenant_nome" in str(exc) or "duplicate key" in str(exc).lower():
            raise HTTPException(status_code=409, detail="já existe uma fonte com este nome nesta empresa") from exc
        raise
    return dict(row)

@router.patch("/{fonte_id}", dependencies=[Depends(exigir_csrf_header)])
async def atualizar_fonte(fonte_id: int, dados: FonteSIEMRequest, usuario: dict = Depends(exigir_papel("admin")), conn=Depends(conexao_tenant)):
    row = await conn.fetchrow("""UPDATE siem_fontes SET nome=$3,tipo=$4,configuracao=$5::jsonb,ativo=$6 WHERE empresa_id=$1 AND id=$2 RETURNING id,nome,tipo,configuracao,ativo,criado_em""", usuario["empresa_id"], fonte_id, dados.nome, dados.tipo.lower(), __import__("json").dumps(dados.configuracao), dados.ativo)
    if not row:
        raise HTTPException(status_code=404, detail="fonte não encontrada")
    return dict(row)

@router.delete("/{fonte_id}", dependencies=[Depends(exigir_csrf_header)])
async def excluir_fonte(fonte_id: int, usuario: dict = Depends(exigir_papel("admin")), conn=Depends(conexao_tenant)):
    result = await conn.execute("DELETE FROM siem_fontes WHERE empresa_id=$1 AND id=$2", usuario["empresa_id"], fonte_id)
    if result == "DELETE 0":
        raise HTTPException(status_code=404, detail="fonte não encontrada")
    return {"status": "ok"}
