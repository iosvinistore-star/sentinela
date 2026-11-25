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
from sentinela.services import siem as servico_siem

router = APIRouter(prefix="/siem/fontes", tags=["siem-fontes"])

class FonteSIEMRequest(BaseModel):
    nome: str = Field(min_length=2, max_length=120)
    tipo: str = Field(min_length=2, max_length=80)
    configuracao: dict[str, Any] = Field(default_factory=dict)
    ativo: bool = True

@router.get("")
async def listar_fontes(usuario: dict = Depends(exigir_papel("admin", "analista")), sessao=Depends(conexao_tenant)):
    return await servico_siem.listar_fontes(sessao, usuario["empresa_id"])

@router.post("", dependencies=[Depends(exigir_csrf_header)])
async def criar_fonte(dados: FonteSIEMRequest, usuario: dict = Depends(exigir_papel("admin")), sessao=Depends(conexao_tenant)):
    try:
        return await servico_siem.criar_fonte(sessao, usuario["empresa_id"], dados.nome, dados.tipo, dados.configuracao, dados.ativo)
    except servico_siem.FonteSiemDuplicadaError as exc:
        raise HTTPException(status_code=409, detail="já existe uma fonte com este nome nesta empresa") from exc

@router.patch("/{fonte_id}", dependencies=[Depends(exigir_csrf_header)])
async def atualizar_fonte(fonte_id: int, dados: FonteSIEMRequest, usuario: dict = Depends(exigir_papel("admin")), sessao=Depends(conexao_tenant)):
    fonte = await servico_siem.atualizar_fonte(sessao, usuario["empresa_id"], fonte_id, dados.nome, dados.tipo, dados.configuracao, dados.ativo)
    if not fonte:
        raise HTTPException(status_code=404, detail="fonte não encontrada")
    return fonte

@router.delete("/{fonte_id}", dependencies=[Depends(exigir_csrf_header)])
async def excluir_fonte(fonte_id: int, usuario: dict = Depends(exigir_papel("admin")), sessao=Depends(conexao_tenant)):
    if not await servico_siem.excluir_fonte(sessao, usuario["empresa_id"], fonte_id):
        raise HTTPException(status_code=404, detail="fonte não encontrada")
    return {"status": "ok"}
