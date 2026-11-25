# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Playbooks SOAR: cadastro, edição, execuções registradas e acionamento manual.

V8.2 (telas de administração):
* ``gatilho`` validado contra os gatilhos que o motor de correlação realmente
  emite (``siem/correlacao_siem.py``). Antes aceitava qualquer texto: um
  playbook com gatilho digitado errado nunca disparava, sem aviso.
* ``PATCH /playbooks/{id}`` para editar e ativar/desativar (antes não havia
  como desligar um playbook).
* ``GET /execucoes`` para a tela acompanhar os registros.
* ``POST /playbooks/{id}/executar`` passa a gravar ``ACIONADO_MANUAL`` e a
  devolver 404 para playbook inexistente/inativo. Antes gravava
  ``EXECUTADO`` -- falso na trilha de auditoria, porque nenhuma ação é
  executada pela plataforma nesta versão -- e respondia 200 com
  ``executado: false`` quando o playbook não existia.
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from sentinela.auth.dependencies import conexao_tenant, exigir_csrf_header, exigir_papel
from sentinela.services import soar as servico_soar

router = APIRouter(prefix="/soar", tags=["soar"])

# Espelha as regras de siem/correlacao_siem.py (+ o curinga do motor).
GATILHOS = {
    "cti_match": "Indicador de ameaça (IOC)",
    "sigma_match": "Regra Sigma",
    "ueba_anomaly": "Anomalia de comportamento (UEBA)",
    "windows_failed_auth": "Falha de autenticação Windows",
    "snmp_alert": "Alerta SNMP",
    "high_severity": "Evento de severidade alta",
    "qualquer_alto_risco": "Qualquer correlação",
}


def _validar_gatilho(v: str) -> str:
    if v not in GATILHOS:
        raise ValueError(f"gatilho inválido; use um de: {', '.join(GATILHOS)}")
    return v


def _validar_acoes(v: list[dict]) -> list[dict]:
    for i, acao in enumerate(v):
        if not isinstance(acao.get("tipo"), str) or not acao["tipo"].strip():
            raise ValueError(f"ação {i + 1}: campo 'tipo' (texto) é obrigatório")
    if len(json.dumps(v)) > 16_000:
        raise ValueError("ações excedem 16 KB")
    return v


class PlaybookIn(BaseModel):
    nome: str = Field(min_length=2, max_length=120)
    gatilho: str
    acoes: list[dict] = Field(default_factory=list, max_length=30)
    ativo: bool = True

    @field_validator("gatilho")
    @classmethod
    def _gatilho(cls, v: str) -> str:
        return _validar_gatilho(v)

    @field_validator("acoes")
    @classmethod
    def _acoes(cls, v: list[dict]) -> list[dict]:
        return _validar_acoes(v)


class PlaybookPatch(BaseModel):
    nome: str | None = Field(default=None, min_length=2, max_length=120)
    gatilho: str | None = None
    acoes: list[dict] | None = Field(default=None, max_length=30)
    ativo: bool | None = None

    @field_validator("gatilho")
    @classmethod
    def _gatilho(cls, v):
        return None if v is None else _validar_gatilho(v)

    @field_validator("acoes")
    @classmethod
    def _acoes(cls, v):
        return None if v is None else _validar_acoes(v)


@router.get("/gatilhos")
async def listar_gatilhos(usuario: dict = Depends(exigir_papel("admin", "analista"))):
    return [{"valor": k, "rotulo": v} for k, v in GATILHOS.items()]


@router.post("/playbooks", dependencies=[Depends(exigir_csrf_header)])
async def criar_playbook(data: PlaybookIn, usuario: dict = Depends(exigir_papel("admin")), sessao=Depends(conexao_tenant)):
    return await servico_soar.criar_playbook(sessao, usuario["empresa_id"], data.nome, data.gatilho, data.acoes, data.ativo)


@router.get("/playbooks")
async def listar_playbooks(usuario: dict = Depends(exigir_papel("admin", "analista")), sessao=Depends(conexao_tenant)):
    return await servico_soar.listar_playbooks(sessao, usuario["empresa_id"])


@router.patch("/playbooks/{playbook_id}", dependencies=[Depends(exigir_csrf_header)])
async def atualizar_playbook(playbook_id: int, data: PlaybookPatch, usuario: dict = Depends(exigir_papel("admin")),
                             sessao=Depends(conexao_tenant)):
    campos = data.model_dump(exclude_none=True)
    if not campos:
        raise HTTPException(status_code=422, detail="nada para atualizar")
    try:
        return await servico_soar.atualizar_playbook(sessao, usuario["empresa_id"], playbook_id, campos)
    except servico_soar.PlaybookNaoEncontradoError as exc:
        raise HTTPException(status_code=404, detail="playbook não encontrado") from exc


@router.get("/execucoes")
async def listar_execucoes(limite: int = Query(50, ge=1, le=500), usuario: dict = Depends(exigir_papel("admin", "analista")),
                           sessao=Depends(conexao_tenant)):
    return await servico_soar.listar_execucoes(sessao, usuario["empresa_id"], limite)


@router.post("/playbooks/{playbook_id}/executar", dependencies=[Depends(exigir_csrf_header)])
async def executar_playbook(playbook_id: int, incidente_id: int | None = None,
                            usuario: dict = Depends(exigir_papel("admin", "analista")), sessao=Depends(conexao_tenant)):
    """Registra o acionamento manual do playbook (auditoria). Nenhuma ação é executada pela plataforma."""
    try:
        run = await servico_soar.acionar_manual(sessao, usuario["empresa_id"], playbook_id, incidente_id, usuario["sub"])
    except servico_soar.PlaybookNaoEncontradoError as exc:
        raise HTTPException(status_code=404, detail="playbook não encontrado ou inativo") from exc
    return {"registrado": True, **run}
