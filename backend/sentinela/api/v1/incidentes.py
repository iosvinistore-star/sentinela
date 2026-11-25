# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""GET/PATCH /api/v1/incidentes/... -- listagem, detalhe e triagem (mudança de status).
Admin e analista podem triar (a triagem é tarefa típica de um analista)."""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from sentinela.auth.dependencies import conexao_tenant, exigir_csrf_header, exigir_login, exigir_papel
from sentinela.services import incidentes as servico

router = APIRouter(prefix="/incidentes", tags=["incidentes"])

_STATUS_VALIDOS = {"OPEN", "EM_ANDAMENTO", "RESOLVIDO", "FALSO_POSITIVO"}


class AtualizarStatusRequest(BaseModel):
    status: str
    # A coluna é `text` (sem teto no banco) -- sem isto, qualquer usuário
    # com papel analista/admin podia gravar um campo de observações de
    # tamanho arbitrário (payload multi-MB) num incidente, sem custo algum
    # pra quem chama.
    observacoes: str = Field(default="", max_length=4000)


@router.get("")
async def listar_incidentes(
    status: str | None = None,
    # gt=0/le=500: sem teto, um `?limite=999999999` virava uma consulta sem
    # LIMIT efetivo -- não vaza dado de OUTRO tenant (RLS ainda filtra por
    # empresa_id), mas é uma consulta arbitrariamente cara/lenta disparável
    # por qualquer usuário autenticado (analista incluído), sem custo algum
    # para quem chama.
    limite: int = Query(100, gt=0, le=500),
    usuario: dict = Depends(exigir_login), sessao=Depends(conexao_tenant),
):
    if status and status not in _STATUS_VALIDOS:
        raise HTTPException(status_code=422, detail=f"status inválido -- use um de {sorted(_STATUS_VALIDOS)}")
    return {"incidentes": await servico.listar_incidentes(sessao, status=status, limite=limite)}


@router.get("/{incident_id}")
async def obter_incidente(incident_id: str, usuario: dict = Depends(exigir_login), sessao=Depends(conexao_tenant)):
    incidente = await servico.obter_incidente(sessao, usuario["empresa_id"], incident_id)
    if incidente is None:
        raise HTTPException(status_code=404, detail="incidente não encontrado")
    return {"incidente": incidente}


@router.patch("/{incident_id}/status", dependencies=[Depends(exigir_csrf_header)])
async def atualizar_status(incident_id: str, dados: AtualizarStatusRequest,
                             # Fase C / C1 -- VIEWER é somente leitura: não pode triar
                             # incidentes. Retrofit de `exigir_login` (que também
                             # aceitava viewer) para `exigir_papel("admin", "analista")`.
                             usuario: dict = Depends(exigir_papel("admin", "analista")), sessao=Depends(conexao_tenant)):
    if dados.status not in _STATUS_VALIDOS:
        raise HTTPException(status_code=422, detail=f"status inválido -- use um de {sorted(_STATUS_VALIDOS)}")
    incidente = await servico.atualizar_status(
        sessao, usuario["empresa_id"], incident_id, dados.status, dados.observacoes, usuario_id=usuario["sub"],
    )
    if incidente is None:
        raise HTTPException(status_code=404, detail="incidente não encontrado")
    return {"incidente": incidente}
