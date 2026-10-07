# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Sentinela Endpoint -- /api/v1/agentes.

Duas famílias de rota bem diferentes aqui, de propósito:

  - Gestão de agentes (`GET/POST /agentes`, `POST /agentes/{id}/revogar`):
    sessão humana normal (cookie + CSRF), admin da empresa gerenciando os
    PRÓPRIOS agentes -- mesmo padrão de api/v1/usuarios.py.

  - Heartbeat (`POST /agentes/heartbeat`): não é uma sessão humana. É a
    MÁQUINA do cliente se autenticando com o token de longa duração
    (header X-Sentinela-Agent-Token, ver auth/agentes.py). Sem cookie, sem
    CSRF (CSRF protege contra o BROWSER de outra pessoa forjar uma
    requisição usando a sessão de alguém logado -- não se aplica a um
    agente que nunca teve cookie nenhum).
"""
import uuid
import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from sentinela.auth.dependencies import (
    agente_atual,
    conexao_tenant,
    conexao_tenant_agente,
    conexao_tenant_enrollment,
    enrollment_atual,
    exigir_csrf_header,
    exigir_login,
    exigir_papel,
)
from sentinela.services import agentes as servico
from sentinela.services import chave_ativacao
from sentinela.services import enrollment as servico_enrollment
from sentinela.services.agentes import AgenteHostnameDivergenteError
from sentinela.services.enrollment import TokenEnrollmentInvalidoError
from sentinela.services.licenciamento import LimiteEndpointsExcedidoError
from sentinela.util import ip_valido

router = APIRouter(prefix="/agentes", tags=["agentes"])

_HOSTNAME_MAX_LENGTH = 255
# Teto de processos "suspeitos" por heartbeat -- o agente já filtra do lado
# dele (ver sentinela_agente.py do protótipo), mas o backend nunca confia
# só nisso: sem este teto, um agente comprometido/com bug poderia mandar
# um payload arbitrariamente grande a cada 15-30s.
_MAX_PROCESSOS_SUSPEITOS = 50


class CriarAgenteRequest(BaseModel):
    hostname: str = Field(min_length=1, max_length=_HOSTNAME_MAX_LENGTH)


class CriarEnrollmentRequest(BaseModel):
    """Fase D / D3 -- ver ARQUITETURA_LICENCIAMENTO.md §12. `expira_em` é
    sempre obrigatório (ao contrário de licença, "sem expiração" nunca é
    válido para um token de enrollment -- é uma credencial de curta
    duração por natureza)."""
    expira_em: datetime
    max_usos: int | None = Field(default=None, gt=0)


class EnrollRequest(BaseModel):
    hostname: str = Field(min_length=1, max_length=_HOSTNAME_MAX_LENGTH)


class ProcessoSuspeitoPayload(BaseModel):
    pid: int | None = None
    nome: str | None = Field(default=None, max_length=200)
    usuario: str | None = Field(default=None, max_length=200)
    linha_de_comando: str | None = Field(default=None, max_length=500)


class HeartbeatRequest(BaseModel):
    hostname: str = Field(min_length=1, max_length=_HOSTNAME_MAX_LENGTH)
    sistema_operacional: str = Field(default="", max_length=200)
    versao_agente: str = Field(default="", max_length=50)
    total_processos: int = Field(default=0, ge=0)
    processos_suspeitos: list[ProcessoSuspeitoPayload] = Field(default_factory=list, max_length=_MAX_PROCESSOS_SUSPEITOS)
    # Best-effort -- o agente do protótipo não manda isto ainda (ver
    # próximos passos no documento de proposta). Sem IP, `criar_incidente`
    # recebe "0.0.0.0" (ver services/agentes.py), só para preencher a
    # coluna NOT NULL herdada dos incidentes de rede -- não afeta a
    # detecção em si, que já não depende de IP para incidentes de endpoint.
    ip_local: str | None = None

    @field_validator("ip_local")
    @classmethod
    def _validar_ip_local(cls, valor: str | None) -> str | None:
        """
        Correção de bug encontrado em revisão crítica (2026-09): este era o
        ÚNICO ponto de entrada de IP do sistema que não passava por
        `util.ip_valido` antes de tocar o banco -- todo outro lugar
        (core/firewall.py, core/reputacao.py, core/analisador_logs.py,
        api/v1/reputacao.py) já validava, exatamente por causa do que
        `ip_valido` documenta: um valor que `ipaddress.ip_address()`
        aceita mas que a coluna `inet` do Postgres rejeita (zone id de
        IPv6, ou qualquer string sem forma de IP) estoura
        `asyncpg.exceptions.DataError` -- que NÃO é subclasse de
        `ValueError`, não é pego pelo handler genérico da API, e vira um
        500 cru. Pior: como o heartbeat inteiro roda numa única transação
        (`conexao_tenant_agente`), esse erro no INSERT do incidente
        derrubava o ROLLBACK de TUDO que já tinha sido gravado antes nessa
        mesma requisição -- inclusive o evento bruto de heartbeat e o
        `ultimo_heartbeat_em`, apagando até o rastro de auditoria de um
        heartbeat com processo suspeito de verdade.

        String vazia/None continua permitida (o campo é best-effort, ver
        comentário acima) -- vira None, `criar_incidente` usa "0.0.0.0".
        """
        if valor is None or valor == "":
            return None
        if ip_valido(valor) is None:
            raise ValueError("ip_local não é um endereço IP válido")
        return valor


@router.get("")
async def listar_agentes(usuario: dict = Depends(exigir_login), conn=Depends(conexao_tenant)):
    return {"agentes": await servico.listar_agentes(conn)}


@router.post("", dependencies=[Depends(exigir_csrf_header)])
async def criar_agente(dados: CriarAgenteRequest, usuario: dict = Depends(exigir_papel("admin")),
                         conn=Depends(conexao_tenant)):
    # Fase D / D1 -- `servico.criar_agente` agora tenta vincular o agente
    # novo à licença ativa da empresa (se houver uma), ocupando uma vaga de
    # `licencas_endpoints` -- ver o docstring lá para o raciocínio completo.
    # `LimiteEndpointsExcedidoError` só pode ser levantada quando existe de
    # fato uma licença ativa cujo limite de `planos.max_endpoints` já foi
    # atingido -- traduzida aqui para 409, mesmo código já usado abaixo para
    # hostname duplicado (os dois são "não dá pra criar este agente agora",
    # com motivos diferentes no corpo da resposta).
    try:
        agente, token = await servico.criar_agente(conn, usuario["empresa_id"], dados.hostname, ator_usuario_id=usuario["sub"])
    except LimiteEndpointsExcedidoError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if agente is None:
        raise HTTPException(status_code=409, detail="já existe um agente com este hostname nesta empresa")
    # `token` só existe aqui -- nunca mais recuperável depois desta
    # resposta (só o hash persiste). O chamador (admin) precisa copiar
    # agora e configurar o agente local com ele.
    return {"agente": agente, "token": token}


@router.post("/{agente_id}/kill-switch", dependencies=[Depends(exigir_csrf_header)])
async def kill_switch_agente(agente_id: uuid.UUID, usuario: dict = Depends(exigir_papel("admin")), conn=Depends(conexao_tenant)):
    agente = await servico.definir_habilitado(conn, usuario["empresa_id"], str(agente_id), False, ator_usuario_id=usuario["sub"])
    if agente is None:
        raise HTTPException(status_code=404, detail="agente não encontrado")
    return {"agente": agente, "kill_switch": True}

@router.post("/{agente_id}/reativar", dependencies=[Depends(exigir_csrf_header)])
async def reativar_agente(agente_id: uuid.UUID, usuario: dict = Depends(exigir_papel("admin")), conn=Depends(conexao_tenant)):
    agente = await servico.definir_habilitado(conn, usuario["empresa_id"], str(agente_id), True, ator_usuario_id=usuario["sub"])
    if agente is None:
        raise HTTPException(status_code=404, detail="agente não encontrado")
    return {"agente": agente, "kill_switch": False}


@router.post("/{agente_id}/revogar", dependencies=[Depends(exigir_csrf_header)])
async def revogar_agente(agente_id: uuid.UUID, usuario: dict = Depends(exigir_papel("admin")),
                           conn=Depends(conexao_tenant)):
    agente = await servico.revogar_agente(conn, usuario["empresa_id"], str(agente_id), ator_usuario_id=usuario["sub"])
    if agente is None:
        raise HTTPException(status_code=404, detail="agente não encontrado")
    return {"agente": agente}


# ---------------------------------------------------------------------------
# Fase D / D3 -- enrollment self-service (ver ARQUITETURA_LICENCIAMENTO.md
# §12). `/agentes/enrollment` (gestão, sessão humana admin) e
# `/agentes/enroll` (troca, token de enrollment, sem cookie/CSRF -- mesma
# família "máquina" de `/agentes/heartbeat`) são rotas DIFERENTES de
# propósito, mesma separação já usada para gestão vs. heartbeat acima.
# ---------------------------------------------------------------------------

@router.get("/enrollment")
async def listar_tokens_enrollment(usuario: dict = Depends(exigir_login), conn=Depends(conexao_tenant)):
    return {"tokens": await servico_enrollment.listar_tokens_enrollment(conn)}


@router.post("/enrollment", dependencies=[Depends(exigir_csrf_header)])
async def criar_token_enrollment(dados: CriarEnrollmentRequest, request: Request,
                                   usuario: dict = Depends(exigir_papel("admin")), conn=Depends(conexao_tenant)):
    token_publico, token = await servico_enrollment.criar_token_enrollment(
        conn, usuario["empresa_id"], dados.expira_em, max_usos=dados.max_usos, ator_usuario_id=usuario["sub"],
    )
    # `token` só existe aqui -- nunca mais recuperável depois desta resposta
    # (só o hash persiste), mesma filosofia de criar_agente/criar_licenca.
    backend_url = chave_ativacao.endereco_publico(request.app.state.settings.url_base_publica, str(request.base_url))
    return {"enrollment": token_publico, "token": token, "backend_url": backend_url,
            "chave_ativacao": chave_ativacao.gerar(backend_url, token),
            "aviso": chave_ativacao.aviso_endereco(backend_url)}


@router.post("/enrollment/{enrollment_id}/revogar", dependencies=[Depends(exigir_csrf_header)])
async def revogar_token_enrollment(enrollment_id: uuid.UUID, usuario: dict = Depends(exigir_papel("admin")),
                                     conn=Depends(conexao_tenant)):
    token_publico = await servico_enrollment.revogar_token_enrollment(
        conn, usuario["empresa_id"], str(enrollment_id), ator_usuario_id=usuario["sub"],
    )
    if token_publico is None:
        raise HTTPException(status_code=404, detail="token de enrollment não encontrado")
    return {"enrollment": token_publico}


@router.post("/enroll")
async def enroll(dados: EnrollRequest, enrollment: dict = Depends(enrollment_atual),
                   conn=Depends(conexao_tenant_enrollment)):
    """
    Troca o token de enrollment (header `X-Sentinela-Enrollment-Token`) pela
    identidade PERMANENTE de um agente novo -- ver
    ARQUITETURA_LICENCIAMENTO.md §12. `hostname` vem do CORPO da requisição
    (a máquina se autodeclarando, já que ainda não existe nenhum registro
    prévio para validar contra -- ao contrário do heartbeat, que confere o
    hostname informado contra o REGISTRADO na criação).
    """
    try:
        agente, token = await servico_enrollment.trocar_por_agente(conn, enrollment, dados.hostname)
    except TokenEnrollmentInvalidoError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LimiteEndpointsExcedidoError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if agente is None:
        raise HTTPException(status_code=409, detail="já existe um agente com este hostname nesta empresa")
    return {"agente": agente, "token": token}


@router.post("/heartbeat")
async def heartbeat(dados: HeartbeatRequest, agente: dict = Depends(agente_atual), conn=Depends(conexao_tenant_agente)):
    """
    `agente` (resolvido pelo token) e `conn` (tenant-scoped, resolvido por
    `conexao_tenant_agente` -- que por baixo também depende de
    `agente_atual`) apontam para o MESMO agente: FastAPI cacheia a
    resolução de uma dependência por requisição, então `agente_atual` só
    roda uma vez aqui, não duas.

    `dados.hostname` é validado por `servico.registrar_heartbeat` contra o
    hostname REGISTRADO para este agente (ligado ao token, não ao corpo da
    requisição) -- ver `AgenteHostnameDivergenteError` para o porquê: um
    token válido não deveria conseguir se autodeclarar como qualquer
    hostname arbitrário.
    """
    try:
        incidente = await servico.registrar_heartbeat(
            conn,
            agente["empresa_id"],
            agente["agente_id"],
            dados.hostname,
            dados.sistema_operacional,
            dados.versao_agente,
            dados.total_processos,
            [p.model_dump() for p in dados.processos_suspeitos],
            dados.ip_local,
        )
    except AgenteHostnameDivergenteError:
        raise HTTPException(
            status_code=409,
            detail="hostname informado não corresponde ao hostname registrado para este token de agente",
        )
    # EDR: preserva telemetria de processos suspeitos como evidência estruturada.
    # V8.2: deduplicado por (agente, pid, processo) na última hora -- antes o
    # mesmo processo era regravado a CADA heartbeat, indefinidamente.
    if dados.processos_suspeitos:
        await conn.executemany(
            """INSERT INTO edr_telemetria (empresa_id, agente_id, tipo, hostname, processo, pid, usuario, detalhes, severidade)
               SELECT $1, $2, 'processo_suspeito', $3, $4, $5, $6, $7::jsonb, 'HIGH'
               WHERE NOT EXISTS (
                   SELECT 1 FROM edr_telemetria
                    WHERE empresa_id = $1 AND agente_id = $2 AND pid IS NOT DISTINCT FROM $5
                      AND processo IS NOT DISTINCT FROM $4 AND criado_em > now() - interval '1 hour')""",
            [
                (agente["empresa_id"], agente["agente_id"], dados.hostname, proc.nome, proc.pid, proc.usuario,
                 json.dumps({"linha_de_comando": proc.linha_de_comando, "origem": "heartbeat"}))
                for proc in dados.processos_suspeitos
            ],
        )
    return {"status": "ok", "incidente_criado": incidente is not None, "incidente": incidente}


class EventosAgenteRequest(BaseModel):
    eventos: list[dict] = Field(default_factory=list, max_length=5000)


_MAX_ERROS_DETALHADOS = 20


@router.post("/eventos", status_code=202)
async def ingerir_eventos_agente(
    dados: EventosAgenteRequest,
    agente: dict = Depends(agente_atual),
    conn=Depends(conexao_tenant_agente),
):
    """Ingestão autenticada pelo Agent (Windows Event Log, NetFlow/IPFIX, SNMP, logs Unix).

    V8.2:
    * Validação POR EVENTO: um evento inválido é rejeitado e contado, os
      demais do lote são gravados. Antes a ValidationError estourava como 500
      e o Agent retentava o mesmo lote venenoso (perdendo o lote inteiro).
    * Correlação em LOTE (ver siem/correlacao_siem.py).
    * ``siem_agente_fontes`` soma só o lote atual. Antes somava a contagem do
      HISTÓRICO INTEIRO do agente a cada lote (total inflava sem limite) e
      fazia um GROUP BY sobre todos os eventos do agente a cada requisição.
    """
    from pydantic import ValidationError

    from sentinela.siem.correlacao_siem import correlacionar_lote
    from sentinela.siem.modelos import EventoSIEMEntrada
    from sentinela.siem.servico import persistir_eventos_com_ids

    if not dados.eventos:
        return {"recebidos": 0, "rejeitados": 0, "correlacoes": 0}
    empresa_id = str(agente["empresa_id"])
    agente_id = str(agente["agente_id"])
    normalizados: list[dict] = []
    erros: list[dict] = []
    for indice, raw in enumerate(dados.eventos):
        try:
            normalizados.append(EventoSIEMEntrada.model_validate(raw).normalizado(empresa_id, agente_id))
        except ValidationError as exc:
            if len(erros) < _MAX_ERROS_DETALHADOS:
                erros.append({"indice": indice, "erro": exc.errors(include_url=False, include_input=False)[0]["msg"]})
            else:
                erros.append({"indice": indice})
    if not normalizados:
        raise HTTPException(status_code=422, detail={"mensagem": "nenhum evento válido no lote", "erros": erros[:_MAX_ERROS_DETALHADOS]})

    ids = await persistir_eventos_com_ids(conn, empresa_id, normalizados, agente_id)
    resultado = await correlacionar_lote(conn, empresa_id, list(zip(ids, normalizados)))

    por_tipo: dict[str, tuple[datetime, int]] = {}
    for ev in normalizados:
        tipo = str(ev["source_type"])
        ts, n = por_tipo.get(tipo, (ev["timestamp"], 0))
        por_tipo[tipo] = (max(ts, ev["timestamp"]), n + 1)
    await conn.executemany(
        """INSERT INTO siem_agente_fontes (empresa_id, agente_id, tipo, ultimo_evento_em, total_eventos)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (agente_id, tipo) DO UPDATE
               SET ultimo_evento_em = GREATEST(siem_agente_fontes.ultimo_evento_em, EXCLUDED.ultimo_evento_em),
                   total_eventos = siem_agente_fontes.total_eventos + EXCLUDED.total_eventos""",
        # sorted(): ordem de lock determinística entre lotes concorrentes (deadlock).
        [(agente["empresa_id"], agente["agente_id"], tipo, ts, n) for tipo, (ts, n) in sorted(por_tipo.items())],
    )
    return {
        "recebidos": len(normalizados),
        "rejeitados": len(erros),
        "erros": erros[:_MAX_ERROS_DETALHADOS],
        "correlacoes": resultado["correlacoes"],
        "playbooks": resultado["playbooks"],
        "sigma_alertas": resultado["sigma_alertas"],
    }
