# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Regras de negócio de incidentes -- equivalente ao antigo `incidents.py`
(SQLite), agora sobre Postgres/SQLAlchemy, escopado por empresa via RLS.

Camada de serviço: sem SQL aqui (isso é do `IncidenteRepositorio`). Toda
função espera uma `AsyncSession` já escopada (ver
`sentinela.database.session.Database.tenant_session`) como primeiro
argumento -- não abre conexão própria, para que o chamador controle a
transação/tenant.
"""
import uuid
from datetime import datetime, timezone

from sentinela.repositories.incidentes import IncidenteRepositorio
from sentinela.services import auditoria as servico_auditoria


def _gerar_incident_id(ip: str) -> str:
    """
    Item 17 do plano de endurecimento pós-auditoria: o formato legado do
    incidents.py (INC-YYYYMMDD-<ip8>-HHMMSS) colidia sempre que o MESMO IP
    gerava um segundo incidente HIGH/CRITICAL dentro do MESMO segundo --
    nada hipotético: um upload de log processa um relatório inteiro em
    memória antes de chamar `responder_a_incidentes`, então dois lotes de
    ataque do mesmo IP em relatórios diferentes analisados no mesmo
    segundo (ou até o mesmo relatório reprocessado por um retry) geravam o
    mesmo `incident_id` -- e `criar_incidente` silenciosamente descarta
    esse segundo incidente via `ON CONFLICT DO NOTHING` (comportamento
    herdado do `INSERT OR IGNORE` do incidents.py/SQLite legado), perdendo
    o registro sem erro nenhum visível pra quem chamou.

    A correção troca só o SUFIXO por 12 hex chars de um uuid4 (48 bits de
    aleatoriedade -- colisão prática impossível mesmo em altíssimo volume),
    em vez de HHMMSS. Mantém o prefixo `INC-<data>-<ip8>` (nenhum código
    depende do formato exato -- ver services/incidentes.py só usa o valor
    como string opaca -- mas manter data+IP legíveis ajuda quem está
    triando incidentes visualmente no dashboard/lista). Não usamos uma
    biblioteca de ULID à toa: `uuid` já é da biblioteca padrão, e o pedido
    original era resolver a COLISÃO, não conseguir ordenação lexicográfica
    por tempo (a tabela já ordena por `criado_em`, uma coluna de verdade,
    não pelo ID). `ON CONFLICT DO NOTHING` continua como defesa em
    profundidade, agora praticamente inatingível.
    """
    agora = datetime.now(timezone.utc)
    sufixo_ip = ip.replace(":", "").replace(".", "")[-8:]
    sufixo_aleatorio = uuid.uuid4().hex[:12]
    return f"INC-{agora.strftime('%Y%m%d')}-{sufixo_ip}-{sufixo_aleatorio}"


def _linha_para_dict(incidente):
    """Modelo -> dict público: `ip` (inet) e `empresa_id` (uuid) viram str, uma vez, aqui."""
    if incidente is None:
        return None
    d = incidente.para_dict()
    if d.get("empresa_id") is not None:
        d["empresa_id"] = str(d["empresa_id"])
    return d


async def criar_incidente(sessao, empresa_id, ip: str, risco: dict, ataques: list, origem: str = "rede", agente_id=None):
    """
    risco: dict no formato de risk_engine.calcular_risco (precisa de
    "severity" e "score"). Retorna a linha criada (dict) ou None em caso de
    colisão de incident_id (mesmo IP + mesmo segundo -- extremamente raro;
    o comportamento de "silenciosamente não grava e segue" é herdado do
    incidents.py legado, que tinha a mesma limitação com INSERT OR IGNORE).

    `origem` (migrations/0016_agentes_endpoint.sql): 'rede' (default,
    preserva o comportamento de todo chamador existente que não passa este
    argumento) ou 'endpoint' (ver services/agentes.py -- Sentinela
    Endpoint). Painel único de incidentes para as duas origens, em vez de
    uma tabela paralela por fonte de sinal.

    `agente_id` (migrations/0018_incidentes_agente_dedup.sql): só
    preenchido para `origem='endpoint'` -- ver
    `obter_incidente_endpoint_aberto`/`acrescentar_deteccoes` abaixo, que
    usam esta coluna para não abrir um incidente novo a cada heartbeat
    enquanto a mesma detecção continua ativa no mesmo agente.
    """
    incident_id = _gerar_incident_id(ip)
    row = await IncidenteRepositorio(sessao).inserir_ignorando_duplicata(
        empresa_id=empresa_id,
        incident_id=incident_id,
        ip=ip,
        severidade=risco["severity"],
        pontuacao_risco=risco["score"],
        ataques=list(ataques),
        origem=origem,
        agente_id=agente_id,
    )
    criado = _linha_para_dict(row)
    if criado is not None:
        # Alerta no celular (services/push.py). Fica AQUI, e não em cada
        # chamador, para que os dois caminhos que abrem incidente -- rede e
        # endpoint -- avisem do mesmo jeito. Não espera a entrega e engole
        # qualquer erro: a notificação é um extra, gravar o incidente não.
        from sentinela.services import push as servico_push

        servico_push.agendar_alerta_incidente(empresa_id, criado)
    return criado


async def obter_incidente_endpoint_aberto(sessao, empresa_id, agente_id):
    """
    O incidente OPEN/EM_ANDAMENTO mais recente deste agente, se houver.
    Correção de bug encontrado em revisão crítica (2026-09): usado por
    `services/agentes.py:registrar_heartbeat` para decidir entre abrir um
    incidente NOVO ou só acrescentar a detecção mais recente a um já
    aberto -- sem isto, um processo suspeito residente (mimikatz que
    continua rodando) abria um incidente CRITICAL novo a cada ciclo de
    heartbeat (15-30s) indefinidamente. Só considera incidentes já
    RESOLVIDO/FALSO_POSITIVO como "fechados" -- se um humano (ou a
    auto-triagem) já encerrou o caso, uma detecção nova depois disso abre
    um incidente NOVO de propósito (o caso anterior já foi julgado).
    """
    row = await IncidenteRepositorio(sessao).obter_endpoint_aberto(empresa_id, agente_id)
    return _linha_para_dict(row)


async def acrescentar_deteccoes(sessao, empresa_id, incident_id: str, risco_novo: dict, ataques_novos: list):
    """
    Funde uma nova detecção (heartbeat de endpoint) num incidente JÁ
    ABERTO do mesmo agente (ver `obter_incidente_endpoint_aberto`), em vez
    de abrir um incidente paralelo. Nunca REBAIXA severidade/score -- só
    escala se a nova detecção for mais grave que o que já estava
    registrado (`GREATEST`/`CASE` abaixo); os ataques da nova detecção são
    ANEXADOS à lista existente (nunca substituem), preservando o histórico
    completo de tudo que já foi visto neste incidente."""
    row = await IncidenteRepositorio(sessao).acrescentar_deteccoes(
        empresa_id, incident_id, list(ataques_novos), risco_novo["score"], risco_novo["severity"]
    )
    return _linha_para_dict(row)


async def listar_incidentes(sessao, status: str | None = None, limite: int = 100):
    rows = await IncidenteRepositorio(sessao).listar(status, limite)
    return [_linha_para_dict(r) for r in rows]


async def obter_incidente(sessao, empresa_id, incident_id: str):
    """
    O `WHERE empresa_id = $1` abaixo é redundante com a RLS da tabela
    `incidentes` (a conexão já está escopada para uma única empresa por
    `tenant_scoped_connection` -- sem RLS, isto já bastaria pra vazar
    incidentes de outra empresa por `incident_id` adivinhado/enumerado).
    Mantido mesmo assim como defesa em profundidade: se um dia a RLS for
    removida por engano, ou a conexão passada aqui não estiver mais
    corretamente escopada (ex.: um `superadmin_scoped_connection` usado por
    engano numa rota que deveria ser tenant-only), esta cláusula sozinha já
    impede o vazamento entre empresas, em vez de depender só de uma camada.
    """
    row = await IncidenteRepositorio(sessao).obter(empresa_id, incident_id)
    return _linha_para_dict(row)


async def atualizar_status(sessao, empresa_id, incident_id: str, status: str, observacoes: str = "", usuario_id=None):
    """Mesma defesa em profundidade de `obter_incidente` -- ver docstring lá.

    `usuario_id` (item novo do modo autônomo -- ver
    migrations/0014_autonomia_operacional.sql e
    services/automacao.py) distingue uma mudança de status feita por um
    HUMANO de uma feita pela auto-triagem
    (`services/automacao.auto_classificar_incidentes_abertos`, que chama
    esta mesma lógica de gravação por SQL direto, não por esta função --
    ela nunca passa por EM_ANDAMENTO, vai direto para RESOLVIDO/
    FALSO_POSITIVO):
      - status -> EM_ANDAMENTO com usuario_id: grava
        `em_andamento_por_usuario_id` (só a PRIMEIRA vez -- COALESCE
        preserva quem pegou o incidente primeiro, mesmo que outro
        analista/admin volte a tocar o status depois).
      - status -> RESOLVIDO/FALSO_POSITIVO: grava `resolvido_por` =
        'humano' quando usuario_id foi informado (sempre é o caso aqui,
        rota HTTP -- só a auto-triagem grava 'sistema', e não passa por
        esta função).
    """
    resolvido_por = "humano" if status in ("RESOLVIDO", "FALSO_POSITIVO") else None
    em_andamento_usuario = usuario_id if status == "EM_ANDAMENTO" else None
    row = await IncidenteRepositorio(sessao).atualizar_status(
        empresa_id, incident_id, status, observacoes, em_andamento_usuario, resolvido_por
    )
    if row is not None:
        await servico_auditoria.registrar_evento(
            sessao, empresa_id, "incidente.status_atualizado",
            {"incident_id": incident_id, "status": status},
            ator_usuario_id=usuario_id,
        )
    return _linha_para_dict(row)
