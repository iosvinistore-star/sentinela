# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Sentinela Endpoint -- camada tenant-scoped para gestão de agentes locais e
processamento de heartbeat. Segue a mesma convenção do resto de
`services/*.py`: toda função aqui espera uma conexão JÁ tenant-scoped
(`Database.tenant_session`, de `sentinela.database`) como primeiro argumento.

Geração/verificação do TOKEN em si (que precisa rodar ANTES de saber o
tenant, no caso da autenticação) fica em `auth/agentes.py`, não aqui -- ver
o docstring de `auth/login.py` para o mesmo raciocínio aplicado a usuários.

Escopo desta primeira fase (ver documento "Sentinela Endpoint -- Proposta
de Agente Local"): o agente só OBSERVA. `registrar_heartbeat` pode abrir um
incidente (reaproveitando a mesma `services.incidentes.criar_incidente` que
já existe para ataques de rede), mas nunca aciona firewall nem qualquer
resposta automática local -- isso fica para uma fase futura, deliberadamente
fora do escopo agora.
"""

from sentinela.auth.agentes import gerar_token
from sentinela.auth.security import hash_token
from sentinela.repositories.agentes import AgenteRepositorio
from sentinela.repositories.licencas import LicencaRepositorio
from sentinela.services import auditoria as servico_auditoria
from sentinela.services import incidentes as servico_incidentes
from sentinela.services import licenciamento as servico_licenciamento

STATUS_VALIDOS = {"ativo", "revogado"}

# Heurística de risco DELIBERADAMENTE simples para esta primeira fase --
# não é o mesmo motor de correlação de core/risk_engine.py (que foi
# desenhado em torno de sinais de REDE: volume, diversidade de tipo de
# ataque, reputação de IP). Unificar de verdade os dois motores de risco
# (rede + endpoint) é o próximo passo natural, registrado como tal no
# roadmap do documento de proposta -- não fingido aqui como se já
# estivesse pronto. Cada processo suspeito reportado soma um degrau fixo
# de risco, com teto em CRITICAL.
_SCORE_BASE_PROCESSO_SUSPEITO = 55
_SCORE_POR_PROCESSO_ADICIONAL = 15
_SCORE_TETO = 95

# Correção de bug encontrado em revisão crítica (2026-09): a heurística
# acima é PURAMENTE baseada em contagem -- um único processo suspeito
# nunca passava de MEDIUM, não importa QUAL processo fosse. Isso interage
# mal com `services/automacao.py:auto_classificar_incidentes_abertos`, que
# fecha como FALSO_POSITIVO (após 72h sem revisão humana) qualquer
# incidente sem contenção ativa de firewall com severidade LOW/MEDIUM --
# e um incidente de origem 'endpoint' NUNCA tem contenção de firewall
# nesta fase (o agente só observa, ver docstring do módulo). Resultado:
# um heartbeat reportando um único processo "mimikatz.exe" (ferramenta de
# dump de credenciais amplamente conhecida, sem nenhum uso legítimo fora
# de pentest autorizado) virava MEDIUM e, sem ação humana em 72h, era
# auto-marcado como falso positivo -- uma detecção real de comprometimento
# sendo descartada silenciosamente.
#
# A correção NÃO substitui a heurística por contagem (ela continua valendo
# para processos "suspeitos, mas não claramente maliciosos" -- ex.: um
# executável desconhecido qualquer). Em vez disso, adiciona um segundo
# sinal: se qualquer processo relatado bate com um indicador de ferramenta
# de ataque conhecida (nome do executável OU linha de comando), o score
# vai direto ao teto (CRITICAL), independente da contagem. Lista
# deliberadamente pequena e de alta confiança (ferramentas ofensivas
# amplamente conhecidas, sem uso administrativo legítimo comum) -- não é
# uma tentativa de cobrir todo malware possível, isso é trabalho do motor
# de correlação/reputação, não desta heurística de primeira fase.
_INDICADORES_CRITICOS = frozenset({
    "mimikatz",
    "cobaltstrike",
    "cobalt strike",
    "cobalt-strike",
    "psexec",
    "meterpreter",
    "empire",
    "bloodhound",
    "sharphound",
    "lazagne",
})


def _tem_indicador_critico(processos_suspeitos: list[dict]) -> bool:
    for processo in processos_suspeitos:
        campos = (processo.get("nome") or "", processo.get("linha_de_comando") or "")
        texto = " ".join(campos).lower()
        if any(indicador in texto for indicador in _INDICADORES_CRITICOS):
            return True
    return False


def avaliar_risco_endpoint(processos_suspeitos: list[dict]) -> dict:
    if not processos_suspeitos:
        return {"score": 0, "severity": "LOW"}
    if _tem_indicador_critico(processos_suspeitos):
        # Ferramenta de ataque conhecida detectada -- não é uma questão de
        # "quantos processos", é uma questão de "qual processo". Sempre
        # CRITICAL, sempre no teto, mesmo que seja o único processo
        # suspeito no heartbeat.
        return {"score": _SCORE_TETO, "severity": "CRITICAL"}
    score = min(
        _SCORE_TETO,
        _SCORE_BASE_PROCESSO_SUSPEITO + _SCORE_POR_PROCESSO_ADICIONAL * (len(processos_suspeitos) - 1),
    )
    if score >= 80:
        nivel = "CRITICAL"
    elif score >= 60:
        nivel = "HIGH"
    else:
        nivel = "MEDIUM"
    return {"score": score, "severity": nivel}


def _publico(agente):
    if agente is None:
        return None
    d = agente.para_dict()
    d["id"] = str(d["id"])
    d["empresa_id"] = str(d["empresa_id"])
    if d.get("criado_por_usuario_id") is not None:
        d["criado_por_usuario_id"] = str(d["criado_por_usuario_id"])
    # token_hash nunca sai desta camada para fora -- nem em listagem, nem
    # em resposta de criação (só o token EM CLARO, uma única vez, na
    # própria criação -- ver api/v1/agentes.py).
    d.pop("token_hash", None)
    return d


async def criar_agente(sessao, empresa_id, hostname: str, ator_usuario_id=None):
    """
    Retorna (agente_publico, token_completo). `token_completo` só existe
    neste retorno -- não é recuperável depois (nem por este serviço, nem
    por ninguém: só o hash bcrypt persiste). Se já existe um agente ATIVO
    com este hostname para esta empresa, retorna (None, None) -- o
    chamador decide o 409 (mesmo padrão de services/usuarios.py:criar_usuario
    para email duplicado).

    O conflito é escopado a `status = 'ativo'` via
    `idx_agentes_empresa_hostname_ativo` (índice único PARCIAL, ver
    migrations/0017_agentes_hostname_unico_ativo.sql) -- correção de bug
    encontrado em revisão crítica (2026-09): a UNIQUE constraint original
    (0016) era de tabela inteira, então revogar um agente (que nunca
    apaga a linha -- ver `revogar_agente` abaixo) travava o hostname
    PARA SEMPRE, impedindo reinstalar/reemitir um token para a mesma
    máquina. A cláusula `WHERE status = 'ativo'` abaixo precisa
    espelhar EXATAMENTE o predicado do índice parcial -- é assim que o
    Postgres decide qual índice este `ON CONFLICT` está mirando; como
    toda linha nova nasce com `status` no valor default 'ativo' (ver
    coluna na migration 0016), o predicado sempre bate para um INSERT.
    """
    token_completo, prefixo = gerar_token()
    token_hash = hash_token(token_completo)
    row = await AgenteRepositorio(sessao).inserir_se_hostname_livre(
        empresa_id, hostname, prefixo, token_hash, ator_usuario_id
    )
    if row is None:
        return None, None
    await servico_auditoria.registrar_evento(
        sessao, empresa_id, "agente.criado", {"hostname": hostname, "agente_id": str(row.id)},
        ator_usuario_id=ator_usuario_id,
    )

    # Fase D / D1 (ver ARQUITETURA_LICENCIAMENTO.md §10 -- decisão de
    # arquitetura documentada ANTES desta implementação): o vínculo
    # Agent<->Licença nasce AQUI, na criação do agente, reaproveitando
    # `licencas_endpoints`/`registrar_endpoint` que já existiam prontos
    # desde a etapa de licenciamento (ver docstring de `revogar_agente`
    # abaixo para o outro lado deste mesmo vínculo). Escolhido em vez de
    # "no primeiro heartbeat" ou "ativação da licença" porque é o momento
    # mais cedo possível em que o limite `planos.max_endpoints` pode ser
    # aplicado -- um admin que tenta provisionar um agente além do limite
    # do plano recebe o 409 na hora de gerar o token (ver
    # api/v1/agentes.py:criar_agente), em vez de distribuir um token para
    # uma máquina que nunca vai conseguir ocupar vaga nenhuma, ou pior,
    # descobrir isso só quando o Agent de verdade (D4) já estiver instalado
    # e seu primeiro heartbeat for recusado.
    #
    # Uma empresa SEM nenhuma licença ativa (recurso comercial ainda
    # opcional -- ver docstring da migration 0019_licenciamento.sql) continua
    # podendo criar agentes normalmente, sem vínculo nenhum: licenciamento
    # não é (ainda) pré-requisito para o Sentinela Endpoint funcionar. Se a
    # empresa tiver mais de uma licença (histórico de upgrades/renovações
    # que criaram linhas novas em vez de reaproveitar a mesma -- decisão de
    # `services/licenciamento.py`, não uma restrição de schema), usa a mais
    # recente com status 'ativa'.
    #
    # `LimiteEndpointsExcedidoError`, se levantada por `registrar_endpoint`,
    # propaga daqui para fora sem ser capturada -- a transação inteira
    # (incluindo o INSERT do agente acima) é revertida pelo
    # `Database.tenant_session` que envolve esta chamada (ver
    # db/pool.py:Database.tenant_session), então nunca sobra um agente
    # "órfão" criado sem conseguir vaga; quem traduz isso para HTTP 409 é a
    # rota (api/v1/agentes.py:criar_agente).
    licenca_ativa_id = await LicencaRepositorio(sessao).obter_ativa_mais_recente(empresa_id)
    if licenca_ativa_id is not None:
        await servico_licenciamento.registrar_endpoint(sessao, empresa_id, licenca_ativa_id, row.id)

    return _publico(row), token_completo


async def listar_agentes(sessao):
    return [_publico(a) for a in await AgenteRepositorio(sessao).listar()]


async def obter_agente(sessao, agente_id):
    return _publico(await AgenteRepositorio(sessao).obter(agente_id))


async def revogar_agente(sessao, empresa_id, agente_id, ator_usuario_id=None):
    """
    Revoga (nunca apaga a linha -- preserva o histórico de que este agente
    existiu e o que reportou, mesmo espírito de `ips_protegidos`/sessão de
    superadmin: revogação é uma ação operacional explícita e rastreável,
    não uma exclusão silenciosa). Idempotente: revogar um agente já
    revogado não é erro.

    Correção pós-auditoria (GAP_REPORT_V3.1.md, Fase 18 --
    "liberar_endpoint() não conectado à revogação do Agent"):
    `services.licenciamento.liberar_endpoint` existia pronta desde a
    implementação do módulo de licenciamento (ver
    ARQUITETURA_LICENCIAMENTO.md §4, que já documentava esta chamada como
    trabalho futuro), mas nunca tinha sido conectada a este fluxo -- um
    agente revogado continuava contando para sempre contra
    `planos.max_endpoints` da licença que ocupava, um vazamento de vaga
    que só um UPDATE manual direto no banco resolveria. Chamada aqui, na
    MESMA transação da revogação (atômico: se a liberação falhar por
    qualquer motivo, a revogação também é desfeita, nunca fica um dos dois
    lados feito sozinho).

    Best-effort/idempotente por natureza: um agente que nunca ocupou vaga
    nenhuma (nenhuma chamada bem-sucedida a `licenciamento.registrar_endpoint`
    para ele -- hoje o único caminho que registra isso é o próprio teste de
    integração do módulo de licenciamento, já que o cliente Agent real que
    chamaria isso na prática ainda não foi construído, ver
    ARQUITETURA_LICENCIAMENTO.md §9) não tem o que liberar --
    `liberar_endpoint` já trata esse caso retornando `None` sem levantar
    exceção, e o payload de auditoria abaixo registra honestamente qual dos
    dois casos aconteceu (`vaga_endpoint_liberada`), em vez de fingir que
    uma vaga sempre existia.

    HISTÓRICO (esta correção, GAP_REPORT_V3.1.md Fase 18, resolvia só a
    metade "contabilidade de vagas" do gap -- a outra metade, "Agent para
    de operar quando a LICENÇA é revogada/suspensa", ficou deliberadamente
    NÃO implementada aqui, porque dependia de uma decisão de arquitetura
    (quando um Agent se vincula a uma licença) que só foi tomada na Fase D.
    ATUALIZADO na Fase D: `criar_agente` (acima) agora faz esse vínculo no
    nascimento do agente, e `auth/dependencies.py:conexao_tenant_agente`
    reconfere o status da licença vinculada a cada heartbeat -- ver
    ARQUITETURA_LICENCIAMENTO.md §10 para a decisão completa e o porquê. A
    parte que `liberar_endpoint` faz aqui (soltar a vaga quando o AGENTE é
    revogado) e a parte que a Fase D adicionou (bloquear o heartbeat quando
    a LICENÇA é revogada) são complementares, não a mesma checagem: um
    agente pode ser revogado sem a licença nunca ter sido tocada (libera a
    vaga, nada mais), e uma licença pode ser revogada sem nenhum agente
    específico ser revogado (múltiplos agentes daquela empresa param de
    aceitar heartbeat na hora, mas continuam existindo como linhas
    'ativo').
    """
    row = await AgenteRepositorio(sessao).revogar(empresa_id, agente_id)
    if row is None:
        return None
    vaga_liberada = await servico_licenciamento.liberar_endpoint(sessao, empresa_id, agente_id)
    await servico_auditoria.registrar_evento(
        sessao, empresa_id, "agente.revogado",
        {
            "agente_id": str(agente_id),
            "hostname": row.hostname,
            "vaga_endpoint_liberada": vaga_liberada is not None,
        },
        ator_usuario_id=ator_usuario_id,
    )
    return _publico(row)


def _hostnames_equivalentes(a: str, b: str) -> bool:
    """
    Compara hostnames tolerando diferença de maiúscula/minúscula e espaço
    em branco nas pontas -- correção de bug encontrado em revisão crítica
    (2026-09): a comparação original era um `==` byte a byte. Hostname do
    Windows é case-insensitive por natureza do próprio SO, e o valor
    "registrado" vem de texto livre digitado por um admin humano na hora
    de cadastrar o agente (`POST /agentes`, ver `criar_agente`) -- um
    espaço colado por engano no copia-cola, ou uma diferença de
    caixa entre o que o admin digitou e o que o agente reporta sozinho
    (nome curto vs. FQDN não é coberto por isto, é um problema
    operacional diferente), bastaria para deixar um agente recém-instalado
    incapaz de mandar um único heartbeat -- só perceptível quando alguém
    notar o evento de auditoria `agente.heartbeat_hostname_divergente` e
    tiver que revogar e recriar o agente (reemitir token, reconfigurar a
    máquina). Note que isto NÃO muda a coluna `agentes.hostname`
    persistida nem a unicidade (`idx_agentes_empresa_hostname_ativo`,
    migrations/0017) -- ainda é case-sensitive para fins de cadastro,
    exatamente como já era; só a COMPARAÇÃO do heartbeat ficou mais
    tolerante.
    """
    return a.strip().casefold() == b.strip().casefold()


class AgenteHostnameDivergenteError(Exception):
    """
    Levantado quando o `hostname` de um heartbeat não bate com o hostname
    REGISTRADO para o agente que apresentou o token -- ver o docstring de
    `registrar_heartbeat` logo abaixo para o raciocínio completo. Quem
    chama (api/v1/agentes.py) decide o HTTPException (409), mesmo padrão
    de `LimiteUploadExcedidoError` (core/limites_upload.py).
    """

    def __init__(self, hostname_registrado: str, hostname_recebido: str):
        super().__init__(
            f"hostname divergente: registrado='{hostname_registrado}', recebido='{hostname_recebido}'"
        )
        self.hostname_registrado = hostname_registrado
        self.hostname_recebido = hostname_recebido


async def registrar_heartbeat(
    sessao,
    empresa_id,
    agente_id,
    hostname: str,
    sistema_operacional: str,
    versao_agente: str,
    total_processos: int,
    processos_suspeitos: list[dict],
    ip_local: str | None,
):
    """
    1. Valida que `hostname` (vindo do CORPO da requisição, portanto sob
       controle de quem detém o token -- ver item abaixo) bate com o
       hostname REGISTRADO para este agente (o que `criar_agente` gravou
       na criação, ligado ao token). Achado em revisão crítica (2026-09):
       antes desta validação, o campo `hostname` do heartbeat era aceito
       sem checagem nenhuma e ia direto para o evento bruto e para
       `ataques`/incidente -- ou seja, um token válido para o agente
       "servidor-financeiro" conseguia reportar heartbeats se
       identificando como "notebook-do-estagiario" (ou qualquer string
       arbitrária). Na prática isso permite dois cenários ruins: (a) um
       agente mal configurado (hostname mudou, ex. reimagem de disco sem
       reemitir o token) polui incidentes/auditoria com o hostname ERRADO,
       confundindo quem investiga; (b) um token comprometido poderia ser
       usado para atribuir atividade maliciosa a uma máquina inocente
       (falso rastro), já que nada validava a alegação. A validação é
       propositalmente ANTES de qualquer escrita (nenhum evento é gravado
       para uma divergência) -- só depois de registrar o evento de
       auditoria específico de divergência, para não perder o sinal de
       "alguém apresentou este token afirmando um hostname diferente".
    2. Atualiza `ultimo_heartbeat_em` e os metadados que podem mudar entre
       heartbeats (SO/versão do agente, no caso de auto-update futuro).
    3. Sempre grava um evento bruto em `agentes_eventos` (histórico,
       nunca vira incidente sozinho).
    4. Se `processos_suspeitos` não estiver vazio, avalia risco (ver
       `avaliar_risco_endpoint` acima) e abre (ou ACRESCENTA a um já
       aberto do mesmo agente -- ver
       `servico_incidentes.obter_incidente_endpoint_aberto`/
       `acrescentar_deteccoes`) um incidente de verdade na MESMA tabela
       `incidentes` que ataques de rede usam (`origem` 'endpoint' -- ver
       migrations/0016_agentes_endpoint.sql) -- painel único, não dois
       produtos separados. A deduplicação por agente evita que um
       processo suspeito residente (ex.: mimikatz que continua rodando)
       abra um incidente novo a cada heartbeat, indefinidamente.

    Retorna o incidente (criado OU atualizado) como dict, ou None se nada
    suspeito foi reportado. Levanta `AgenteHostnameDivergenteError` se o
    hostname não bater.
    """
    repo = AgenteRepositorio(sessao)
    hostname_registrado = await repo.obter_hostname(agente_id)
    if hostname_registrado is not None and not _hostnames_equivalentes(hostname_registrado, hostname):
        await servico_auditoria.registrar_evento(
            sessao, empresa_id, "agente.heartbeat_hostname_divergente",
            {
                "agente_id": str(agente_id),
                "hostname_registrado": hostname_registrado,
                "hostname_recebido": hostname,
            },
            ator_usuario_id=None,
        )
        raise AgenteHostnameDivergenteError(hostname_registrado, hostname)

    await repo.registrar_heartbeat(agente_id, sistema_operacional, versao_agente)
    await repo.registrar_evento(
        empresa_id, agente_id, "heartbeat",
        {
            "hostname": hostname,
            "total_processos": total_processos,
            "processos_suspeitos": processos_suspeitos,
        },
    )

    if not processos_suspeitos:
        return None

    risco = avaliar_risco_endpoint(processos_suspeitos)
    ataques = [
        {
            "tipo": "Processo suspeito (endpoint)",
            "pid": p.get("pid"),
            "nome": p.get("nome"),
            "usuario": p.get("usuario"),
            "linha_de_comando": p.get("linha_de_comando"),
        }
        for p in processos_suspeitos
    ]

    # Correção de bug encontrado em revisão crítica (2026-09): um processo
    # suspeito residente (mimikatz que continua rodando, por exemplo) abria
    # um incidente CRITICAL novo a CADA heartbeat -- a cada 15-30s,
    # indefinidamente -- inundando a tabela de incidentes. Se este agente
    # já tem um incidente OPEN/EM_ANDAMENTO, a nova detecção é ANEXADA a
    # ele (nunca abaixa severidade/score, só escala) em vez de abrir um
    # incidente paralelo; só abre um novo se não houver nenhum aberto
    # (primeira detecção, ou o anterior já foi RESOLVIDO/FALSO_POSITIVO).
    incidente_aberto = await servico_incidentes.obter_incidente_endpoint_aberto(sessao, empresa_id, agente_id)
    if incidente_aberto is not None:
        incidente = await servico_incidentes.acrescentar_deteccoes(
            sessao, empresa_id, incidente_aberto["incident_id"], risco, ataques,
        )
    else:
        # Bandit sinaliza B104 aqui: interpreta o literal abaixo como um
        # bind de rede (falso positivo, ver auditoria V3.1,
        # GAP_REPORT_V3.1.md Fase 18). É só um valor-placeholder para a
        # coluna `inet` NOT NULL de `incidentes.ip` quando o heartbeat do
        # agente não informa `ip_local` (best-effort, ver
        # HeartbeatRequest.ip_local em api/v1/agentes.py) -- nenhum socket
        # é aberto/escutado neste ponto. Suprimido inline abaixo.
        incidente = await servico_incidentes.criar_incidente(
            sessao, empresa_id, ip_local or "0.0.0.0", risco, ataques, origem="endpoint", agente_id=agente_id,  # nosec B104
        )
    if incidente is not None:
        await repo.registrar_evento(
            empresa_id, agente_id, "processo_suspeito",
            {"incidente_id": incidente["incident_id"], "ataques": ataques},
        )
    return incidente


async def definir_habilitado(sessao, empresa_id, agente_id, habilitado: bool, ator_usuario_id=None):
    row = await AgenteRepositorio(sessao).definir_habilitado(empresa_id, agente_id, habilitado)
    if row is None:
        return None
    await servico_auditoria.registrar_evento(
        sessao, empresa_id, "AGENT_ENABLED" if habilitado else "AGENT_DISABLED", {"agente_id": str(agente_id)},
        ator_usuario_id=ator_usuario_id,
    )
    return _publico(row)
