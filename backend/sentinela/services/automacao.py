# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Autonomia operacional: as quatro capacidades que fecham as dependências de
um humano presente que ainda restavam depois do plano de endurecimento
pós-auditoria --

  1. avaliar_e_ajustar_modo_firewall -- o nível de automação de firewall de
     um tenant sobe/desce sozinho, olhando o histórico real de acertos e
     erros dos bloqueios automáticos daquele tenant.
  2. auto_classificar_incidentes_abertos -- incidentes esquecidos (sem
     nenhum humano ter tocado) por tempo demais se auto-resolvem ou viram
     falso positivo, com um critério deliberadamente conservador.
  3. obter_contagem_falsos_positivos -- alimenta o amortecimento de risco
     (ver core/risk_engine.aplicar_amortecimento_falso_positivo) usado por
     services/resposta_incidentes.py antes de decidir bloquear de novo.
  4. ips_protegidos -- curadoria automática (e manual) de uma whitelist
     persistida por tenant (ver services/firewall.py para os dois pontos
     que alimentam/consultam isto).

1, 2 e 4-automático são OPT-IN por tenant (ver migrations/0014_...sql e
services/empresas.py -- default false/off, um superadmin liga
explicitamente por empresa). 3 é sempre-ativo (só torna o sistema mais
conservador, nunca mais agressivo -- ver core/risk_engine.py). Toda decisão
autônoma grava um evento de auditoria com ator_usuario_id=None -- "sistema"
é um ator visível e rastreável, nunca uma decisão silenciosa; nada aqui
apaga o rastro de quem (ou o quê) decidiu o quê.

`executar_ciclo_autonomo` é o ponto de entrada periódico (chamado pelo loop
em `rodar_ciclo_autonomo_periodicamente`, iniciado no lifespan -- ver
main.py) que dá vida a 1 e 2 sem depender de nenhuma requisição HTTP: sem
isso, a autonomia dependeria de alguém continuar fazendo upload de log pra
"destravar" a reavaliação, o que ainda seria uma dependência humana
disfarçada.
"""
import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sentinela.repositories.empresas import EmpresaRepositorio
from sentinela.repositories.incidentes import IncidenteRepositorio
from sentinela.repositories.ips_protegidos import IpProtegidoRepositorio
from sentinela.services import auditoria as servico_auditoria

logger = logging.getLogger("sentinela.automacao")

# Escada de autoajuste -- só transita dentro destes três modos. Um tenant em
# "observacao" ou "dry_run" fez uma escolha deliberada de nunca automatizar
# (ou nunca automatizar de verdade) -- o autoajuste nunca tira o tenant
# desses dois modos, nem entra neles vindo da escada.
_ESCADA_MODO_FIREWALL = ["manual", "automacao_controlada", "automacao_total"]

_JANELA_AMOSTRAS = 20
_MINIMO_PARA_PROMOVER = 20
_MINIMO_PARA_REBAIXAR = 5
_TAXA_PROBLEMA_PARA_PROMOVER = 0.05
_TAXA_PROBLEMA_PARA_REBAIXAR = 0.15
_JANELA_FREIO_EMERGENCIA = 5

_HORAS_INCIDENTE_PARADO = 72

REVERSAO_RAPIDA_HORAS = 1  # usado por services/firewall.py (capacidade 4)


async def avaliar_e_ajustar_modo_firewall(sessao, empresa_id):
    """
    Lê os últimos `_JANELA_AMOSTRAS` bloqueios AUTOMÁTICOS (incidente_id IS
    NOT NULL) desta empresa e decide se `modo_firewall` deveria subir ou
    descer um degrau na escada. "Problema" = o incidente que originou o
    bloqueio foi marcado FALSO_POSITIVO, OU o próprio bloqueio foi revertido
    em menos de 2h (sinal de que um humano corrigiu a automação rápido
    demais).

    Promove com <= 5% de problema em >= 20 amostras; rebaixa com > 15% de
    problema em >= 5 amostras. Freio de emergência: já no topo da escada
    (automacao_total), qualquer problema nas últimas
    `_JANELA_FREIO_EMERGENCIA` amostras derruba um degrau na hora, sem
    esperar acumular a taxa de 15% -- é o modo mais permissivo, então o
    custo de um falso positivo escorregar é o maior.

    `sessao`: espera uma sessão com BYPASSRLS (superadmin_session)
    -- é quem tem o GRANT UPDATE em `empresas` (ver services/empresas.py,
    escrita em `empresas` é admin-only de propósito). Filtra por
    empresa_id explicitamente em toda consulta (defesa em profundidade --
    BYPASSRLS não filtra sozinho).
    """
    linha_empresa = await EmpresaRepositorio(sessao).obter_config_firewall(empresa_id)
    if linha_empresa is None or not linha_empresa.modo_firewall_auto:
        return None
    modo_atual = linha_empresa.modo_firewall
    if modo_atual not in _ESCADA_MODO_FIREWALL:
        return None

    amostras = await IncidenteRepositorio(sessao).amostras_de_bloqueios_automaticos(empresa_id, _JANELA_AMOSTRAS)
    if not amostras:
        return None

    total = len(amostras)
    problemas = sum(1 for a in amostras if a["revertido_rapido"] or a["foi_falso_positivo"])
    taxa_problema = problemas / total
    indice_atual = _ESCADA_MODO_FIREWALL.index(modo_atual)

    novo_modo = None
    motivo = None

    if modo_atual == _ESCADA_MODO_FIREWALL[-1]:
        recentes = amostras[:_JANELA_FREIO_EMERGENCIA]
        if any(a["revertido_rapido"] or a["foi_falso_positivo"] for a in recentes):
            novo_modo = _ESCADA_MODO_FIREWALL[indice_atual - 1]
            motivo = "freio_emergencia"

    if novo_modo is None and total >= _MINIMO_PARA_REBAIXAR and taxa_problema > _TAXA_PROBLEMA_PARA_REBAIXAR and indice_atual > 0:
        novo_modo = _ESCADA_MODO_FIREWALL[indice_atual - 1]
        motivo = "taxa_de_problema_alta"
    elif (novo_modo is None and total >= _MINIMO_PARA_PROMOVER and taxa_problema <= _TAXA_PROBLEMA_PARA_PROMOVER
          and indice_atual < len(_ESCADA_MODO_FIREWALL) - 1):
        novo_modo = _ESCADA_MODO_FIREWALL[indice_atual + 1]
        motivo = "taxa_de_problema_baixa"

    if novo_modo is None or novo_modo == modo_atual:
        return None

    await EmpresaRepositorio(sessao).definir_modo_firewall(empresa_id, novo_modo)
    await servico_auditoria.registrar_evento(
        sessao, empresa_id, "firewall.modo_ajustado_automaticamente",
        {
            "modo_anterior": modo_atual, "modo_novo": novo_modo, "motivo": motivo,
            "amostras": total, "problemas": problemas, "taxa_problema": round(taxa_problema, 3),
        },
        ator_usuario_id=None,
    )
    return {"modo_anterior": modo_atual, "modo_novo": novo_modo, "motivo": motivo}


async def auto_classificar_incidentes_abertos(sessao, empresa_id, agora=None):
    """
    Fecha incidentes esquecidos: nenhum humano tocou (`em_andamento_por_usuario_id
    IS NULL`) e o incidente está parado (sem atualização) há mais de
    `_HORAS_INCIDENTE_PARADO`. Critério deliberadamente conservador --
    incidentes HIGH/CRITICAL sem contenção ativa NUNCA são
    auto-classificados, ficam para um humano decidir:

      - se ainda há um bloqueio ATIVO ligado ao incidente -> RESOLVIDO
        (contido).
      - senão, se a severidade for LOW/MEDIUM -> FALSO_POSITIVO (sem
        contenção e de baixo risco, mais provável ruído do que ataque real
        ainda em curso).
      - senão (HIGH/CRITICAL sem contenção) -> não mexe.

    Correção de bug encontrado em revisão crítica (2026-09): a regra
    "sem contenção + LOW/MEDIUM -> FALSO_POSITIVO" acima foi desenhada
    pensando só em incidentes de origem 'rede', onde "contenção" (bloqueio
    de firewall) é sempre uma possibilidade real -- se não há bloqueio
    ativo depois de 72h, é razoável supor que ninguém considerou o
    incidente grave o suficiente para agir. Mas incidentes de origem
    'endpoint' (Sentinela Endpoint, ver services/agentes.py) NUNCA podem
    ter `contido = true` nesta fase: o agente só OBSERVA, nunca aciona
    firewall. Ou seja, para um incidente de endpoint, "sem contenção" não
    sinaliza nada sobre a gravidade real -- é sempre verdade,
    estruturalmente, para TODO incidente de endpoint, grave ou não. Sem
    esta distinção, um heartbeat suspeito (mesmo com severidade MEDIUM,
    que já podia decorrer de um único processo malicioso conhecido -- ver
    `_INDICADORES_CRITICOS` em services/agentes.py) era descartado como
    falso positivo automaticamente após 72h sem revisão humana, mesmo
    sendo uma detecção real. A correção: incidentes de origem 'endpoint'
    NUNCA são elegíveis para FALSO_POSITIVO automático -- só para
    RESOLVIDO (caso a lógica de contenção mude no futuro) ou ficam para um
    humano, do mesmo jeito que HIGH/CRITICAL sem contenção já ficava.

    Só age se `empresas.auto_triagem_incidentes = true`. `sessao`: mesmo
    contrato de `avaliar_e_ajustar_modo_firewall` (BYPASSRLS, filtra
    empresa_id manualmente).
    """
    agora = agora or datetime.now(timezone.utc)
    if not await EmpresaRepositorio(sessao).auto_triagem_ligada(empresa_id):
        return []

    limite = agora - timedelta(hours=_HORAS_INCIDENTE_PARADO)
    repo = IncidenteRepositorio(sessao)
    candidatos = await repo.candidatos_a_triagem(empresa_id, limite)
    resultados = []
    for c in candidatos:
        if c["contido"]:
            novo_status = "RESOLVIDO"
            nota = "contido por bloqueio de firewall ativo"
        elif c["origem"] == "endpoint":
            continue  # endpoint nunca tem contenção real nesta fase -- fica para um humano, nunca vira falso positivo sozinho
        elif c["severidade"] in ("LOW", "MEDIUM"):
            novo_status = "FALSO_POSITIVO"
            nota = f"sem contenção ativa e severidade {c['severidade']}"
        else:
            continue  # HIGH/CRITICAL sem contenção -- fica para um humano

        nota_completa = f"[triagem automática] parado há mais de {_HORAS_INCIDENTE_PARADO}h sem ação humana, {nota}."
        nova_observacoes = f"{c['observacoes']}\n{nota_completa}" if c["observacoes"] else nota_completa

        await repo.resolver_pelo_sistema(c["id"], novo_status, nova_observacoes)
        await servico_auditoria.registrar_evento(
            sessao, empresa_id, "incidente.triagem_automatica",
            {"incident_id": c["incident_id"], "status_novo": novo_status, "contido": c["contido"], "severidade": c["severidade"]},
            ator_usuario_id=None,
        )
        resultados.append({"incident_id": c["incident_id"], "status_novo": novo_status})

    return resultados


async def obter_contagem_falsos_positivos(sessao, empresa_id, ip: str) -> int:
    """Quantos incidentes DE REDE deste IP, NESTE tenant, já foram marcados
    FALSO_POSITIVO (por humano ou pela auto-triagem acima). Ver
    core/risk_engine.aplicar_amortecimento_falso_positivo -- usado para
    amortecer o score de NOVOS ataques de rede vindos do mesmo IP.

    Correção de bug encontrado em revisão crítica (2026-09): antes desta
    filtragem por `origem = 'rede'`, um incidente de ORIGEM ENDPOINT
    (Sentinela Endpoint, ver services/agentes.py) marcado FALSO_POSITIVO
    também contava aqui, mesmo sendo uma classificação sobre um PROCESSO
    suspeito numa máquina, nada a ver com o comportamento de rede daquele
    IP. Como `registrar_heartbeat` grava o incidente de endpoint usando
    `ip_local` (valor que vem do CORPO da requisição do agente, plano
    futuro é agentes reportarem o IP real da máquina), dois heartbeats
    descartados como ruído (algo rotineiro numa triagem) já bastavam para
    amortecer -40 pontos de qualquer ataque de REDE futuro vindo daquele
    mesmo IP -- o suficiente para um SQLi/Command Injection real (HIGH,
    score 72) cair para MEDIUM (48) e nunca virar incidente, já que
    `services/resposta_incidentes.py` só abre incidente/aciona firewall
    para HIGH/CRITICAL. Ou seja: descartar ruído de ENDPOINT baixava
    silenciosamente a guarda contra ataques de REDE do mesmo IP -- os dois
    sinais nunca deveriam ter se misturado.
    """
    return await IncidenteRepositorio(sessao).contar_falsos_positivos_de_rede(empresa_id, ip)


def _linha_ip_protegido_para_dict(ip_protegido):
    d = ip_protegido.para_dict()  # `ip` (inet) já vem como str
    d["id"] = str(d["id"])
    d["empresa_id"] = str(d["empresa_id"])
    return d


async def listar_ips_protegidos(sessao, empresa_id):
    return [_linha_ip_protegido_para_dict(r) for r in await IpProtegidoRepositorio(sessao).listar(empresa_id)]


async def adicionar_ip_protegido(sessao, empresa_id, ip: str, motivo: str = "", origem: str = "manual",
                                   criado_por_usuario_id=None):
    """origem: 'manual' (um admin protegeu explicitamente, via API/dashboard)
    ou 'automatico' (ver services/firewall.py -- reversão rápida de um
    bloqueio automático -- e auto_classificar_incidentes_abertos acima --
    FALSO_POSITIVO ligado a um bloqueio automático).

    Proteger de novo um IP já protegido só atualiza o motivo (não duplica
    linha nem dá erro) -- via DELETE+INSERT dentro de um SAVEPOINT (é o que
    `sessao.begin_nested()` vira automaticamente quando chamado dentro de uma
    transação já aberta, mesmo padrão de services/resposta_incidentes.py),
    não `ON CONFLICT DO UPDATE`: essa seria a forma mais direta, mas
    exigiria GRANT UPDATE em `ips_protegidos` para app_tenant -- privilégio
    que esta tabela deliberadamente não concede (ver
    migrations/0014_...sql: uma entrada é criada ou removida, nunca
    "editada", preservando o rastro de cada evento em vez de
    sobrescrevê-lo)."""
    async with sessao.begin_nested():
        row = await IpProtegidoRepositorio(sessao).substituir(empresa_id, ip, motivo, origem, criado_por_usuario_id)
    await servico_auditoria.registrar_evento(
        sessao, empresa_id, "firewall.ip_protegido_adicionado", {"ip": ip, "motivo": motivo, "origem": origem},
        ator_usuario_id=criado_por_usuario_id,
    )
    return _linha_ip_protegido_para_dict(row)


async def remover_ip_protegido(sessao, empresa_id, ip: str, usuario_id=None) -> bool:
    removido = await IpProtegidoRepositorio(sessao).remover(empresa_id, ip)
    if removido:
        await servico_auditoria.registrar_evento(
            sessao, empresa_id, "firewall.ip_protegido_removido", {"ip": ip}, ator_usuario_id=usuario_id,
        )
    return removido
async def listar_ips_protegidos_para_whitelist(sessao, empresa_id):
    """Só os endereços (list[str]), no formato que
    core.firewall.ip_e_protegido espera em `whitelist` -- ver
    services/firewall.py:registrar_bloqueio."""
    return await IpProtegidoRepositorio(sessao).listar_enderecos(empresa_id)


async def executar_ciclo_autonomo(db):
    """
    Iteração cross-tenant com BYPASSRLS (mesmo padrão de
    services/firewall.py:sincronizar_bloqueios_expirados), uma
    conexão/transação POR EMPRESA -- uma falha numa empresa não derruba o
    ciclo das outras. Só considera empresas ativas com pelo menos uma das
    duas flags de autonomia ligada.
    """
    async with db.superadmin_session() as sessao:
        empresas_elegiveis = await EmpresaRepositorio(sessao).listar_ids_com_autonomia()

    resultado = {"empresas_processadas": 0, "ajustes_modo": [], "triagens": [], "erros": []}
    for empresa_id in empresas_elegiveis:
        try:
            async with db.superadmin_session() as sessao:
                ajuste = await avaliar_e_ajustar_modo_firewall(sessao, empresa_id)
                if ajuste:
                    resultado["ajustes_modo"].append({"empresa_id": str(empresa_id), **ajuste})
                triagens = await auto_classificar_incidentes_abertos(sessao, empresa_id)
                if triagens:
                    resultado["triagens"].extend({"empresa_id": str(empresa_id), **t} for t in triagens)
            resultado["empresas_processadas"] += 1
        except Exception as exc:  # noqa: BLE001 -- isolar falha por empresa, mesmo padrão de resposta_incidentes.py
            logger.exception("ciclo autônomo falhou para empresa %s", empresa_id)
            resultado["erros"].append({"empresa_id": str(empresa_id), "erro": str(exc)})

    return resultado


async def rodar_ciclo_autonomo_periodicamente(db, intervalo_segundos: int = 900):
    """
    Loop em background iniciado no lifespan (ver main.py) -- roda
    `executar_ciclo_autonomo` a cada `intervalo_segundos` (default 15min)
    até ser cancelado no shutdown. Sem isto, a auto-triagem e o autoajuste
    de modo_firewall só reavaliariam quando um upload de log HTTP
    disparasse `responder_a_incidentes` -- ou seja, continuariam
    dependendo de uma ação humana para "destravar" a automação, o oposto
    do objetivo.
    """
    while True:
        try:
            await asyncio.sleep(intervalo_segundos)
            await executar_ciclo_autonomo(db)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 -- um ciclo com erro não deve matar o loop inteiro
            logger.exception("ciclo autônomo periódico falhou")
