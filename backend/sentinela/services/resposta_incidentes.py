# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Orquestração assíncrona de resposta a incidentes — equivalente
tenant-aware do antigo `analisador_logs.responder_a_incidentes()` (que
chamava reputacao.py/firewall.py/incidents.py diretamente e de forma
síncrona). É AQUI que a lacuna do upload do dashboard é consertada: tanto
a API (`POST /api/v1/logs/analisar`) quanto o HTMX (`POST /logs/upload`)
chamam esta mesma função, então um log enviado por qualquer um dos dois
frontends passa a criar incidentes de verdade, escopados por empresa —
antes, só o CLI fazia isso.
"""
from sentinela.core.analisador_logs import candidatos_por_limite, perfil_comportamental_por_ip
from sentinela.core.mitre import obter_mitre
from sentinela.core.correlacao import correlacionar_por_ip
from sentinela.core.risk_engine import aplicar_amortecimento_falso_positivo, calcular_risco
from sentinela.repositories.empresas import EmpresaRepositorio
from sentinela.services import automacao as servico_automacao
from sentinela.services import firewall as servico_firewall
from sentinela.services import incidentes as servico_incidentes
from sentinela.services import reputacao as servico_reputacao


MODOS_FIREWALL_VALIDOS = {"observacao", "dry_run", "manual", "automacao_controlada", "automacao_total"}
_TETO_HORAS_AUTOMACAO_CONTROLADA = 24


async def responder_a_incidentes(
    sessao,
    empresa_id,
    relatorio: dict,
    limite_ataques: int = 5,
    verificar_reputacao: bool = True,
    bloquear: bool = False,
    whitelist=None,
    dry_run: bool = False,
    duracao_horas=24,
    modo_resposta: str = "manual",
    origem: str = "api",
    usuario_id=None,
    permitir_escalonamento_por_correlacao: bool = False,
    automacao_habilitada: bool = True,
):
    """
    Para cada IP que ultrapassar `limite_ataques` no relatório (ver
    `candidatos_por_limite`, função pura), opcionalmente:
      1. consulta a reputação do IP (cache em Postgres + AbuseIPDB/VirusTotal)
      2. cria um incidente (HIGH/CRITICAL) escopado a `empresa_id`
      3. bloqueia o IP via iptables (host-wide -- ver services.firewall)

    Retorna a lista de resultados por IP, no mesmo formato do
    responder_a_incidentes() legado (chaves: ip, total_ataques,
    tipos_ataque, reputacao?, risk, mitre, incident_id?, bloqueio?).

    `permitir_escalonamento_por_correlacao` (default False): quando True,
    um IP abaixo de `limite_ataques` ainda pode virar candidato (incidente
    e, se `bloquear=True`, bloqueio) caso o motor de correlação encontre
    uma cadeia comportamental forte (`correlacionado=True`, ver
    core/correlacao.py). Com a flag desligada (padrão), `limite_ataques`
    continua sendo um piso garantido: um chamador que pedir
    `limite_ataques=5` não vê um IP com só 1-2 eventos ser bloqueado por
    trás das cortinas. Quem quiser a escalada comportamental (mais
    sensível, mais falsos positivos, em troca de detectar ataques "de
    baixo e devagar") liga explicitamente.

    `automacao_habilitada` (item 8 do plano de endurecimento pós-auditoria,
    kill-switch GLOBAL -- ver `Settings.firewall_automacao_habilitada` em
    config.py): quando False, NENHUM bloqueio automático acontece nesta
    chamada, em NENHUM tenant, não importa o que `bloquear`/`modo_resposta`
    peçam -- vira dry-run. Combinado com `empresas.modo_firewall` (por
    tenant, lido abaixo), essas duas checagens são aplicadas por ÚLTIMO,
    depois de toda a lógica de `modo_resposta`/`bloquear` já decidida --
    nenhum parâmetro vindo da requisição HTTP consegue contorná-las.
    """
    candidatos = candidatos_por_limite(relatorio, limite_ataques)
    perfis = perfil_comportamental_por_ip(relatorio)
    # Defesa em profundidade (revisão crítica 2026-09, achado 3): esta
    # chamada roda ANTES do loop por-candidato abaixo, que isola falhas de
    # UM candidato com try/except -- uma exceção aqui (ex.: um bug futuro em
    # core/correlacao.py, ou um formato de timestamp ainda não coberto)
    # derrubaria a criação de incidente do LOTE INTEIRO, para todos os IPs,
    # não só o problemático. correlacionar_por_ip já foi corrigida para não
    # lançar mais no caso conhecido (timestamps aware/naive misturados por
    # IP -- ver o comentário em core/correlacao.py), mas correlação é só um
    # sinal de ESCALONAMENTO opcional (ver `permitir_escalonamento_por_correlacao`
    # abaixo) -- degradar para "sem correlação" e seguir processando os
    # candidatos normais é estritamente melhor do que perder o lote inteiro.
    try:
        correlacoes = correlacionar_por_ip(relatorio)
    except Exception:
        correlacoes = {}

    config_firewall = await EmpresaRepositorio(sessao).obter_config_firewall(empresa_id)
    modo_firewall = config_firewall.modo_firewall if config_firewall else None
    if modo_firewall not in MODOS_FIREWALL_VALIDOS:
        modo_firewall = "automacao_controlada"  # linha não encontrada, ou valor inesperado -- cai no padrão mais conservador-razoável

    # "observacao"/"manual" são escolhas do TENANT de nunca sequer simular
    # um bloqueio automático (a diferença entre os dois é só semântica --
    # nenhum efeito de código diferente hoje). O kill-switch GLOBAL
    # (`automacao_habilitada=False`) é tratado separadamente, abaixo, como
    # downgrade para dry-run, não como supressão total -- um botão de
    # emergência temporário deveria continuar mostrando "o que TERIA
    # acontecido" (visibilidade operacional), não apagar o rastro.
    bloqueio_automatico_desligado_pelo_tenant = modo_firewall in ("observacao", "manual")
    dry_run_efetivo = dry_run or not automacao_habilitada or modo_firewall == "dry_run"
    duracao_horas_efetiva = duracao_horas
    if modo_firewall == "automacao_controlada" and duracao_horas_efetiva:
        # "controlada" nunca é permanente, e nunca dura mais que o teto --
        # não importa o que o chamador (upload de log) pediu.
        duracao_horas_efetiva = min(duracao_horas_efetiva, _TETO_HORAS_AUTOMACAO_CONTROLADA)

    if permitir_escalonamento_por_correlacao:
        # Correlação permite elevar um IP abaixo do limite quando há uma
        # cadeia comportamental forte (ex.: scanner -> traversal -> SQLi).
        existentes = {c["ip"] for c in candidatos}
        for ip, corr in correlacoes.items():
            if corr["correlacionado"] and ip not in existentes:
                candidatos.append({
                    "ip": ip,
                    "total_ataques": corr["total_eventos"],
                    "tipos_ataque": corr["tipos"],
                })

    # Resposta inteligente: só o motor pode promover um evento para contenção.
    # "manual" preserva o comportamento legado; "inteligente" bloqueia apenas
    # quando a evidência comportamental é CRITICAL.
    if modo_resposta not in ("manual", "inteligente", "observacao"):
        raise ValueError("modo_resposta inválido")

    respostas = []
    for candidato in candidatos:
        entrada = dict(candidato)

        # Defesa em profundidade: um `ip` malformado já é descartado bem
        # antes de virar candidato (analisador_logs.analisar_linha_log
        # valida com util.ip_valido), mas isolar cada candidato em seu
        # próprio SAVEPOINT garante que UM item problemático -- reputação
        # indisponível, erro inesperado do banco, um bug futuro -- não
        # aborte o processamento de TODOS os outros candidatos do mesmo
        # lote. Sem isso, uma exceção em qualquer iteração propagava e
        # cancelava a resposta a incidentes inteira, inclusive para IPs de
        # ataque real já processados antes dele (a lista é ordenada por
        # mais ativo primeiro -- o pior lugar possível pra um item
        # problemático travar o lote). `conn.transaction()`, chamado dentro
        # de uma transação já aberta (ver db/pool.tenant_scoped_connection),
        # vira automaticamente um SAVEPOINT no asyncpg -- uma falha aqui dá
        # ROLLBACK só até esse ponto, sem invalidar a transação externa
        # (que ficaria travada em "current transaction is aborted" para
        # todo o resto do lote se não fosse por isso).
        try:
            async with sessao.begin_nested():
                if verificar_reputacao:
                    entrada["reputacao"] = await servico_reputacao.consultar_reputacao_ip(sessao, empresa_id, candidato["ip"])

                entrada["correlacao"] = correlacoes.get(candidato["ip"], {"score": 0, "severity": "LOW", "sinais": []})
                entrada["risk"] = calcular_risco(
                    candidato["total_ataques"], candidato["tipos_ataque"], entrada.get("reputacao"),
                    reincidente=perfis.get(candidato["ip"], {}).get("reincidente", False),
                    eventos_ultimos_minutos=perfis.get(candidato["ip"], {}).get("total", 0),
                    taxa_ataques_por_minuto=perfis.get(candidato["ip"], {}).get("pico_por_minuto", 0),
                    correlacao_score=entrada["correlacao"].get("score", 0),
                )
                entrada["mitre"] = [obter_mitre(t) for t in candidato["tipos_ataque"]]

                # Capacidade 3 do modo autônomo (filtro de falso positivo
                # mais esperto, sempre-ativo -- ver
                # core/risk_engine.aplicar_amortecimento_falso_positivo):
                # um IP com histórico de FALSO_POSITIVO NESTE tenant pesa
                # menos antes de decidir criar um novo incidente/bloqueio.
                # Só torna o sistema mais conservador -- nunca eleva risco.
                qtd_falsos_positivos = await servico_automacao.obter_contagem_falsos_positivos(
                    sessao, empresa_id, candidato["ip"],
                )
                if qtd_falsos_positivos:
                    entrada["risk"] = aplicar_amortecimento_falso_positivo(entrada["risk"], qtd_falsos_positivos)

                incidente = None
                if entrada["risk"]["severity"] in ("HIGH", "CRITICAL"):
                    incidente = await servico_incidentes.criar_incidente(
                        sessao, empresa_id, candidato["ip"], entrada["risk"], candidato["tipos_ataque"]
                    )
                    entrada["incident_id"] = incidente["incident_id"] if incidente else None

                deve_bloquear = bloquear and (modo_resposta != "inteligente" or entrada["risk"]["severity"] == "CRITICAL")
                if modo_resposta == "observacao":
                    deve_bloquear = False
                # Modo de firewall por tenant (ver docstring da função) --
                # aplicado por último, depois de toda a decisão acima
                # baseada em modo_resposta/bloquear. O kill-switch GLOBAL
                # não entra aqui -- ele já foi incorporado em
                # `dry_run_efetivo` acima (downgrade para simulação, não
                # supressão).
                deve_bloquear = deve_bloquear and not bloqueio_automatico_desligado_pelo_tenant
                if deve_bloquear:
                    motivo = f"{candidato['total_ataques']} ataques detectados ({', '.join(candidato['tipos_ataque'])})"
                    entrada["bloqueio"] = await servico_firewall.registrar_bloqueio(
                        sessao, empresa_id, candidato["ip"], motivo,
                        whitelist=whitelist, dry_run=dry_run_efetivo, duracao_horas=duracao_horas_efetiva,
                        origem=origem, usuario_id=usuario_id, incidente_id=incidente["id"] if incidente else None,
                    )
        except Exception as exc:  # noqa: BLE001 -- ver comentário acima: isolar falha por candidato
            entrada["erro"] = f"falha ao processar este candidato: {exc}"

        respostas.append(entrada)

    return respostas
