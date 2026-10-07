# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Correlação comportamental determinística de eventos de segurança.

Não depende de I/O. Trabalha com uma janela temporal real (timestamps Apache)
eproduzindo evidências de cadeia, velocidade, diversidade e escalada.
"""
from collections import Counter, defaultdict
from datetime import datetime, timezone

HIGH_SIGNAL = {"SQL Injection (SQLi)", "Command Injection", "Path Traversal"}
SCANNER = {"Scanner de Vulnerabilidades", "Scanner de Vulnerabilidades (User-Agent)"}

# Correção de bug encontrado em revisão crítica (2026-09, achado 3):
# `_parse_data` tinha DOIS caminhos de sucesso -- um com "%z" (retorna
# datetime AWARE, quando o log tem offset, ex.: "-0300") e outro sem "%z"
# (retorna datetime NAIVE, usado como fallback pra formatos sem offset ou
# truncados). Para o MESMO IP, se um evento caísse no primeiro caminho e
# outro no segundo (ou caísse no fallback `datetime.min`, também naive, na
# linha de sort abaixo), a comparação entre um aware e um naive -- no sort,
# na subtração de tempos, no Counter de minutos -- lançava
# `TypeError: can't compare offset-naive and offset-aware datetimes` sem
# nenhum catch. Pior: essa chamada (`correlacionar_por_ip`, em
# services/resposta_incidentes.py) roda ANTES do loop por-candidato que
# isola falhas com try/except -- então UM timestamp malformado de UM IP
# derrubava a criação de incidente do LOTE INTEIRO, inclusive de outros
# IPs com ataques reais e óbvios no mesmo upload.
#
# A correção normaliza todo datetime parseado para AWARE em UTC -- um
# datetime aware com offset é convertido para UTC (`astimezone`); um
# datetime naive (sem offset no log original) é tratado como já estando em
# UTC (`replace(tzinfo=...)`, não converte o valor, só anota o fuso) --
# nunca mistura os dois tipos entre si, então toda comparação/subtração
# depois disto é sempre aware-com-aware.
_DATA_MINIMA = datetime.min.replace(tzinfo=timezone.utc)


def _parse_data(valor):
    if not valor:
        return None
    try:
        partes = str(valor).split(" ", 1)
        bruto = partes[0] + (" " + partes[1] if len(partes) > 1 else "")
        return datetime.strptime(bruto, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
    except Exception:
        try:
            return datetime.strptime(str(valor)[:20], "%d/%b/%Y:%H:%M:%S").replace(tzinfo=timezone.utc)
        except Exception:
            return None


def correlacionar_por_ip(relatorio: dict, janela_segundos: int = 300) -> dict:
    eventos = relatorio.get("detalhes_alertas", [])
    por_ip = defaultdict(list)
    for evento in eventos:
        if evento.get("ip"):
            por_ip[evento["ip"]].append(evento)

    resultado = {}
    for ip, itens in por_ip.items():
        itens = sorted(itens, key=lambda e: _parse_data(e.get("data")) or _DATA_MINIMA)
        tipos = {e.get("tipo_ataque") for e in itens if e.get("tipo_ataque")}
        tempos = [_parse_data(e.get("data")) for e in itens]
        tempos = [t for t in tempos if t]
        pico = max(Counter(t.replace(second=0, microsecond=0) for t in tempos).values(), default=0)
        max_eventos_janela = 1
        for i, inicio in enumerate(tempos):
            n = sum(1 for fim in tempos[i:] if (fim - inicio).total_seconds() <= janela_segundos)
            max_eventos_janela = max(max_eventos_janela, n)

        sinais, score = [], 0
        sequencia = list(dict.fromkeys(e.get("tipo_ataque") for e in itens if e.get("tipo_ataque")))
        tem_scanner = bool(tipos & SCANNER)
        tem_exploracao = bool(tipos & HIGH_SIGNAL)

        if len(tipos) >= 3:
            score += 25; sinais.append("diversidade_de_ataques")
        if tem_scanner and tem_exploracao:
            score += 25; sinais.append("reconhecimento_e_exploracao")
        if pico >= 3:
            score += 15; sinais.append("rajada_temporal")
        if max_eventos_janela >= 5:
            score += 15; sinais.append("alta_concentracao_na_janela")
        if len(itens) >= 5:
            score += 10; sinais.append("reincidencia_no_periodo")
        if len(itens) >= 10:
            score += 10; sinais.append("volume_elevado")

        cadeia = []
        if tem_scanner:
            cadeia.append("reconhecimento")
        if "Path Traversal" in tipos:
            cadeia.append("acesso_a_arquivo")
        if "SQL Injection (SQLi)" in tipos:
            cadeia.append("exploracao_banco")
        if "Command Injection" in tipos:
            cadeia.append("execucao_comando")
        if "Cross-Site Scripting (XSS)" in tipos:
            cadeia.append("injecao_cliente")

        nivel = "CRITICAL" if score >= 70 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
        resultado[ip] = {
            "score": min(score, 100), "severity": nivel,
            "total_eventos": len(itens), "tipos": sorted(tipos),
            "pico_por_minuto": pico, "max_eventos_janela": max_eventos_janela,
            "janela_segundos": janela_segundos, "cadeia": cadeia,
            "sequencia": sequencia, "sinais": sinais,
            "correlacionado": score >= 50,
        }
    return resultado
