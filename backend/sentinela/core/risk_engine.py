# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Motor de risco do Sentinela SOC 2.0.

Além do score original, considera diversidade, inteligência externa,
frequência, reincidência e concentração temporal dos eventos.
"""
SEVERIDADE_PESO = {
    "SQL Injection (SQLi)": 25,
    "Command Injection": 30,
    "Path Traversal": 20,
    "Cross-Site Scripting (XSS)": 15,
    "Scanner de Vulnerabilidades": 10,
    "Scanner de Vulnerabilidades (User-Agent)": 10,
    # Portado de sentinela_soc_saas_2_3/risk_engine.py (GAP_REPORT_V3.1.md,
    # Fase 18) junto com as assinaturas/detectores correspondentes em
    # analisador_logs.py e o mapeamento MITRE em mitre.py.
    "Server-Side Request Forgery (SSRF)": 25,
    "XML External Entity (XXE)": 25,
    "Server-Side Template Injection (SSTI)": 25,
    "LDAP Injection": 20,
    "NoSQL Injection": 20,
    "Log4Shell / JNDI Injection": 35,
    "Deserialização Insegura": 30,
    "CRLF Injection / HTTP Response Splitting": 12,
    "Open Redirect": 8,
    "Força Bruta em Login (Brute Force)": 18,
    "Possível DDoS / Flood de Requisições": 15,
}


def calcular_risco(total_ataques, tipos_ataque, reputacao=None, *, reincidente=False,
                   eventos_ultimos_minutos=0, taxa_ataques_por_minuto=0.0,
                   correlacao_score=0):
    base = min(total_ataques * 4, 35)
    diversidade = min(len(set(tipos_ataque)) * 6, 18)
    severidade = min(sum(SEVERIDADE_PESO.get(t, 8) for t in set(tipos_ataque)) / 2, 25)
    intel = 0
    if reputacao:
        abuse = reputacao.get("abuseipdb", {}) if isinstance(reputacao, dict) else {}
        score = abuse.get("score_abuso", abuse.get("abuseConfidenceScore", abuse.get("score", 0))) if isinstance(abuse, dict) else 0
        intel += min(float(score or 0) * 0.15, 15)
        vt = reputacao.get("virustotal", {}) if isinstance(reputacao, dict) else {}
        if isinstance(vt, dict):
            malicious = vt.get("maliciosos", vt.get("malicious", vt.get("malicious_count", 0))) or 0
            intel += min(float(malicious) * 2, 12)

    comportamento = 0
    correlacao = min(max(float(correlacao_score or 0) * 0.20, 0), 20)
    if reincidente:
        comportamento += 10
    if eventos_ultimos_minutos >= 10:
        comportamento += 8
    if taxa_ataques_por_minuto >= 5:
        comportamento += 10
    elif taxa_ataques_por_minuto >= 2:
        comportamento += 5

    score = min(100, round(base + diversidade + severidade + intel + comportamento + correlacao))
    if score >= 80:
        nivel = "CRITICAL"
    elif score >= 60:
        nivel = "HIGH"
    elif score >= 35:
        nivel = "MEDIUM"
    else:
        nivel = "LOW"
    return {
        "score": score,
        "severity": nivel,
        "fatores": {
            "volume": base,
            "diversidade": diversidade,
            "severidade": round(severidade, 1),
            "threat_intelligence": round(intel, 1),
            "comportamento": comportamento,
            "correlacao": round(correlacao, 1),
        },
    }


_PONTOS_POR_FALSO_POSITIVO = 12
_TETO_AMORTECIMENTO = 40
_MINIMO_FALSOS_POSITIVOS_PARA_AMORTECER = 2


def aplicar_amortecimento_falso_positivo(risco: dict, quantidade_falsos_positivos: int) -> dict:
    """
    Filtro de falso positivo mais esperto (capacidade 3 do modo autônomo --
    ver services/automacao.py:obter_contagem_falsos_positivos): um IP com
    histórico de já ter sido marcado FALSO_POSITIVO NESTE tenant pesa menos
    da próxima vez, em vez do sistema repetir o mesmo erro contra o mesmo
    IP indefinidamente.

    Sempre-ativo, sem opt-in -- ao contrário das outras três capacidades,
    isto só torna o sistema mais conservador (nunca mais agressivo), então
    não carrega o mesmo risco de bloqueio indevido que justificaria deixar
    como opt-in.

    Abaixo de `_MINIMO_FALSOS_POSITIVOS_PARA_AMORTECER` ocorrências, não
    amortece nada -- um único falso positivo passado não deveria proteger
    um IP daqui pra sempre (podia ter sido genuinamente um erro de
    triagem). `_TETO_AMORTECIMENTO` limita o quanto o histórico pode puxar
    o score pra baixo -- muitos falsos positivos tornam um bloqueio bem mais
    difícil, mas nunca impossível: um IP com histórico ruim que volta a
    atacar com evidência muito forte (score alto o bastante mesmo após o
    teto) ainda pode virar incidente CRITICAL.

    Retorna um NOVO dict (não modifica `risco` in-place) com "score"/
    "severity" recalculados e "fatores.amortecimento_falso_positivo"
    registrando o quanto foi descontado, para transparência de quem for
    investigar por que um IP com muitos ataques não virou incidente.
    """
    if quantidade_falsos_positivos < _MINIMO_FALSOS_POSITIVOS_PARA_AMORTECER:
        return risco

    desconto = min(quantidade_falsos_positivos * _PONTOS_POR_FALSO_POSITIVO, _TETO_AMORTECIMENTO)
    novo_score = max(0, risco["score"] - desconto)

    if novo_score >= 80:
        nivel = "CRITICAL"
    elif novo_score >= 60:
        nivel = "HIGH"
    elif novo_score >= 35:
        nivel = "MEDIUM"
    else:
        nivel = "LOW"

    return {
        "score": novo_score,
        "severity": nivel,
        "fatores": {**risco["fatores"], "amortecimento_falso_positivo": -desconto},
    }
