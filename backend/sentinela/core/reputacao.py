# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Módulo de consulta de reputação de IPs (AbuseIPDB + VirusTotal).

Configuração (variáveis de ambiente):
    ABUSEIPDB_API_KEY  -> chave da API do AbuseIPDB (https://www.abuseipdb.com/account/api)
    VT_API_KEY         -> chave da API do VirusTotal (https://www.virustotal.com/gui/my-apikey)

As duas consultas são independentes: se uma chave não estiver configurada, essa
fonte simplesmente retorna um erro e a outra continua funcionando normalmente.

Nota da rearquitetura multi-tenant: o cache em memória (`_cache`) e o
throttle do VirusTotal (`_ultima_consulta_vt`) abaixo continuam
process-global — propositalmente NÃO viraram por-empresa, porque a
reputação de um IP não é um atributo da empresa que perguntou (ver
`services.reputacao`, que também cacheia em Postgres na tabela
`reputacao_cache` -- essa sim tenant-scoped com RLS desde
migrations/0007_reputacao_cache_tenant.sql, ao contrário do que um
comentário antigo deste arquivo dizia; o cache em memória aqui embaixo é só
a otimização "não repetir dentro da mesma execução", sem relação com o
cache em Postgres). O throttle do VT, no entanto, é uma limitação
conhecida em múltiplos workers — ver README, seção Limitações.
"""
import time
from collections import OrderedDict

import requests

from sentinela.core.segredos import obter_segredo
from sentinela.util import ip_valido

# Cache simples em memória para não repetir consultas ao mesmo IP na mesma
# execução. OrderedDict com teto de tamanho (em vez de dict comum): sem
# TTL nem limite, esse cache cresceria sem parar num processo de longa
# duração que consultasse muitos IPs distintos ao longo do tempo (o cache
# "de verdade", com TTL, é o Postgres via services.reputacao -- este aqui é
# só a otimização "não repetir dentro da mesma execução").
_CACHE_MAX_ENTRADAS = 5_000
_cache: "OrderedDict[str, dict]" = OrderedDict()
_ultima_consulta_vt = 0.0

# VirusTotal free tier: ~4 requisições/minuto -> respeitamos um intervalo mínimo
_VT_INTERVALO_MINIMO_SEGUNDOS = 15.0


def _guardar_no_cache(ip, resultado):
    _cache[ip] = resultado
    _cache.move_to_end(ip)
    while len(_cache) > _CACHE_MAX_ENTRADAS:
        _cache.popitem(last=False)


def consultar_abuseipdb(ip, api_key=None, timeout=10):
    """Consulta o score de abuso de um IP no AbuseIPDB."""
    api_key = api_key or obter_segredo("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"erro": "ABUSEIPDB_API_KEY não configurada"}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=timeout,
        )
        resp.raise_for_status()
        dados = resp.json().get("data", {})
        return {
            "score_abuso": dados.get("abuseConfidenceScore"),
            "total_denuncias": dados.get("totalReports"),
            "pais": dados.get("countryCode"),
            "isp": dados.get("isp"),
            "uso": dados.get("usageType"),
            "dominio": dados.get("domain"),
        }
    except requests.RequestException as e:
        return {"erro": str(e)}


def consultar_virustotal(ip, api_key=None, timeout=10):
    """Consulta as estatísticas de detecção de um IP no VirusTotal."""
    global _ultima_consulta_vt
    api_key = api_key or obter_segredo("VT_API_KEY")
    if not api_key:
        return {"erro": "VT_API_KEY não configurada"}

    espera = _VT_INTERVALO_MINIMO_SEGUNDOS - (time.time() - _ultima_consulta_vt)
    if espera > 0:
        time.sleep(espera)

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key},
            timeout=timeout,
        )
        _ultima_consulta_vt = time.time()
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "maliciosos": stats.get("malicious"),
            "suspeitos": stats.get("suspicious"),
            "inofensivos": stats.get("harmless"),
            "reputacao": attrs.get("reputation"),
            "pais": attrs.get("country"),
            "proprietario": attrs.get("as_owner"),
        }
    except requests.RequestException as e:
        return {"erro": str(e)}


def consultar_reputacao_ip(ip, usar_cache=True, abuseipdb_key=None, vt_key=None):
    """
    Consulta a reputação de um IP nas duas fontes (AbuseIPDB + VirusTotal) e
    devolve uma classificação de risco combinada.

    Valida `ip` ANTES de qualquer chamada de rede: os chamadores (API,
    pipeline de análise de log) já validam na borda, mas essa checagem
    aqui também é defesa em profundidade -- sem ela, uma string qualquer
    era interpolada sem escaping na URL do VirusTotal
    (`consultar_virustotal`) e podia derrubar a gravação em Postgres mais
    adiante (coluna `inet`, que rejeita valor não-IP com exceção crua).
    Usa `ip_valido` (não só `ipaddress.ip_address`) para também rejeitar a
    notação de zone-id do IPv6, que o Postgres `inet` não entende -- ver
    `sentinela.util.ip_valido`.
    """
    if ip_valido(ip) is None:
        return {"ip": ip, "erro": "IP inválido", "classificacao": "BAIXO RISCO / DESCONHECIDO"}

    if usar_cache and ip in _cache:
        _cache.move_to_end(ip)
        return _cache[ip]

    resultado = {
        "ip": ip,
        "abuseipdb": consultar_abuseipdb(ip, abuseipdb_key),
        "virustotal": consultar_virustotal(ip, vt_key),
    }

    score_abuso = resultado["abuseipdb"].get("score_abuso") or 0
    maliciosos_vt = resultado["virustotal"].get("maliciosos") or 0

    if score_abuso >= 75 or maliciosos_vt >= 5:
        classificacao = "ALTO RISCO"
    elif score_abuso >= 25 or maliciosos_vt >= 1:
        classificacao = "RISCO MODERADO"
    else:
        classificacao = "BAIXO RISCO / DESCONHECIDO"

    resultado["classificacao"] = classificacao

    if usar_cache:
        _guardar_no_cache(ip, resultado)
    return resultado
