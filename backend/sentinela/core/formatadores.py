# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Formatadores de exportação para SIEMs (Splunk, QRadar, Elastic, Graylog...).

Nenhuma função aqui abre conexão de rede nem grava em disco -- elas só
transformam um alerta (o mesmo formato de dict que analisar_linha_log ou
responder_a_incidentes já produzem) na representação de texto que um SIEM
sabe interpretar nativamente. O transporte real (enviar por Syslog
UDP/TCP/TLS, HTTP Event Collector etc.) fica para uma fase seguinte, quando
houver um piloto real com um SIEM de verdade para testar contra -- não faz
sentido implementar transporte sem ter o que atacar como alvo.
"""
import re
from datetime import datetime, timezone

DEVICE_VENDOR = "SentinelaDeLogs"
DEVICE_PRODUCT = "AnalisadorDeLogsApacheNginx"
DEVICE_VERSION = "1.0"

# Nome do assunto (APP-NAME) usado nas mensagens Syslog RFC 5424
SYSLOG_APP_NAME = "sentinela-de-logs"
SYSLOG_FACILITY_PADRAO = 16  # local0 -- convenção comum para aplicações próprias

# Severidade CEF vai de 0 (menor) a 10 (maior)
_SEVERIDADE_CEF_POR_CLASSIFICACAO = {
    "ALTO RISCO": 9,
    "RISCO MODERADO": 6,
    "BAIXO RISCO / DESCONHECIDO": 3,
}
_SEVERIDADE_CEF_PADRAO = 5

# Severidade Syslog vai de 0 (Emergency) a 7 (Debug) -- quanto menor, mais grave
_SEVERIDADE_SYSLOG_POR_CLASSIFICACAO = {
    "ALTO RISCO": 2,       # Critical
    "RISCO MODERADO": 4,   # Warning
    "BAIXO RISCO / DESCONHECIDO": 5,  # Notice
}
_SEVERIDADE_SYSLOG_PADRAO = 5

_SIGNATURE_ID_POR_TIPO_ATAQUE = {
    "SQL Injection (SQLi)": "100",
    "Cross-Site Scripting (XSS)": "101",
    "Path Traversal": "102",
    "Command Injection": "103",
    "Scanner de Vulnerabilidades": "104",
    "Scanner de Vulnerabilidades (User-Agent)": "104",
}
_SIGNATURE_ID_PADRAO = "000"


def _tipo_ataque_de(alerta):
    return (
        alerta.get("tipo_ataque")
        or ", ".join(alerta.get("tipos_ataque", []) or [])
        or "Atividade suspeita"
    )


def _extrair_metodo_http(requisicao):
    if not requisicao:
        return None
    partes = requisicao.split(" ", 1)
    return partes[0] or None


# --------------------------------------------------------------------------
# CEF (Common Event Format) -- Splunk, QRadar, ArcSight
# --------------------------------------------------------------------------

def _escapar_cabecalho_cef(valor):
    """No cabeçalho CEF, só '\\' e '|' precisam de escape."""
    texto = "" if valor is None else str(valor)
    return texto.replace("\\", "\\\\").replace("|", "\\|")


def _escapar_extensao_cef(valor):
    """Na extensão CEF (pares chave=valor), '\\', '=' e quebras de linha precisam de escape."""
    texto = "" if valor is None else str(valor)
    texto = texto.replace("\\", "\\\\").replace("=", "\\=")
    texto = texto.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\n")
    return texto


def formatar_cef(alerta, classificacao=None, timestamp_epoch_millis=None):
    """
    Formata um alerta no padrão CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension

    `alerta` aceita tanto o dict de analisar_linha_log (com "tipo_ataque",
    "ip", "requisicao", "status") quanto uma entrada de
    responder_a_incidentes (com "tipos_ataque", "ip", "total_ataques").
    `classificacao` é a classificação de reputação opcional ("ALTO RISCO"
    etc.), usada só para calibrar a severidade do evento.
    """
    tipo_ataque = _tipo_ataque_de(alerta)
    signature_id = _SIGNATURE_ID_POR_TIPO_ATAQUE.get(tipo_ataque, _SIGNATURE_ID_PADRAO)
    severidade = _SEVERIDADE_CEF_POR_CLASSIFICACAO.get(classificacao, _SEVERIDADE_CEF_PADRAO)

    cabecalho = "|".join([
        "CEF:0",
        _escapar_cabecalho_cef(DEVICE_VENDOR),
        _escapar_cabecalho_cef(DEVICE_PRODUCT),
        _escapar_cabecalho_cef(DEVICE_VERSION),
        _escapar_cabecalho_cef(signature_id),
        _escapar_cabecalho_cef(tipo_ataque),
        str(severidade),
    ])

    ts = timestamp_epoch_millis
    if ts is None:
        ts = int(datetime.now(timezone.utc).timestamp() * 1000)

    campos_extensao = [
        ("src", alerta.get("ip")),
        ("requestMethod", _extrair_metodo_http(alerta.get("requisicao"))),
        ("request", alerta.get("requisicao")),
        ("cat", tipo_ataque),
        ("cnt", alerta.get("total_ataques")),
        ("cs1Label", "httpStatus"),
        ("cs1", alerta.get("status")),
        ("rt", ts),
    ]

    extensao = " ".join(
        f"{chave}={_escapar_extensao_cef(valor)}"
        for chave, valor in campos_extensao
        if valor is not None
    )

    return f"{cabecalho}|{extensao}"


# --------------------------------------------------------------------------
# Syslog RFC 5424 -- Elastic, Graylog, rsyslog e praticamente todo SIEM
# --------------------------------------------------------------------------

def _pri_syslog(classificacao, facility=SYSLOG_FACILITY_PADRAO):
    severidade = _SEVERIDADE_SYSLOG_POR_CLASSIFICACAO.get(classificacao, _SEVERIDADE_SYSLOG_PADRAO)
    return facility * 8 + severidade


def _sanitizar_campo_cabecalho_syslog(valor, padrao="-"):
    """HOSTNAME/APP-NAME/PROCID/MSGID (RFC 5424) não podem ter espaço; usa
    '-' (valor "nil" do RFC) quando o campo está ausente ou vazio."""
    if valor is None or str(valor).strip() == "":
        return padrao
    return re.sub(r"\s+", "_", str(valor).strip())


def _escapar_valor_dados_estruturados(valor):
    """Dentro de um SD-PARAM (RFC 5424 §6.3.3), '"', ']' e '\\' precisam de escape."""
    texto = "" if valor is None else str(valor)
    return texto.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def formatar_syslog_rfc5424(alerta, classificacao=None, hostname=None, msgid="ALERTA", facility=SYSLOG_FACILITY_PADRAO, timestamp=None):
    """
    Formata um alerta no padrão Syslog RFC 5424:
        <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG

    `timestamp`, quando informado, deve já vir no formato RFC 3339
    (ex.: "2026-08-31T13:00:00.000Z") -- útil para tornar os testes
    determinísticos. Sem ele, usa o instante atual em UTC.
    """
    pri = _pri_syslog(classificacao, facility)
    ts = timestamp or datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    host = _sanitizar_campo_cabecalho_syslog(hostname)
    procid = "-"
    msg_id = _sanitizar_campo_cabecalho_syslog(msgid)

    tipo_ataque = _tipo_ataque_de(alerta)
    total = alerta.get("total_ataques")
    if total is None:
        total = alerta.get("status", "")

    dados_estruturados = (
        "[sentinela@32473 "
        f'ip="{_escapar_valor_dados_estruturados(alerta.get("ip", ""))}" '
        f'tipo="{_escapar_valor_dados_estruturados(tipo_ataque)}" '
        f'total="{_escapar_valor_dados_estruturados(total)}" '
        f'classificacao="{_escapar_valor_dados_estruturados(classificacao or "desconhecida")}"]'
    )

    mensagem = f"Ataque detectado: {tipo_ataque} a partir de {alerta.get('ip', 'IP desconhecido')}"

    return f"<{pri}>1 {ts} {host} {SYSLOG_APP_NAME} {procid} {msg_id} {dados_estruturados} {mensagem}"
