# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testes dos formatadores de exportação para SIEM (formatadores.py).

Nenhum destes testes abre socket nem grava arquivo -- as funções testadas
são puras (dict de alerta -> string), então não precisam de nenhuma
fixture de isolamento além das já aplicadas globalmente em conftest.py.
"""
import re

from sentinela.core import formatadores


ALERTA_SQLI = {
    "ip": "203.0.113.5",
    "data": "26/Aug/2026:10:01:00",
    "requisicao": "GET /vulneravel.php?id=1' UNION SELECT null,pass FROM users HTTP/1.1",
    "status": "200",
    "tipo_ataque": "SQL Injection (SQLi)",
}

ALERTA_INCIDENTE = {
    "ip": "198.51.100.7",
    "total_ataques": 12,
    "tipos_ataque": ["Cross-Site Scripting (XSS)", "Path Traversal"],
}


# ---------------------------------------------------------------------------
# CEF
# ---------------------------------------------------------------------------

def test_formatar_cef_tem_o_cabecalho_esperado():
    linha = formatadores.formatar_cef(ALERTA_SQLI, timestamp_epoch_millis=1735689600000)
    assert linha.startswith(
        "CEF:0|SentinelaDeLogs|AnalisadorDeLogsApacheNginx|1.0|100|SQL Injection (SQLi)|5|"
    )


def test_formatar_cef_inclui_campos_de_extensao_esperados():
    linha = formatadores.formatar_cef(ALERTA_SQLI, timestamp_epoch_millis=1735689600000)
    extensao = linha.split("|")[-1]
    assert "src=203.0.113.5" in extensao
    assert "requestMethod=GET" in extensao
    assert "cat=SQL Injection (SQLi)" in extensao
    assert "cs1=200" in extensao
    assert "rt=1735689600000" in extensao


def test_formatar_cef_aceita_entrada_de_responder_a_incidentes():
    linha = formatadores.formatar_cef(ALERTA_INCIDENTE)
    assert "src=198.51.100.7" in linha
    assert "cnt=12" in linha
    # tipos_ataque (lista) vira o "cat" da extensão e o "Name" do cabeçalho
    assert "Cross-Site Scripting (XSS), Path Traversal" in linha


def test_formatar_cef_severidade_varia_com_a_classificacao():
    baixo = formatadores.formatar_cef(ALERTA_SQLI, classificacao="BAIXO RISCO / DESCONHECIDO")
    alto = formatadores.formatar_cef(ALERTA_SQLI, classificacao="ALTO RISCO")
    sev_baixo = int(baixo.split("|")[6])
    sev_alto = int(alto.split("|")[6])
    assert sev_alto > sev_baixo


def test_formatar_cef_escapa_barra_invertida_na_extensao_e_preserva_pipe():
    # No CEF, o pipe só é especial no CABEÇALHO; na extensão (chave=valor)
    # apenas '\' e '=' precisam de escape -- por isso o pipe da requisição
    # segue intacto, e a barra invertida é duplicada.
    requisicao_original = "GET /a|b\\c HTTP/1.1"
    alerta = dict(ALERTA_SQLI, requisicao=requisicao_original)
    linha = formatadores.formatar_cef(alerta)
    esperado = "request=" + requisicao_original.replace("\\", "\\\\")
    assert esperado in linha


def test_formatar_cef_tipo_de_ataque_desconhecido_usa_signature_id_padrao():
    alerta = dict(ALERTA_SQLI, tipo_ataque="Algo Novo Que Ainda Não Existe")
    linha = formatadores.formatar_cef(alerta)
    assert linha.split("|")[4] == "000"


# ---------------------------------------------------------------------------
# Syslog RFC 5424
# ---------------------------------------------------------------------------

# <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
PADRAO_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<versao>\d) (?P<timestamp>\S+) (?P<hostname>\S+) "
    r"(?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) (?P<sd>\[.*?\]) (?P<msg>.*)$"
)


def test_formatar_syslog_bate_com_a_estrutura_do_rfc5424():
    linha = formatadores.formatar_syslog_rfc5424(
        ALERTA_SQLI, timestamp="2026-08-31T10:01:00.000Z"
    )
    match = PADRAO_RFC5424.match(linha)
    assert match is not None, f"linha fora do formato RFC 5424: {linha!r}"
    assert match.group("versao") == "1"
    assert match.group("timestamp") == "2026-08-31T10:01:00.000Z"
    assert match.group("app") == "sentinela-de-logs"


def test_formatar_syslog_pri_reflete_facility_e_severidade():
    # facility=16 (local0), severidade "RISCO MODERADO"=4 -> PRI = 16*8+4 = 132
    linha = formatadores.formatar_syslog_rfc5424(ALERTA_SQLI, classificacao="RISCO MODERADO")
    pri = int(PADRAO_RFC5424.match(linha).group("pri"))
    assert pri == 132


def test_formatar_syslog_hostname_ausente_vira_nil_value():
    linha = formatadores.formatar_syslog_rfc5424(ALERTA_SQLI, hostname=None)
    hostname = PADRAO_RFC5424.match(linha).group("hostname")
    assert hostname == "-"


def test_formatar_syslog_hostname_com_espaco_e_sanitizado():
    linha = formatadores.formatar_syslog_rfc5424(ALERTA_SQLI, hostname="meu servidor web")
    hostname = PADRAO_RFC5424.match(linha).group("hostname")
    assert " " not in hostname
    assert hostname == "meu_servidor_web"


def test_formatar_syslog_dados_estruturados_contem_ip_e_tipo():
    linha = formatadores.formatar_syslog_rfc5424(ALERTA_SQLI)
    sd = PADRAO_RFC5424.match(linha).group("sd")
    assert 'ip="203.0.113.5"' in sd
    assert 'tipo="SQL Injection (SQLi)"' in sd


def test_formatar_syslog_escapa_aspas_nos_dados_estruturados():
    alerta = dict(ALERTA_SQLI, ip='1.2.3.4" injetado')
    linha = formatadores.formatar_syslog_rfc5424(alerta)
    sd = PADRAO_RFC5424.match(linha).group("sd")
    assert '\\"' in sd


def test_formatar_syslog_aceita_entrada_de_responder_a_incidentes():
    linha = formatadores.formatar_syslog_rfc5424(ALERTA_INCIDENTE)
    assert "198.51.100.7" in linha
    assert "Cross-Site Scripting (XSS), Path Traversal" in linha
