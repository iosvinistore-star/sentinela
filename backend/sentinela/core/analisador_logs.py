# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Analisador de Logs do Apache/Nginx para Detecção de Ataques Web.

Lê arquivos de log de um servidor web e identifica comportamentos suspeitos
usando expressões regulares (Regex), gerando um relatório de segurança.

Este módulo é PURO: nenhuma função aqui faz I/O de rede, escreve em disco
(fora da leitura do próprio arquivo de log) ou toca o banco de dados. A
orquestração de resposta a incidentes (reputação, bloqueio, criação de
incidente) foi movida para `sentinela.services.resposta_incidentes`, que é
assíncrona e tenant-aware — este módulo não sabe o que é uma "empresa".

Antes da rearquitetura multi-tenant, este arquivo também continha
`responder_a_incidentes()` (chamava incidents.py/SQLite diretamente) e o
bloco `__main__` de CLI. Ambos foram relocados: a CLI para
`sentinela.cli`, a orquestração para `sentinela.services.resposta_incidentes`
(que reusa `candidatos_por_limite` abaixo).

Correção pós-auditoria (GAP_REPORT_V3.1.md, Fase 18): a rearquitetura acima
não portou junto 9 assinaturas de ataque (SSRF, XXE, SSTI, LDAP/NoSQL
Injection, Log4Shell, Deserialização Insegura, CRLF Injection, Open
Redirect) nem a detecção volumétrica (Força Bruta em Login, DDoS/Flood) que
já existiam em `sentinela_soc_saas_2_3/analisador_logs.py` -- uma regressão
de cobertura de detecção, não uma decisão deliberada. Ambas foram portadas
de volta abaixo (`RastreadorVolumetrico` e as entradas correspondentes em
`PADROES_ATAQUE`), mantendo este módulo PURO: nenhum I/O novo foi
introduzido, só contadores em memória dentro de `processar_arquivo_logs`.
"""
import re
from collections import Counter
from urllib.parse import unquote

from sentinela.core.risk_engine import SEVERIDADE_PESO
from sentinela.util import ip_valido

# Expressões regulares para detectar padrões de ataques comuns.
# Aplicadas sobre a requisição já normalizada (URL-decoded) para reduzir
# evasão simples via encoding (%20, %27, %2e%2e%2f etc.).
PADROES_ATAQUE = {
    "SQL Injection (SQLi)": (
        r"(\bUNION\s+SELECT\b|\bSELECT\b.+\bFROM\b|\bINSERT\s+INTO\b|\bDROP\s+TABLE\b"
        r"|\bOR\s+1\s*=\s*1\b|'\s*OR\s*'|--\s|\/\*.*?\*\/|\b\w*SLEEP\s*\(|\bBENCHMARK\s*\("
        r"|\bWAITFOR\s+DELAY\b|\bINFORMATION_SCHEMA\b"
        # blind booleano genérico (ex.: ' AND 1=1, ' AND SUBSTRING(...)='a) --
        # exige uma aspa antes do AND/OR, igual a uma injeção real quebrando
        # a string original, para não disparar em cima de "and"/"or" comuns
        # em texto normal.
        r"|'\s*(AND|OR)\s+\S+\s*(=|<=|>=|<>|!=|<|>|LIKE)\s*"
        # stacked query / abuso de procedure (EXEC xp_cmdshell, sp_..., etc.)
        r"|\bEXEC(UTE)?\s+(XP|SP)_\w+|\bXP_CMDSHELL\b)"
    ),
    "Cross-Site Scripting (XSS)": (
        # \bon\w+\s*= cobre qualquer manipulador de evento HTML (onclick,
        # ontoggle, onpointerdown, e outros que apareçam no futuro) em vez de
        # uma lista fechada de 4 nomes -- \b antes de "on" evita bater em
        # palavras comuns como "salonEvent=" (que têm "on" no meio, não numa
        # borda de palavra).
        r"(<script[^>]*>|javascript:|\bon\w+\s*=|<iframe"
        r"|document\.cookie|String\.fromCharCode)"
    ),
    "Path Traversal": (
        r"(\.\./|\.\.\\|/etc/passwd|boot\.ini|/proc/self/environ|win\.ini"
        # qualquer caminho absoluto para um diretório sensível do SO, não só
        # os 4 arquivos específicos da lista original (ex.: /etc/shadow,
        # /proc/self/cmdline, /root/.ssh, /var/log/auth.log).
        r"|\/(etc|proc|sys|root|boot)\/|\/var\/(log|www)\/)"
    ),
    "Command Injection": (
        # separador antes do comando: ";", "|" OU uma quebra de linha real
        # (%0a decodificado) -- e a MESMA lista de binários nos três casos.
        # Na versão anterior, o grupo depois de "|" só reconhecia
        # cat/id/whoami (um subconjunto do grupo depois de ";"), então
        # "| sh", "| bash", "| nc" -- o clássico "baixar e executar" --
        # passavam despercebidos.
        r"([;|\n]\s*(cat|ls|wget|curl|nc|ncat|socat|bash|sh|dash|zsh|whoami|id"
        r"|rm|mv|cp|chmod|chown|ping|telnet|python3?|perl|php|ruby|base64|touch|echo|kill|uname|pwd)\b"
        r"|`[^`]+`|\$\([^)]+\))"
    ),
    "Scanner de Vulnerabilidades": r"\b(nikto|acunetix|dirbuster|sqlmap|nmap|nuclei|gobuster|wpscan|masscan|zgrab|whatweb)\b",
    # As 9 categorias abaixo (SSRF até Open Redirect) fecham a lacuna
    # identificada na auditoria V3.1 (GAP_REPORT_V3.1.md, Fase 18): existiam
    # há tempos em sentinela_soc_saas_2_3/analisador_logs.py e nunca tinham
    # sido portadas para este módulo -- uma regressão funcional de cobertura
    # de detecção, não uma escolha deliberada de arquitetura. Regexes e
    # comentários idênticos aos da V3, só reformatados para o estilo local.
    "Server-Side Request Forgery (SSRF)": (
        # Requisição tentando fazer o SERVIDOR buscar uma URL apontando para
        # loopback, rede interna (RFC1918) ou o endpoint de metadados de
        # nuvem (169.254.169.254, usado pra roubar credenciais de IAM em
        # AWS/GCP/Azure) -- o clássico "faça o servidor bater nele mesmo".
        r"(https?|ftp|dict|gopher|file)://(127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254"
        r"|\[::1\]|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}"
        r"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})"
    ),
    "XML External Entity (XXE)": (
        r"(<!DOCTYPE[^>]*\[|<!ENTITY\s+\S+\s+(SYSTEM|PUBLIC)\b)"
    ),
    "Server-Side Template Injection (SSTI)": (
        # Payloads clássicos de "prova de conceito" (matemática dentro da
        # sintaxe de template) mais alguns objetos internos que só existem
        # em engines de template server-side (Jinja2/Twig/etc.) -- nunca em
        # HTML/JS legítimo.
        r"(\{\{\s*\d+\s*[*+-]\s*\d+\s*\}\}|\{%.*?%\}|\$\{\s*\d+\s*[*+-]\s*\d+\s*\}|<%=.*?%>"
        r"|\{\{\s*(config|self|request|lipsum)\b)"
    ),
    "LDAP Injection": r"(\*\)\(\||\(\|\(|\(&\(|\)\(uid=\*|\(objectClass=\*\))",
    "NoSQL Injection": r"(\$where\b|\[\$where\]|\[\$ne\]|\[\$gt\]|\[\$regex\]|\$ne\s*[:=]|\$gt\s*[:=]|\$regex\s*[:=]|\$exists\s*[:=])",
    "Log4Shell / JNDI Injection": r"\$\{jndi:(ldap|ldaps|rmi|dns|iiop|nis|nds)://",
    "Deserialização Insegura": (
        # rO0AB.../aced0005 = assinatura de objeto Java serializado (em
        # base64 ou hex); O:N:"Classe":... = assinatura de objeto PHP
        # serializado -- os dois formatos exploráveis mais comuns.
        r"(rO0AB|aced0005|O:\d+:\"[^\"]+\":\d+:\{)"
    ),
    "CRLF Injection / HTTP Response Splitting": r"(\r\n|\n)\s*(Set-Cookie|Location)\s*:",
    "Open Redirect": (
        # Qualquer parâmetro de redirecionamento comum apontando para uma
        # URL absoluta -- inclusive pro próprio domínio, então isso aceita
        # mais falso positivo em troca de não exigir uma lista de domínios
        # confiáveis (que este projeto não tem como conhecer de antemão),
        # o mesmo trade-off já aceito na heurística de User-Agent acima.
        r"[?&](redirect|redirect_uri|return|returnurl|return_url|next|url|dest|destination|continue)=https?://"
    ),
}

# User-Agents de ferramentas de varredura conhecidas (muitos scanners não
# colocam payload na URL, só se identificam no cabeçalho User-Agent).
# Além dos nomes de scanners específicos, inclui bibliotecas HTTP genéricas
# muito usadas em scripts de varredura customizados (curl, wget, python,
# go, java, ruby, php, ferramentas de automação de API etc.) -- um script
# "na mão" raramente reproduz o User-Agent de um navegador de verdade.
# Isso não elimina o problema de fundo (uma lista de assinaturas nunca
# cobre um User-Agent nunca visto antes), mas reduz bastante a superfície.
PADRAO_SCANNER_USER_AGENT = (
    r"\b(nikto|acunetix|dirbuster|sqlmap|nmap|nuclei|gobuster|wpscan|masscan|zgrab|whatweb"
    r"|hydra|curl.*bot|python-requests|python-urllib|go-http-client|libwww-perl|okhttp"
    r"|axios|node-fetch|postmanruntime|apache-httpclient|scrapy|ruby|php-|java\/|winhttp|libcurl)\b"
)

# Heurística de fallback: nenhuma lista de nomes de ferramenta cobre uma
# ferramenta nunca vista antes. Em vez de tentar enumerar cada scanner que
# ainda vai ser lançado, viramos a lógica ao contrário -- um User-Agent de
# navegador de verdade SEMPRE carrega um destes tokens de motor de
# renderização; se não carrega nenhum, o cliente não está usando um
# navegador (é uma lib HTTP crua, um script, uma ferramenta customizada
# qualquer). Isso fecha a lacuna estrutural de qualquer lista fechada, ao
# custo de mais falso positivo em tráfego legítimo não-navegador
# (health checks, webhooks, apps mobile, integrações de API) -- por isso
# damos um passe livre pros bots/monitoramento conhecidos abaixo antes de
# aplicar essa heurística.
PADRAO_USER_AGENT_NAVEGADOR = r"\b(Mozilla|AppleWebKit|Gecko|Chrome|Safari|Firefox|Edg|OPR|Trident|MSIE)\b"

# Bots, crawlers e monitoramento amplamente conhecidos e legítimos que não
# usam "cara de navegador" -- não devem virar alerta só por causa disso.
PADRAO_CLIENTE_LEGITIMO_CONHECIDO = (
    r"\b(googlebot|bingbot|slackbot|facebookexternalhit|twitterbot|discordbot|linkedinbot"
    r"|applebot|duckduckbot|yandexbot|pingdom|uptimerobot|statuscake|newrelic|datadog"
    r"|kube-probe|elb-healthchecker|googlehc|github-hookshot|stripe)\b"
)


def _user_agent_parece_navegador_ou_cliente_legitimo(user_agent):
    return bool(
        re.search(PADRAO_USER_AGENT_NAVEGADOR, user_agent, re.IGNORECASE)
        or re.search(PADRAO_CLIENTE_LEGITIMO_CONHECIDO, user_agent, re.IGNORECASE)
    )

# Aceita Common Log Format e Combined Log Format (referrer/user-agent opcionais)
# Exemplo CLF: 192.168.1.1 - - [26/Aug/2026:16:14:00 -0300] "GET /admin?id=1' OR '1'='1 HTTP/1.1" 200 4502
# Exemplo Combined: ... 200 4502 "https://referer.com" "Mozilla/5.0 ..."
PADRAO_LOG = (
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<data>.*?)\]\s+"(?P<requisicao>.*?)"\s+'
    r'(?P<status>\d{3})\s+(?P<tamanho>\S+)'
    r'(?:\s+"(?P<referrer>.*?)"\s+"(?P<user_agent>.*?)")?'
)


# ---------------------------------------------------------------------------
# Detecção por VOLUME (Força Bruta e DDoS/Flood).
#
# SQLi, XSS, path traversal etc. são detectáveis numa ÚNICA requisição -- o
# payload sozinho já denuncia a intenção. Força bruta de login e DDoS/flood
# são diferentes: uma requisição isolada (uma tentativa de login errada, um
# GET normal) é indistinguível de tráfego legítimo. O que denuncia o ataque
# é a REPETIÇÃO -- por isso são tratados à parte, contando ocorrências por IP
# em vez de casar uma regex numa linha só.
#
# Portado de sentinela_soc_saas_2_3/analisador_logs.py (GAP_REPORT_V3.1.md,
# Fase 18) -- ver nota equivalente acima em PADROES_ATAQUE. Continua PURO
# (só contadores em memória, nenhum I/O além da leitura do arquivo já feita
# por `processar_arquivo_logs`), então não quebra a separação descrita no
# docstring do módulo nem exige nenhuma mudança em
# `sentinela.services.resposta_incidentes`: os alertas sintéticos abaixo
# entram na mesma lista `detalhes_alertas`/`contagem_completa_ips` de
# qualquer outro alerta, então `candidatos_por_limite` e
# `perfil_comportamental_por_ip` já os enxergam de graça.
# ---------------------------------------------------------------------------

# Rotas comumente usadas para autenticação -- usado para saber quando uma
# resposta de falha (401/403) é uma tentativa de login, e não qualquer
# outro endpoint protegido.
PADRAO_ROTA_LOGIN = r"\b(login|signin|sign-in|log-in|entrar|autenticar|authenticate|wp-login\.php|admin/login)\b"

# Códigos HTTP que indicam falha de autenticação.
STATUS_FALHA_LOGIN = {"401", "403"}

# A partir de quantas tentativas de login falhas do MESMO IP consideramos
# força bruta (e não só o usuário errando a senha uma ou duas vezes).
LIMITE_TENTATIVAS_LOGIN_PADRAO = 5

# A partir de quantas requisições do MESMO IP, dentro do arquivo/janela
# analisada, consideramos volume anormal (possível DDoS/flood). É um limiar
# arbitrário e alto de propósito -- o objetivo é pegar volume claramente
# fora da curva, não gerar alerta pra todo cliente que navega bastante.
LIMITE_REQUISICOES_DDOS_PADRAO = 100


class RastreadorVolumetrico:
    """
    Acompanha, por IP, o volume de requisições e as tentativas de login
    falhas, para detectar Força Bruta e DDoS/Flood -- ataques que não têm
    assinatura de payload (a requisição individual é "limpa"), só ficam
    visíveis pela repetição ao longo do tempo.

    Usado por `processar_arquivo_logs`, que alimenta linha por linha na
    ordem em que aparecem no arquivo -- por isso é incremental
    (`registrar()` é chamado uma linha de cada vez) em vez de operar sobre
    o arquivo inteiro de uma vez.

    Dispara o alerta sintético UMA ÚNICA VEZ por IP, no exato momento em
    que o limite é cruzado -- as linhas seguintes do mesmo IP não geram um
    novo alerta repetido a cada requisição.
    """

    def __init__(self, limite_tentativas_login=LIMITE_TENTATIVAS_LOGIN_PADRAO,
                 limite_requisicoes_ddos=LIMITE_REQUISICOES_DDOS_PADRAO):
        self.limite_tentativas_login = limite_tentativas_login
        self.limite_requisicoes_ddos = limite_requisicoes_ddos
        self.requisicoes_por_ip = Counter()
        self.tentativas_login_por_ip = Counter()
        self._sinalizado_ddos = set()
        self._sinalizado_forca_bruta = set()

    def registrar(self, ip, data, requisicao, status):
        """Registra uma requisição já parseada. Retorna uma lista (0 a 2
        itens) com os alertas sintéticos de volume que acabaram de cruzar
        o limite agora."""
        novos_alertas = []

        self.requisicoes_por_ip[ip] += 1
        if (
            self.requisicoes_por_ip[ip] == self.limite_requisicoes_ddos
            and ip not in self._sinalizado_ddos
        ):
            self._sinalizado_ddos.add(ip)
            novos_alertas.append({
                "ip": ip,
                "data": data,
                "requisicao": f"{self.requisicoes_por_ip[ip]} requisições no período analisado",
                "status": "-",
                "tipo_ataque": "Possível DDoS / Flood de Requisições",
            })

        if status in STATUS_FALHA_LOGIN and re.search(PADRAO_ROTA_LOGIN, requisicao, re.IGNORECASE):
            self.tentativas_login_por_ip[ip] += 1
            if (
                self.tentativas_login_por_ip[ip] == self.limite_tentativas_login
                and ip not in self._sinalizado_forca_bruta
            ):
                self._sinalizado_forca_bruta.add(ip)
                novos_alertas.append({
                    "ip": ip,
                    "data": data,
                    "requisicao": f"{self.tentativas_login_por_ip[ip]} tentativas de login falhas",
                    "status": "401/403",
                    "tipo_ataque": "Força Bruta em Login (Brute Force)",
                })

        return novos_alertas


_NORMALIZAR_MAX_CAMADAS = 5


def _normalizar(texto):
    """
    Decodifica URL-encoding em camadas (uma chamada fixa de unquote(unquote(...))
    parava em 2 níveis -- um payload codificado 3x ou mais escapava de todas as
    assinaturas). Decodifica em loop até o texto estabilizar (não muda mais) ou
    até um teto de camadas, o que vier primeiro -- o teto existe só para não
    girar indefinidamente num texto adversarial construído para isso.
    """
    try:
        atual = texto
        for _ in range(_NORMALIZAR_MAX_CAMADAS):
            proximo = unquote(atual)
            if proximo == atual:
                break
            atual = proximo
        return atual
    except Exception:
        return texto


def analisar_linha_log(linha):
    match = re.match(PADRAO_LOG, linha)

    if not match:
        return {"nao_reconhecida": True}

    dados = match.groupdict()

    # O grupo (?P<ip>\S+) do regex casa com QUALQUER token sem espaço, não
    # só endereços IP -- um log corrompido, um proxy mal configurado
    # anexando um hostname, ou uma linha adversarial construída para isso
    # podia colocar lixo nesse campo. Esse valor depois viaja sem
    # tratamento até: (a) reputacao.consultar_reputacao_ip -- já validado
    # lá como defesa em profundidade, mas causava trabalho e chamadas de
    # rede desperdiçadas antes; e (b) services.incidentes.criar_incidente,
    # que faz INSERT numa coluna Postgres `inet` -- essa SIM rejeitava
    # valor não-IP com uma exceção crua (asyncpg.DataError), virando 500
    # sem tratamento nenhum. Tratamos como linha não reconhecida, igual a
    # uma linha que não bate no formato de log esperado.
    #
    # `ip_valido` (não só `ipaddress.ip_address`) também rejeita a notação
    # de zone-id do IPv6 ("fe80::1%eth0") -- `ipaddress` aceita, Postgres
    # `inet` não, e um candidato assim travava o lote inteiro de resposta a
    # incidentes (ver util.ip_valido para a explicação completa).
    if ip_valido(dados["ip"]) is None:
        return {"nao_reconhecida": True}

    requisicao = dados["requisicao"]
    requisicao_normalizada = _normalizar(requisicao)
    user_agent = dados.get("user_agent") or ""

    # Verifica se a requisição bate com algum padrão de ataque.
    #
    # Correção de bug encontrado em revisão crítica (2026-09, "revisa as
    # outras partes do sistema", achado 2): PADROES_ATAQUE é iterado em
    # ordem de inserção e o código antigo retornava no PRIMEIRO padrão que
    # batesse -- mas o padrão de "Path Traversal" bate em qualquer caminho
    # absoluto sensível (`/(etc|proc|sys|root|boot)/`), MESMO sem `../`, e
    # vem antes de "Command Injection" no dict. Um payload de injeção de
    # comando real que também referencia um caminho sensível (ex.:
    # `;cat /etc/passwd`) era classificado como Path Traversal em vez de
    # Command Injection -- e como SEVERIDADE_PESO pesa Command Injection em
    # 30 contra 20 de Path Traversal (ver core/risk_engine.py), isso podia
    # derrubar o score calculado abaixo do limiar HIGH/CRITICAL que
    # services/resposta_incidentes.py usa para decidir se cria incidente e
    # aciona bloqueio automático de firewall -- deixando ataques reais de
    # command injection passarem sem gerar incidente.
    #
    # A correção verifica TODOS os padrões (em vez de parar no primeiro) e
    # escolhe o de MAIOR severidade entre os que bateram, usando a mesma
    # tabela de pesos que o motor de risco usa depois -- assim a
    # classificação reportada é sempre consistente com o score que ela
    # alimenta.
    tipo_ataque_escolhido = None
    peso_escolhido = -1
    for tipo_ataque, regex in PADROES_ATAQUE.items():
        if re.search(regex, requisicao_normalizada, re.IGNORECASE):
            peso = SEVERIDADE_PESO.get(tipo_ataque, 8)
            if peso > peso_escolhido:
                peso_escolhido = peso
                tipo_ataque_escolhido = tipo_ataque
    if tipo_ataque_escolhido is not None:
        return {
            "ip": dados["ip"],
            "data": dados["data"],
            "requisicao": requisicao,
            "status": dados["status"],
            "tipo_ataque": tipo_ataque_escolhido,
        }

    # Alguns scanners não colocam payload na URL, só se identificam no User-Agent
    if user_agent and re.search(PADRAO_SCANNER_USER_AGENT, user_agent, re.IGNORECASE):
        return {
            "ip": dados["ip"],
            "data": dados["data"],
            "requisicao": requisicao,
            "status": dados["status"],
            "tipo_ataque": "Scanner de Vulnerabilidades (User-Agent)",
        }

    # Fallback: User-Agent presente, mas que não bate com nenhum nome de
    # ferramenta conhecido -- se também não se parece com um navegador nem
    # com um bot/monitoramento legítimo conhecido, tratamos como cliente
    # suspeito (ver comentário de PADRAO_USER_AGENT_NAVEGADOR acima).
    if user_agent and not _user_agent_parece_navegador_ou_cliente_legitimo(user_agent):
        return {
            "ip": dados["ip"],
            "data": dados["data"],
            "requisicao": requisicao,
            "status": dados["status"],
            "tipo_ataque": "Scanner de Vulnerabilidades (User-Agent)",
        }

    return None


def processar_arquivo_logs(
    caminho_arquivo,
    limite_tentativas_login=LIMITE_TENTATIVAS_LOGIN_PADRAO,
    limite_requisicoes_ddos=LIMITE_REQUISICOES_DDOS_PADRAO,
):
    alertas = []
    ips_suspeitos = []
    linhas_totais = 0
    linhas_nao_reconhecidas = 0
    rastreador = RastreadorVolumetrico(
        limite_tentativas_login=limite_tentativas_login,
        limite_requisicoes_ddos=limite_requisicoes_ddos,
    )

    with open(caminho_arquivo, "r", encoding="utf-8") as arquivo:
        for linha in arquivo:
            linha = linha.rstrip("\n")
            if not linha.strip():
                continue
            linhas_totais += 1

            # Volume (Força Bruta / DDoS): precisa ver TODA linha reconhecida
            # pelo formato de log, inclusive as "limpas" sem payload
            # malicioso -- é a repetição delas que denuncia o ataque, não o
            # conteúdo de uma isolada (ver RastreadorVolumetrico acima).
            # Mesma validação de IP aplicada em analisar_linha_log (ver
            # comentário lá): um IP malformado não deve virar candidato a
            # incidente/bloqueio também pela via volumétrica.
            match_bruto = re.match(PADRAO_LOG, linha)
            if match_bruto:
                dados_brutos = match_bruto.groupdict()
                if ip_valido(dados_brutos["ip"]) is not None:
                    for alerta_volumetrico in rastreador.registrar(
                        dados_brutos["ip"], dados_brutos["data"],
                        dados_brutos["requisicao"], dados_brutos["status"],
                    ):
                        alertas.append(alerta_volumetrico)
                        ips_suspeitos.append(alerta_volumetrico["ip"])

            resultado = analisar_linha_log(linha)
            if resultado is None:
                continue
            if resultado.get("nao_reconhecida"):
                linhas_nao_reconhecidas += 1
                continue

            alertas.append(resultado)
            ips_suspeitos.append(resultado["ip"])

    # Resumo estatístico
    contagem_ips = Counter(ips_suspeitos)

    relatorio = {
        "linhas_totais": linhas_totais,
        "linhas_nao_reconhecidas": linhas_nao_reconhecidas,
        "total_alertas": len(alertas),
        "ips_mais_perigosos": contagem_ips.most_common(3),
        "contagem_completa_ips": dict(contagem_ips),
        "detalhes_alertas": alertas,
    }

    return relatorio


def perfil_comportamental_por_ip(relatorio):
    """Resume o comportamento temporal de cada IP detectado.

    Retorna contagem, tipos, reincidência dentro do próprio arquivo e
    concentração de ataques por minuto. É deliberadamente puro para que a
    mesma regra possa ser usada pela API, CLI e testes.
    """
    from collections import defaultdict
    perfis = defaultdict(lambda: {"total": 0, "tipos": set(), "minutos": Counter()})
    for alerta in relatorio.get("detalhes_alertas", []):
        ip = alerta["ip"]
        perfis[ip]["total"] += 1
        perfis[ip]["tipos"].add(alerta["tipo_ataque"])
        minuto = str(alerta.get("data", ""))[:17]
        perfis[ip]["minutos"][minuto] += 1
    resultado = {}
    for ip, p in perfis.items():
        pico = max(p["minutos"].values(), default=0)
        resultado[ip] = {
            "total": p["total"],
            "tipos": sorted(p["tipos"]),
            "pico_por_minuto": pico,
            "reincidente": p["total"] >= 10 or len(p["tipos"]) >= 3,
        }
    return resultado


def candidatos_por_limite(relatorio, limite_ataques=5):
    """
    Extrai do relatório os IPs que ultrapassaram `limite_ataques`, com os
    tipos de ataque associados a cada um. Função pura (sem I/O) — é o que
    antes era a primeira metade de `responder_a_incidentes()`; a parte que
    consultava reputação, calculava risco, criava incidente e bloqueava
    agora vive em `sentinela.services.resposta_incidentes` (precisa ser
    assíncrona e saber a empresa do usuário logado).

    Retorna uma lista de dicts `{ip, total_ataques, tipos_ataque}`, ordenada
    do IP mais ativo para o menos ativo (mesma ordem de antes).
    """
    tipos_por_ip = {}
    for alerta in relatorio["detalhes_alertas"]:
        tipos_por_ip.setdefault(alerta["ip"], set()).add(alerta["tipo_ataque"])

    candidatos = []
    for ip, total in sorted(relatorio["contagem_completa_ips"].items(), key=lambda x: -x[1]):
        if total <= limite_ataques:
            continue
        candidatos.append({
            "ip": ip,
            "total_ataques": total,
            "tipos_ataque": sorted(tipos_por_ip.get(ip, [])),
        })
    return candidatos
