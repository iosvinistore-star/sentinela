# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Mapeamento simplificado de detecções para MITRE ATT&CK."""
MAPA_MITRE = {
    "SQL Injection (SQLi)": {"id": "T1190", "nome": "Exploit Public-Facing Application"},
    "Command Injection": {"id": "T1059", "nome": "Command and Scripting Interpreter"},
    "Path Traversal": {"id": "T1190", "nome": "Exploit Public-Facing Application"},
    "Cross-Site Scripting (XSS)": {"id": "T1190", "nome": "Exploit Public-Facing Application"},
    "Scanner de Vulnerabilidades": {"id": "T1595", "nome": "Active Scanning"},
    "Scanner de Vulnerabilidades (User-Agent)": {"id": "T1595", "nome": "Active Scanning"},
    # Portado de sentinela_soc_saas_2_3/mitre.py (GAP_REPORT_V3.1.md, Fase 18)
    # junto com as assinaturas/detectores correspondentes em analisador_logs.py.
    "Server-Side Request Forgery (SSRF)": {"id": "T1190", "nome": "Exploit Public-Facing Application"},
    "XML External Entity (XXE)": {"id": "T1190", "nome": "Exploit Public-Facing Application"},
    "Server-Side Template Injection (SSTI)": {"id": "T1190", "nome": "Exploit Public-Facing Application"},
    "LDAP Injection": {"id": "T1190", "nome": "Exploit Public-Facing Application"},
    "NoSQL Injection": {"id": "T1190", "nome": "Exploit Public-Facing Application"},
    "Log4Shell / JNDI Injection": {"id": "T1210", "nome": "Exploitation of Remote Services"},
    "Deserialização Insegura": {"id": "T1190", "nome": "Exploit Public-Facing Application"},
    "CRLF Injection / HTTP Response Splitting": {"id": "T1190", "nome": "Exploit Public-Facing Application"},
    "Open Redirect": {"id": "T1204", "nome": "User Execution"},
    "Força Bruta em Login (Brute Force)": {"id": "T1110", "nome": "Brute Force"},
    "Possível DDoS / Flood de Requisições": {"id": "T1498", "nome": "Network Denial of Service"},
}
def obter_mitre(tipo): return MAPA_MITRE.get(tipo, {"id":"N/A", "nome":"Não mapeado"})
