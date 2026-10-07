# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Utilitários pequenos e compartilhados entre módulos que não se encaixam em nenhuma camada específica."""
import ipaddress
from datetime import datetime, timezone


def ip_valido(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """
    Único ponto de validação de IP do projeto -- todo `ipaddress.ip_address(ip)`
    espalhado por core/analisador_logs.py, core/reputacao.py, core/firewall.py
    e api/v1/reputacao.py deveria (e agora deve) passar por aqui.

    `ipaddress.ip_address()` sozinho aceita mais do que os tipos de coluna
    do projeto entendem: desde o Python 3.9 ele aceita a notação de "zone
    id"/"scope id" do IPv6 (RFC 4007, ex. "fe80::1%eth0"), inclusive com
    caracteres estranhos dentro da zona (confirmado: espaço, "?", "#" -- só
    um segundo "%" ou "/" são rejeitados). O tipo `inet` do Postgres NÃO
    entende essa notação -- `'fe80::1%eth0'::inet` falha com
    `invalid input syntax for type inet`, e essa exceção (asyncpg.DataError)
    não é subclasse de ValueError, então não cai no handler genérico da API
    (vira 500 cru). Pior: como esse valor podia ser aceito como "IP" de um
    alerta em analisador_logs.py, um único candidato assim, num lote de
    resposta a incidentes, abortava o processamento de TODOS os outros
    candidatos do mesmo lote (ver services/resposta_incidentes.py) --
    técnica de evasão do pipeline inteiro, não só um erro cosmético.

    Retorna o objeto `IPv4Address`/`IPv6Address` se `ip` for um endereço
    puro e sem zone id (o único formato que os tipos `inet` do banco e as
    APIs externas de reputação esperam); `None` caso contrário.
    """
    if not ip or "%" in ip:
        return None
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return None


def obter_ip_cliente(request, proxies_confiaveis: str) -> str:
    """
    Único ponto de resolução do "IP do chamador" do projeto -- usado pelo
    limitador de força bruta (login e esqueci-senha, ver
    api/v1/auth.py/web/routes_auth.py, que antes tinham cada um sua própria
    cópia de `_ip_do_chamador`).

    Comportamento padrão (proxies_confiaveis vazio, o que preserva o que o
    projeto sempre fez): devolve `request.client.host` direto, ignorando
    completamente o cabeçalho `X-Forwarded-For` -- que é enviado pelo
    CLIENTE, então confiar nele sem mais nada permitiria qualquer um
    escrever `X-Forwarded-For: 1.2.3.4` e resetar o próprio contador de
    tentativas a cada requisição (bypass total do rate limit).

    Quando `proxies_confiaveis` está configurado (lista de IPs separados
    por vírgula -- ex. o IP interno do load balancer/reverse proxy) E a
    conexão TCP direta (`request.client.host`) é de fato um desses
    proxies, aí sim o `X-Forwarded-For` é considerado -- percorrido da
    DIREITA pra esquerda (a ordem em que cada proxy MAIS PRÓXIMO do
    servidor acrescenta a entrada), pulando qualquer entrada que também
    seja um proxy confiável, e usando a primeira que não for. Isso evita
    que o próprio cliente final consiga forjar uma entrada adicional no
    início da lista -- só o que os proxies confiáveis anexaram é
    considerado.
    """
    ip_direto = request.client.host if request.client else "desconhecido"
    proxies = {p.strip() for p in proxies_confiaveis.split(",") if p.strip()}
    if not proxies or ip_direto not in proxies:
        return ip_direto
    cabecalho = request.headers.get("x-forwarded-for", "")
    saltos = [h.strip() for h in cabecalho.split(",") if h.strip()]
    for candidato in reversed(saltos):
        if candidato not in proxies:
            return candidato
    return ip_direto


def parse_datetime_iso(valor):
    """
    Converte strings ISO 8601 (com ou sem 'Z', com ou sem timezone, com ou
    sem microssegundos -- os formatos que core.firewall/scripts de migração
    produzem via datetime.isoformat()) para datetime timezone-aware.

    Necessário porque asyncpg exige um datetime.datetime de verdade para
    colunas timestamptz -- ao contrário do psycopg, ele não roda a função
    de input de texto do Postgres nos parâmetros (mesmo com um cast
    ``::timestamptz`` explícito no SQL), então passar uma string crua falha
    com TypeError/DataError.
    """
    if valor in (None, ""):
        return None
    if isinstance(valor, datetime):
        return valor if valor.tzinfo else valor.replace(tzinfo=timezone.utc)
    texto = str(valor).strip()
    if texto.endswith("Z"):
        texto = texto[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(texto)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
