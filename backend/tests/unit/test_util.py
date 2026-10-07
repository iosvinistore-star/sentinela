# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Testes de sentinela.util -- em particular ip_valido, o único ponto de
validação de IP do projeto (ver o docstring da função para o porquê)."""
import ipaddress

from sentinela.util import ip_valido, obter_ip_cliente


class _ClienteFalso:
    def __init__(self, host):
        self.host = host


class _RequestFalso:
    """Dublê mínimo de fastapi.Request -- só o que obter_ip_cliente usa
    (`request.client.host` e `request.headers.get`)."""

    def __init__(self, host, x_forwarded_for=None):
        self.client = _ClienteFalso(host) if host else None
        self.headers = {}
        if x_forwarded_for is not None:
            self.headers["x-forwarded-for"] = x_forwarded_for


def test_ip_valido_aceita_ipv4_normal():
    assert ip_valido("203.0.113.5") == ipaddress.ip_address("203.0.113.5")


def test_ip_valido_aceita_ipv6_normal():
    assert ip_valido("2606:4700:4700::1111") == ipaddress.ip_address("2606:4700:4700::1111")


def test_ip_valido_rejeita_string_vazia_ou_none():
    assert ip_valido("") is None
    assert ip_valido(None) is None


def test_ip_valido_rejeita_texto_arbitrario():
    assert ip_valido("nao-e-um-ip") is None
    assert ip_valido("example.com") is None


def test_ip_valido_rejeita_zone_id_ipv6():
    """ipaddress.ip_address() sozinho ACEITA essa notação (RFC 4007) --
    é exatamente por isso que ip_valido existe: o Postgres `inet` não
    entende zone-id, então esse valor não pode ser tratado como um IP
    "normal" em nenhum lugar do sistema."""
    assert ip_valido("fe80::1%eth0") is None
    assert ip_valido("2606:4700:4700::1111%eth0") is None
    # confirma que o stdlib sozinho aceitaria (documentando o porquê do guard)
    assert ipaddress.ip_address("fe80::1%eth0") is not None


def test_ip_valido_rejeita_zone_id_com_caracteres_estranhos():
    """A zona pode conter praticamente qualquer coisa exceto um segundo
    '%'/'/' -- inclusive espaço, '?', '#'. ip_valido rejeita tudo isso de
    uma vez só checando '%' na string inteira, sem tentar enumerar formatos
    inválidos de zona."""
    assert ip_valido("2606:4700:4700::1111%abc?x=1") is None
    assert ip_valido("2606:4700:4700::1111%zona com espaco") is None


# obter_ip_cliente -- ver o docstring da função para o raciocínio completo.


def test_obter_ip_cliente_sem_proxies_confiaveis_ignora_x_forwarded_for():
    """Comportamento padrão (o de sempre): X-Forwarded-For é totalmente
    ignorado quando nenhum proxy confiável está configurado -- confiar
    nele sem isso deixaria qualquer requisição forjar seu próprio "IP" e
    zerar o rate limit de login a cada tentativa."""
    request = _RequestFalso("203.0.113.9", x_forwarded_for="9.9.9.9")
    assert obter_ip_cliente(request, "") == "203.0.113.9"


def test_obter_ip_cliente_ignora_x_forwarded_for_de_quem_nao_e_proxy_confiavel():
    """Mesmo com proxies_confiaveis configurado, só usa o header se a
    conexão TCP DIRETA vier de um proxy confiável -- um cliente comum
    (não listado) que manda X-Forwarded-For não consegue forjar nada."""
    request = _RequestFalso("198.51.100.1", x_forwarded_for="9.9.9.9")
    assert obter_ip_cliente(request, "10.0.0.1") == "198.51.100.1"


def test_obter_ip_cliente_usa_x_forwarded_for_quando_proxy_e_confiavel():
    request = _RequestFalso("10.0.0.1", x_forwarded_for="203.0.113.55")
    assert obter_ip_cliente(request, "10.0.0.1") == "203.0.113.55"


def test_obter_ip_cliente_pula_saltos_de_proxy_confiavel_no_meio_da_cadeia():
    """Vários proxies confiáveis encadeados: percorre da direita pra
    esquerda e usa o primeiro salto que NÃO é um proxy confiável -- o
    cliente final não consegue inserir uma entrada falsa antes da que os
    proxies de fato anexaram."""
    request = _RequestFalso("10.0.0.2", x_forwarded_for="9.9.9.9, 203.0.113.55, 10.0.0.1")
    assert obter_ip_cliente(request, "10.0.0.1,10.0.0.2") == "203.0.113.55"


def test_obter_ip_cliente_cai_no_ip_direto_se_todos_os_saltos_forem_proxies():
    request = _RequestFalso("10.0.0.1", x_forwarded_for="10.0.0.1, 10.0.0.1")
    assert obter_ip_cliente(request, "10.0.0.1") == "10.0.0.1"


def test_obter_ip_cliente_sem_client_devolve_desconhecido():
    request = _RequestFalso(None)
    assert obter_ip_cliente(request, "") == "desconhecido"
