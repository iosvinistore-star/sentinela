# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""CTI (siem/cti.py) -- parser STIX, exportação STIX 2.1 e proteção SSRF do TAXII."""
import json
import re
import socket
from datetime import datetime, timezone

import pytest

from sentinela.siem import cti
from sentinela.siem.cti import CTIErro, extrair_bundle_stix, indicador_para_stix, normalizar_stix_indicator, validar_url_taxii


def _ind(pattern, **extra):
    return {"type": "indicator", "id": "indicator--11111111-1111-4111-8111-111111111111", "pattern": pattern, **extra}


@pytest.mark.parametrize("pattern,tipo,valor", [
    ("[ipv4-addr:value = '203.0.113.9']", "ipv4-addr", "203.0.113.9"),
    ("[ipv4-addr:value='203.0.113.9']", "ipv4-addr", "203.0.113.9"),
    ("[domain-name:value = 'evil.example']", "domain-name", "evil.example"),
    ("[url:value = 'http://x.example/a\\'b']", "url", "http://x.example/a'b"),
    ("[file:hashes.'SHA-256' = 'ABCDEF']", "sha256", "abcdef"),
    ("[ipv4-addr:value = '1.2.3.4'] OR [ipv4-addr:value = '5.6.7.8']", "ipv4-addr", "1.2.3.4"),
])
def test_extrai_valor_de_padroes_reais(pattern, tipo, valor):
    """Bug V8.1: com espaços em volta do '=', o 'valor' era o padrão inteiro."""
    r = normalizar_stix_indicator(_ind(pattern), "t")
    assert r["indicator_type"] == tipo
    assert r["valor"] == valor


def test_valid_until_e_labels_prontos_para_asyncpg():
    """Bug V8.1: string ISO ia para TIMESTAMPTZ e lista ia para JSONB -> asyncpg recusava."""
    r = normalizar_stix_indicator(_ind("[ipv4-addr:value = '1.1.1.1']", valid_until="2030-01-01T00:00:00Z",
                                       labels=["malicious-activity"]), "t")
    assert r["valid_until"] == datetime(2030, 1, 1, tzinfo=timezone.utc)
    assert json.loads(r["labels"]) == ["malicious-activity"]
    assert isinstance(r["raw"], str)


def test_ignora_nao_indicadores_e_padroes_sem_igualdade():
    assert normalizar_stix_indicator({"type": "malware", "id": "malware--x"}, "t") is None
    assert normalizar_stix_indicator(_ind("[process:pid > 4]"), "t") is None
    assert normalizar_stix_indicator({**_ind("[ipv4-addr:value = '1.1.1.1']"), "id": None}, "t") is None


def test_aceita_envelope_taxii_e_deduplica():
    obj = _ind("[ipv4-addr:value = '1.1.1.1']")
    assert len(extrair_bundle_stix({"objects": [obj, obj]}, "t")) == 1
    assert len(extrair_bundle_stix({"type": "bundle", "objects": [obj]}, "t")) == 1
    with pytest.raises(CTIErro):
        extrair_bundle_stix(["nao", "objeto"], "t")


def test_exportacao_stix_21_valida_e_deterministica():
    row = {"stix_id": None, "indicator_type": "ipv4-addr", "valor": "1.2.3.4", "pattern": None,
           "confidence": 80, "labels": '["x"]', "valid_until": None,
           "criado_em": datetime(2026, 9, 1, 12, 0, 0, 123456, tzinfo=timezone.utc)}
    a = indicador_para_stix(row, "empresa")
    b = indicador_para_stix(row, "empresa")
    assert a["id"] == b["id"] and a["id"].startswith("indicator--")
    assert a["valid_from"] == "2026-09-01T12:00:00.123Z"
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", a["created"])
    assert a["pattern"] == "[ipv4-addr:value = '1.2.3.4']"
    assert a["labels"] == ["x"]


def test_exportacao_escapa_aspas_no_valor():
    row = {"stix_id": None, "indicator_type": "url", "valor": "http://a/'] OR [x:y = 'z", "pattern": None,
           "confidence": None, "labels": [], "valid_until": None, "criado_em": datetime.now(timezone.utc)}
    padrao = indicador_para_stix(row, "e")["pattern"]
    assert padrao == "[url:value = 'http://a/\\'] OR [x:y = \\'z']"
    assert normalizar_stix_indicator(_ind(padrao), "t")["valor"] == row["valor"]


def _resolver(ip):
    return lambda host, port, type=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "192.168.0.10", "0.0.0.0", "100.64.0.1"])
def test_taxii_recusa_destinos_internos(monkeypatch, ip):
    monkeypatch.setattr(cti.socket, "getaddrinfo", _resolver(ip))
    with pytest.raises(CTIErro):
        validar_url_taxii("https://feed.example/taxii2/collections/x/objects/")


def test_taxii_aceita_destino_publico_https(monkeypatch):
    monkeypatch.setattr(cti.socket, "getaddrinfo", _resolver("93.184.216.34"))
    esquema, host, porta, caminho, ip = validar_url_taxii("https://feed.example:8443/api/objects/?added_after=x")
    assert (esquema, host, porta, ip) == ("https", "feed.example", 8443, "93.184.216.34")
    assert caminho == "/api/objects/?added_after=x"


@pytest.mark.parametrize("url", ["http://feed.example/x", "file:///etc/passwd", "gopher://x/", "https://u:p@feed.example/x", "https:///x"])
def test_taxii_recusa_esquemas_e_formatos(monkeypatch, url):
    monkeypatch.setattr(cti.socket, "getaddrinfo", _resolver("93.184.216.34"))
    with pytest.raises(CTIErro):
        validar_url_taxii(url, permitir_http=False)


def test_buscar_taxii_e_sincrona():
    """Bug V8.1: era async def chamada via asyncio.to_thread (devolvia coroutine)."""
    import inspect
    assert not inspect.iscoroutinefunction(cti.buscar_taxii_collection)
