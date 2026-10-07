# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""CTI: importação/exportação STIX 2.1 e busca TAXII 2.1 com proteção SSRF.

Correções da V8.2 (ver RELATORIO_REVISAO_V8_2.md):

* ``buscar_taxii_collection`` era ``async def`` mas era chamada via
  ``asyncio.to_thread`` -- o thread devolvia um *coroutine object* (nunca
  aguardado) e ``extrair_bundle_stix`` quebrava com AttributeError. A
  importação TAXII nunca funcionou. Agora é síncrona (roda no thread).
* A URL TAXII vinha do usuário sem nenhuma restrição -- SSRF clássico
  (metadados de nuvem 169.254.169.254, localhost, rede interna, redirects).
  Agora: só HTTPS (HTTP apenas com opt-in explícito), resolve o DNS e
  recusa IP privado/loopback/link-local/reservado, fixa a conexão no IP
  validado (sem janela de DNS rebinding), não segue redirect e limita o
  tamanho da resposta.
* O extrator de valor só entendia ``='valor'`` sem espaços. Feeds reais
  usam ``[ipv4-addr:value = '1.2.3.4']`` -- o "valor" gravado era o
  padrão inteiro e a correlação CTI nunca casava com nada.
* ``valid_until`` (string ISO) ia direto para uma coluna TIMESTAMPTZ e
  ``labels`` (lista) direto para JSONB -- asyncpg recusa os dois; qualquer
  importação STIX real falhava com 500.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

__all__ = [
    "CTIErro",
    "normalizar_stix_indicator",
    "extrair_bundle_stix",
    "buscar_taxii_collection",
    "validar_url_taxii",
    "indicador_para_stix",
    "NAMESPACE_STIX",
]


class CTIErro(ValueError):
    """Entrada CTI inválida ou destino TAXII recusado."""


# Namespace fixo para IDs STIX determinísticos (uuid5) na exportação: o mesmo
# indicador exportado duas vezes mantém o mesmo id -- consumidores STIX/TAXII
# deduplicam por id; um uuid4 novo a cada exportação duplicava tudo neles.
NAMESPACE_STIX = uuid.UUID("7c3e0c5a-6f0e-4a8e-9a57-5e4f3b1d2c10")

_TAMANHO_MAX_RESPOSTA = int(os.getenv("SENTINELA_TAXII_MAX_BYTES", str(20 * 1024 * 1024)))
_TIMEOUT_PADRAO = 10.0

# Comparação simples do STIX Patterning: [objeto:propriedade = 'valor']
# (aspas simples com escape \' e \\ conforme a especificação).
_PADRAO_COMPARACAO = re.compile(
    r"\[\s*(?P<objeto>[a-z0-9\-]+):(?P<prop>[A-Za-z0-9_.\-']+)\s*(?:=|LIKE|MATCHES)\s*'(?P<valor>(?:[^'\\]|\\.)*)'\s*\]",
    re.IGNORECASE,
)

# tipo interno -> (objeto STIX, propriedade) para exportação.
_TIPO_PARA_STIX = {
    "ipv4-addr": ("ipv4-addr", "value"),
    "ipv4": ("ipv4-addr", "value"),
    "ip": ("ipv4-addr", "value"),
    "ipv6-addr": ("ipv6-addr", "value"),
    "ipv6": ("ipv6-addr", "value"),
    "domain-name": ("domain-name", "value"),
    "domain": ("domain-name", "value"),
    "url": ("url", "value"),
    "email-addr": ("email-addr", "value"),
    "email": ("email-addr", "value"),
    "sha256": ("file", "hashes.'SHA-256'"),
    "md5": ("file", "hashes.MD5"),
    "sha1": ("file", "hashes.'SHA-1'"),
}


def _parse_timestamp(valor: Any) -> datetime | None:
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


def _desescapar(valor: str) -> str:
    return re.sub(r"\\(.)", r"\1", valor)


def normalizar_stix_indicator(obj: dict[str, Any], empresa_id: str) -> dict[str, Any] | None:
    """Converte um SDO ``indicator`` STIX 2.x em linha de ``cti_indicadores``.

    Devolve None para objetos que não são indicadores, que não têm id, ou cujo
    padrão não contém nenhuma comparação de igualdade reconhecível (esses não
    servem para a correlação por IOC exato e só poluiriam a tabela).
    """
    if not isinstance(obj, dict) or obj.get("type") != "indicator" or not obj.get("pattern"):
        return None
    stix_id = obj.get("id")
    if not isinstance(stix_id, str) or not stix_id.startswith("indicator--"):
        return None
    pattern = str(obj["pattern"]).strip()
    m = _PADRAO_COMPARACAO.search(pattern)
    if not m:
        return None
    valor = _desescapar(m.group("valor")).strip()
    if not valor:
        return None
    objeto = m.group("objeto").lower()
    prop = m.group("prop")
    indicator_type = objeto
    if objeto == "file" and "hashes" in prop.lower():
        p = prop.upper().replace("'", "").replace("-", "")
        indicator_type = "sha256" if "SHA256" in p else "sha1" if "SHA1" in p else "md5" if "MD5" in p else "file-hash"
        valor = valor.lower()

    confidence = obj.get("confidence")
    if not isinstance(confidence, int) or not 0 <= confidence <= 100:
        confidence = None
    labels = obj.get("labels") or []
    if not isinstance(labels, list):
        labels = []
    return {
        "empresa_id": empresa_id,
        "stix_id": stix_id[:255],
        "tipo": "STIX",
        "indicator_type": indicator_type[:80],
        "valor": valor[:2048],
        "pattern": pattern[:4096],
        "confidence": confidence,
        "valid_until": _parse_timestamp(obj.get("valid_until")),
        "labels": json.dumps([str(x)[:120] for x in labels[:50]]),
        "raw": json.dumps(obj)[:200_000],
    }


def extrair_bundle_stix(payload: Any, empresa_id: str) -> list[dict[str, Any]]:
    """Aceita bundle STIX, envelope TAXII 2.1 (``{"objects": [...]}``) ou objeto isolado."""
    if not isinstance(payload, dict):
        raise CTIErro("payload STIX/TAXII deve ser um objeto JSON")
    if payload.get("type") == "bundle" or ("objects" in payload and "type" not in payload):
        objetos = payload.get("objects") or []
    else:
        objetos = [payload]
    if not isinstance(objetos, list):
        raise CTIErro("'objects' deve ser uma lista")
    vistos: set[str] = set()
    saida: list[dict[str, Any]] = []
    for obj in objetos:
        linha = normalizar_stix_indicator(obj, empresa_id)
        if linha and linha["stix_id"] not in vistos:
            vistos.add(linha["stix_id"])
            saida.append(linha)
    return saida


# --------------------------------------------------------------------------
# TAXII com proteção SSRF
# --------------------------------------------------------------------------

def _ip_permitido(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
        or ip.is_reserved or ip.is_unspecified or not ip.is_global
    )


def validar_url_taxii(url: str, permitir_http: bool | None = None) -> tuple[str, str, int, str, str]:
    """Valida a URL e resolve o destino. Devolve (esquema, host, porta, caminho, ip).

    Levanta CTIErro se o destino não for permitido. ``permitir_http`` vem de
    SENTINELA_TAXII_PERMITIR_HTTP (padrão: só HTTPS).
    """
    if permitir_http is None:
        permitir_http = os.getenv("SENTINELA_TAXII_PERMITIR_HTTP", "false").lower() == "true"
    if not isinstance(url, str) or len(url) > 2048:
        raise CTIErro("URL TAXII inválida")
    partes = urlsplit(url.strip())
    esquema = partes.scheme.lower()
    if esquema not in ({"https", "http"} if permitir_http else {"https"}):
        raise CTIErro("URL TAXII deve usar HTTPS")
    if partes.username or partes.password:
        raise CTIErro("credenciais embutidas na URL não são aceitas")
    host = partes.hostname
    if not host:
        raise CTIErro("URL TAXII sem host")
    try:
        porta = partes.port or (443 if esquema == "https" else 80)
    except ValueError as exc:
        raise CTIErro("porta inválida") from exc
    try:
        infos = socket.getaddrinfo(host, porta, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise CTIErro("não foi possível resolver o host TAXII") from exc
    ips = {ipaddress.ip_address(i[4][0].split("%")[0]) for i in infos}
    if not ips or not all(_ip_permitido(ip) for ip in ips):
        raise CTIErro("destino TAXII aponta para endereço interno/reservado")
    caminho = partes.path or "/"
    if partes.query:
        caminho += "?" + partes.query
    return esquema, host, porta, caminho, str(sorted(ips, key=str)[0])


class _HTTPSFixo(http.client.HTTPSConnection):
    """Conecta no IP já validado, mas faz SNI/verificação de certificado pelo hostname."""

    def __init__(self, host: str, ip: str, porta: int, timeout: float):
        super().__init__(host, porta, timeout=timeout, context=ssl.create_default_context())
        self._ip = ip

    def connect(self):  # noqa: D401 - sobrescreve http.client
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _HTTPFixo(http.client.HTTPConnection):
    def __init__(self, host: str, ip: str, porta: int, timeout: float):
        super().__init__(host, porta, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


def buscar_taxii_collection(url: str, timeout: float = _TIMEOUT_PADRAO, api_key: str | None = None) -> dict[str, Any]:
    """GET síncrono (use via ``asyncio.to_thread``) de uma coleção TAXII 2.1."""
    esquema, host, porta, caminho, ip = validar_url_taxii(url)
    cls = _HTTPSFixo if esquema == "https" else _HTTPFixo
    conn = cls(host, ip, porta, timeout)
    headers = {"Accept": "application/taxii+json;version=2.1, application/stix+json;version=2.1, application/json",
               "User-Agent": "Sentinela-CTI/8.2"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    try:
        conn.request("GET", caminho, headers=headers)
        resp = conn.getresponse()
        if 300 <= resp.status < 400:
            raise CTIErro("servidor TAXII respondeu com redirect (não seguido por segurança)")
        if resp.status != 200:
            raise CTIErro(f"servidor TAXII respondeu HTTP {resp.status}")
        corpo = resp.read(_TAMANHO_MAX_RESPOSTA + 1)
        if len(corpo) > _TAMANHO_MAX_RESPOSTA:
            raise CTIErro("resposta TAXII excede o tamanho máximo")
    except (OSError, http.client.HTTPException) as exc:
        raise CTIErro(f"falha ao consultar servidor TAXII: {exc.__class__.__name__}") from exc
    finally:
        conn.close()
    try:
        return json.loads(corpo.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CTIErro("resposta TAXII não é JSON válido") from exc


# --------------------------------------------------------------------------
# Exportação STIX 2.1
# --------------------------------------------------------------------------

def _ts_stix(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _escapar_stix(valor: str) -> str:
    return valor.replace("\\", "\\\\").replace("'", "\\'")


def indicador_para_stix(row: dict[str, Any], empresa_id: str) -> dict[str, Any]:
    """Linha de ``cti_indicadores`` -> SDO ``indicator`` STIX 2.1 válido."""
    criado = row["criado_em"]
    pattern = row.get("pattern")
    if not pattern or not _PADRAO_COMPARACAO.search(str(pattern)):
        objeto, prop = _TIPO_PARA_STIX.get(str(row.get("indicator_type") or "").lower(), ("x-sentinela-ioc", "value"))
        pattern = f"[{objeto}:{prop} = '{_escapar_stix(str(row['valor']))}']"
    stix_id = row.get("stix_id")
    if not stix_id or not str(stix_id).startswith("indicator--"):
        chave = "{}:{}:{}".format(empresa_id, row.get("indicator_type"), row["valor"])
        stix_id = f"indicator--{uuid.uuid5(NAMESPACE_STIX, chave)}"
    obj: dict[str, Any] = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": stix_id,
        "created": _ts_stix(criado),
        "modified": _ts_stix(criado),
        "valid_from": _ts_stix(criado),
        "pattern_type": "stix",
        "pattern": pattern,
    }
    if row.get("valid_until"):
        obj["valid_until"] = _ts_stix(row["valid_until"])
    if row.get("confidence") is not None:
        obj["confidence"] = int(row["confidence"])
    labels = row.get("labels")
    if isinstance(labels, str):
        try:
            labels = json.loads(labels)
        except json.JSONDecodeError:
            labels = []
    if labels:
        obj["labels"] = [str(x) for x in labels]
    return obj
