# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Chave de ativação do agente: endereço do SaaS + token de instalação num único texto.

Formato (lido por agent/internal/ativacao):

    SNT1-<base64url sem padding de JSON {"u": "<backend_url>", "t": "<enr_...>"}>

O cliente cola a chave no instalador e o agente se registra sozinho na empresa
certa. A chave não é credencial de longo prazo: carrega um token de instalação
com validade e número de usos, trocado pela credencial própria do agente na
primeira execução.
"""
from __future__ import annotations

import base64
import json
from urllib.parse import urlsplit

PREFIXO = "SNT1-"
# Só para AVISAR que a chave aponta para esta máquina -- nada aqui abre porta.
_HOSTS_LOCAIS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}  # nosec B104


def gerar(backend_url: str, token: str) -> str:
    dados = json.dumps({"u": backend_url.rstrip("/"), "t": token}, separators=(",", ":")).encode()
    return PREFIXO + base64.urlsafe_b64encode(dados).decode().rstrip("=")


def ler(chave: str) -> dict[str, str]:
    limpa = "".join(chave.split())
    if not limpa.startswith(PREFIXO):
        raise ValueError("chave de ativação inválida")
    corpo = limpa[len(PREFIXO):]
    dados = json.loads(base64.urlsafe_b64decode(corpo + "=" * (-len(corpo) % 4)))
    return {"backend_url": dados["u"], "token": dados["t"]}


def endereco_publico(url_configurada: str, url_da_requisicao: str) -> str:
    """Endereço que o AGENTE vai usar: SENTINELA_URL_BASE_PUBLICA quando
    configurada; senão, o endereço pelo qual o navegador acessou o SaaS."""
    return (url_configurada or url_da_requisicao).rstrip("/")


def aviso_endereco(backend_url: str) -> str | None:
    host = (urlsplit(backend_url).hostname or "").lower()
    if host in _HOSTS_LOCAIS:
        return (f"Esta chave aponta para {backend_url}: só funciona com o agente instalado NESTA máquina. "
                "Para clientes em outras máquinas, configure SENTINELA_URL_BASE_PUBLICA com o endereço "
                "público do SaaS (ex.: https://soc.suaempresa.com.br) e gere a chave de novo.")
    if urlsplit(backend_url).scheme != "https":
        return "Esta chave usa HTTP sem criptografia. Em produção, publique o SaaS com HTTPS."
    return None
