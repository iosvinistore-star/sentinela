# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""GET /api/v1/reputacao/{ip} -- cache em Postgres com TTL (ver services/reputacao.py)."""
from fastapi import APIRouter, Depends, HTTPException

from sentinela.auth.dependencies import conexao_tenant, exigir_login
from sentinela.services import reputacao as servico
from sentinela.util import ip_valido

router = APIRouter(prefix="/reputacao", tags=["reputacao"])


@router.get("/{ip}")
async def consultar_reputacao(ip: str, usuario: dict = Depends(exigir_login), conn=Depends(conexao_tenant)):
    # Valida ANTES de qualquer I/O: sem isso, uma string arbitrária no path
    # (não necessariamente um IP) chegava a construir a URL da consulta ao
    # VirusTotal (ver core/reputacao.py:consultar_virustotal, que interpola
    # `ip` numa f-string sem escaping) e a um INSERT numa coluna Postgres do
    # tipo `inet` -- que rejeita qualquer coisa não-IP com uma exceção não
    # tratada (500), já que `reputacao_cache.ip` não aceitava valor inválido.
    # `ip_valido` (ver sentinela/util.py) também rejeita zone-id de IPv6,
    # que `ipaddress.ip_address` sozinho aceitava mas `inet` não entende.
    if ip_valido(ip) is None:
        raise HTTPException(status_code=422, detail="IP inválido")
    return await servico.consultar_reputacao_ip(conn, usuario["empresa_id"], ip)
