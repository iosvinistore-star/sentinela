# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Telemetria EDR/XDR por tenant."""
from sentinela.repositories.siem import EdrRepositorio


async def registrar_telemetria(sessao, empresa_id, **campos) -> dict:
    return await EdrRepositorio(sessao).inserir(empresa_id, **campos)


async def listar_telemetria(sessao, empresa_id, limite: int) -> list[dict]:
    return await EdrRepositorio(sessao).listar(empresa_id, limite)


async def resumo_24h(sessao, empresa_id) -> dict:
    return {"24h": await EdrRepositorio(sessao).resumo_24h(empresa_id)}
