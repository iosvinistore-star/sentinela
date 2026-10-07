# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testes de services/auditoria.py -- especificamente o mascaramento de
campos sensíveis (item 16 do plano de endurecimento pós-auditoria, ver
core/redacao.py) aplicado em `registrar_evento` antes de gravar `detalhes`
na tabela `auditoria`.
"""

import pytest

from sentinela.db.pool import tenant_scoped_connection
from sentinela.services import auditoria as servico

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_registrar_evento_mascara_campo_sensivel_em_detalhes(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Auditoria Mascaramento")

    async with tenant_scoped_connection(pool, empresa_id) as conn:
        evento = await servico.registrar_evento(
            conn, empresa_id, "teste.evento_sensivel",
            detalhes={"email": "a@b.com", "senha_nova": "hunter2", "token": "eyJabc.def.ghi"},
        )
    # A coluna jsonb chega já decodificada (dict) pelo SQLAlchemy.
    detalhes = evento["detalhes"]
    assert detalhes["email"] == "a@b.com"
    assert detalhes["senha_nova"] == "***REDACTED***"
    assert detalhes["token"] == "***REDACTED***"

    # a linha gravada no banco (não só o dict devolvido em memória) também
    # não contém o valor bruto -- o que importa de verdade é o que fica
    # persistido, já que é dali que um vazamento por dump/backup viria.
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        linha = await conn.fetchrow(
            "SELECT detalhes::text AS detalhes_texto FROM auditoria WHERE acao = 'teste.evento_sensivel'"
        )
    assert "hunter2" not in linha["detalhes_texto"]
    assert "eyJabc.def.ghi" not in linha["detalhes_texto"]


@pytest.mark.asyncio
async def test_registrar_evento_preserva_detalhes_sem_campo_sensivel(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Auditoria Sem Segredo")

    async with tenant_scoped_connection(pool, empresa_id) as conn:
        evento = await servico.registrar_evento(
            conn, empresa_id, "teste.evento_normal",
            detalhes={"ip": "203.0.113.10", "motivo": "teste comum"},
        )
    assert evento["detalhes"] == {"ip": "203.0.113.10", "motivo": "teste comum"}
