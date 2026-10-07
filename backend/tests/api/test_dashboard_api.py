# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""GET /api/v1/dashboard -- métricas operacionais, sempre tenant-scoped.

Não havia nenhum teste cobrindo esta rota antes -- ver
services/dashboard.py:obter_dashboard, que passou a receber `empresa_id`
explicitamente (defesa em profundidade além da RLS, ver o docstring da
função). Estes testes cobrem tanto o caminho feliz quanto a garantia de
isolamento entre empresas que a mudança reforça.
"""
import pytest

from tests.api.conftest_api import logar
from tests.sql_cru import executar

pytestmark = pytest.mark.integration


async def _criar_incidente_direto(db, empresa_id, ip, severidade="HIGH", pontuacao=70):
    async with db.superadmin_session() as conn:
        await executar(conn, """
            INSERT INTO incidentes (empresa_id, incident_id, ip, severidade, pontuacao_risco, ataques)
            VALUES ($1, $2, $3, $4, $5, '["SQL Injection (SQLi)"]'::jsonb)
            """,
            empresa_id, f"INC-DASH-{ip}", ip, severidade, pontuacao,
        )


@pytest.mark.asyncio
async def test_dashboard_conta_so_incidentes_da_propria_empresa(client, usuario_de_teste, analista_de_teste, db):
    """usuario_de_teste e analista_de_teste são de empresas DIFERENTES
    (ver conftest_api.py) -- um incidente criado na empresa do analista não
    pode aparecer nas métricas do admin da outra empresa. Sem o filtro
    explícito por empresa_id em obter_dashboard, isto ainda funcionaria
    hoje (a RLS já cobre) -- o teste serve pra travar o comportamento
    também nesta camada."""
    await _criar_incidente_direto(db, usuario_de_teste["empresa_id"], "203.0.113.80")
    await _criar_incidente_direto(db, analista_de_teste["empresa_id"], "203.0.113.81")
    await _criar_incidente_direto(db, analista_de_teste["empresa_id"], "203.0.113.82")

    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    resp = await client.get("/api/v1/dashboard")
    assert resp.status_code == 200
    corpo = resp.json()
    assert corpo["metricas"]["total"] == 1
    assert len(corpo["recentes"]) == 1
    # ip::text de uma coluna `inet` inclui a máscara (/32 para um host
    # único) -- mesma formatação que o resto da API já expõe.
    assert corpo["recentes"][0]["ip"] == "203.0.113.80/32"
    assert {ip_info["ip"] for ip_info in corpo["top_ips"]} == {"203.0.113.80/32"}


@pytest.mark.asyncio
async def test_dashboard_sem_sessao_e_401(client):
    resp = await client.get("/api/v1/dashboard")
    assert resp.status_code == 401
