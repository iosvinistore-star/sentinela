# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
import pytest

from sentinela.services import incidentes as servico
from sentinela.services import usuarios as servico_usuarios
from tests.sql_cru import buscar

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_criar_e_listar_incidente(db, empresa_factory):
    empresa_id = await empresa_factory("Empresa Incidentes")
    risco = {"severity": "HIGH", "score": 80}

    async with db.tenant_session(empresa_id) as conn:
        criado = await servico.criar_incidente(conn, empresa_id, "203.0.113.9", risco, ["SQL Injection (SQLi)"])
        assert criado is not None
        assert criado["ip"] == "203.0.113.9"
        assert criado["severidade"] == "HIGH"
        assert criado["ataques"] == ["SQL Injection (SQLi)"]
        assert criado["status"] == "OPEN"

        listados = await servico.listar_incidentes(conn)
        assert len(listados) == 1
        assert listados[0]["incident_id"] == criado["incident_id"]


@pytest.mark.asyncio
async def test_listar_incidentes_filtra_por_status(db, empresa_factory):
    empresa_id = await empresa_factory("Empresa Incidentes Status")
    risco = {"severity": "CRITICAL", "score": 95}

    async with db.tenant_session(empresa_id) as conn:
        criado = await servico.criar_incidente(conn, empresa_id, "203.0.113.10", risco, ["Command Injection"])
        await servico.atualizar_status(conn, empresa_id, criado["incident_id"], "RESOLVIDO", "verificado manualmente")

        abertos = await servico.listar_incidentes(conn, status="OPEN")
        resolvidos = await servico.listar_incidentes(conn, status="RESOLVIDO")

    assert abertos == []
    assert len(resolvidos) == 1
    assert resolvidos[0]["observacoes"] == "verificado manualmente"


@pytest.mark.asyncio
async def test_obter_incidente_inexistente_retorna_none(db, empresa_factory):
    empresa_id = await empresa_factory("Empresa Incidentes Vazia")
    async with db.tenant_session(empresa_id) as conn:
        assert await servico.obter_incidente(conn, empresa_id, "INC-NAO-EXISTE") is None


@pytest.mark.asyncio
async def test_incidente_de_uma_empresa_nao_aparece_para_outra(db, empresa_factory):
    empresa_a = await empresa_factory("Empresa Incidentes A")
    empresa_b = await empresa_factory("Empresa Incidentes B")
    risco = {"severity": "HIGH", "score": 70}

    async with db.tenant_session(empresa_a) as conn:
        await servico.criar_incidente(conn, empresa_a, "203.0.113.11", risco, ["XSS"])

    async with db.tenant_session(empresa_b) as conn:
        listados = await servico.listar_incidentes(conn)

    assert listados == []


@pytest.mark.asyncio
async def test_dois_incidentes_do_mesmo_ip_no_mesmo_segundo_nao_colidem(db, empresa_factory):
    """Item 17 do plano de endurecimento -- regressão do formato legado
    INC-YYYYMMDD-<ip8>-HHMMSS, que colidia (e descartava silenciosamente o
    segundo incidente via ON CONFLICT DO NOTHING) sempre que o MESMO IP
    gerava dois incidentes dentro do MESMO segundo (ex.: dois relatórios de
    upload de log analisados em sequência rápida). Ver
    services/incidentes.py:_gerar_incident_id."""
    empresa_id = await empresa_factory("Empresa Incidentes Colisao")
    risco = {"severity": "CRITICAL", "score": 95}

    async with db.tenant_session(empresa_id) as conn:
        primeiro = await servico.criar_incidente(conn, empresa_id, "203.0.113.50", risco, ["SQL Injection (SQLi)"])
        segundo = await servico.criar_incidente(conn, empresa_id, "203.0.113.50", risco, ["SQL Injection (SQLi)"])

        assert primeiro is not None
        assert segundo is not None
        assert primeiro["incident_id"] != segundo["incident_id"]

        listados = await servico.listar_incidentes(conn)
        assert len(listados) == 2


@pytest.mark.asyncio
async def test_obter_incidente_com_empresa_id_errado_retorna_none_mesmo_existindo(db, empresa_factory):
    """
    Defesa em profundidade de `services/incidentes.py`: mesmo que a
    conexão continuasse tenant-scoped para a empresa dona do incidente (ou
    seja, mesmo que a RLS deixasse passar), o filtro explícito
    `WHERE empresa_id = $1` em `obter_incidente`/`atualizar_status` por si
    só já rejeita um `empresa_id` que não bate com o do incidente.
    """
    empresa_a = await empresa_factory("Empresa Incidentes C")
    empresa_b = await empresa_factory("Empresa Incidentes D")
    risco = {"severity": "HIGH", "score": 70}

    async with db.tenant_session(empresa_a) as conn:
        criado = await servico.criar_incidente(conn, empresa_a, "203.0.113.12", risco, ["XSS"])
        assert await servico.obter_incidente(conn, empresa_b, criado["incident_id"]) is None
        assert await servico.atualizar_status(conn, empresa_b, criado["incident_id"], "RESOLVIDO") is None
        # com o empresa_id correto, continua funcionando normalmente
        assert await servico.obter_incidente(conn, empresa_a, criado["incident_id"]) is not None


@pytest.mark.asyncio
async def test_atualizar_status_registra_ator_humano(db, empresa_factory):
    """Modo autônomo (migrations/0014_autonomia_operacional.sql) --
    `atualizar_status` com `usuario_id` grava `em_andamento_por_usuario_id`
    (na primeira vez que o status vira EM_ANDAMENTO) e `resolvido_por` =
    'humano' quando o status final é RESOLVIDO/FALSO_POSITIVO -- a
    auto-triagem (services/automacao.py) nunca passa por esta função, só
    grava 'sistema' via SQL direto."""
    empresa_id = await empresa_factory("Empresa Incidentes Ator Humano")
    risco = {"severity": "HIGH", "score": 70}

    async with db.tenant_session(empresa_id) as conn:
        criado = await servico_usuarios.criar_usuario(conn, empresa_id, "analista@teste.com", "analista", "SenhaForte123!")
        incidente = await servico.criar_incidente(conn, empresa_id, "203.0.113.60", risco, ["XSS"])
        assert incidente["em_andamento_por_usuario_id"] is None
        assert incidente["resolvido_por"] is None

        em_andamento = await servico.atualizar_status(
            conn, empresa_id, incidente["incident_id"], "EM_ANDAMENTO", usuario_id=criado["id"],
        )
        assert str(em_andamento["em_andamento_por_usuario_id"]) == criado["id"]
        assert em_andamento["resolvido_por"] is None

        resolvido = await servico.atualizar_status(
            conn, empresa_id, incidente["incident_id"], "RESOLVIDO", usuario_id=criado["id"],
        )
        assert resolvido["resolvido_por"] == "humano"
        # em_andamento_por_usuario_id preservado (quem pegou primeiro),
        # mesmo depois do status avançar para RESOLVIDO.
        assert str(resolvido["em_andamento_por_usuario_id"]) == criado["id"]


@pytest.mark.asyncio
async def test_atualizar_status_grava_evento_de_auditoria(db, empresa_factory):
    empresa_id = await empresa_factory("Empresa Incidentes Auditoria Status")
    risco = {"severity": "HIGH", "score": 70}

    async with db.tenant_session(empresa_id) as conn:
        incidente = await servico.criar_incidente(conn, empresa_id, "203.0.113.61", risco, ["XSS"])
        await servico.atualizar_status(conn, empresa_id, incidente["incident_id"], "FALSO_POSITIVO")

        eventos = await buscar(conn, "SELECT * FROM auditoria WHERE empresa_id = $1 AND acao = 'incidente.status_atualizado'", empresa_id,
        )
    assert len(eventos) == 1
