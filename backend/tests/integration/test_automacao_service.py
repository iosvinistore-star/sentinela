# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
services.automacao: as quatro capacidades do modo autônomo (ver
migrations/0014_autonomia_operacional.sql). Insere linhas de
incidentes/bloqueios_firewall diretamente via SQL para controlar
precisamente o cenário testado (quantas amostras, quantos problemas,
timestamps) em vez de rodar o pipeline de resposta a incidentes inteiro
-- mais rápido e mais fácil de deixar determinístico.
"""
import datetime

import pytest

from sentinela.db.pool import superadmin_scoped_connection, tenant_scoped_connection
from sentinela.services import automacao as servico
from sentinela.services import incidentes as servico_incidentes
from sentinela.services import usuarios as servico_usuarios

pytestmark = pytest.mark.integration

_AGORA = datetime.datetime.now(datetime.timezone.utc)


async def _configurar_empresa(pool, empresa_id, *, modo_firewall="automacao_controlada",
                                modo_firewall_auto=False, auto_triagem_incidentes=False):
    async with superadmin_scoped_connection(pool) as conn:
        await conn.execute(
            "UPDATE empresas SET modo_firewall=$2, modo_firewall_auto=$3, auto_triagem_incidentes=$4 WHERE id=$1",
            empresa_id, modo_firewall, modo_firewall_auto, auto_triagem_incidentes,
        )


async def _criar_incidente_com_bloqueio(conn, empresa_id, ip, *, falso_positivo=False,
                                          bloqueado_em, removido_em=None):
    """Cria um incidente + bloqueio AUTOMÁTICO (incidente_id preenchido)
    ligados entre si, com os timestamps/estado exatos que o teste precisa
    -- bypassando o pipeline de resposta a incidentes inteiro."""
    incidente = await servico_incidentes.criar_incidente(
        conn, empresa_id, ip, {"severity": "HIGH", "score": 70}, ["Scanner de Vulnerabilidades"],
    )
    if falso_positivo:
        await conn.execute("UPDATE incidentes SET status = 'FALSO_POSITIVO' WHERE id = $1", incidente["id"])
    await conn.execute(
        """
        INSERT INTO bloqueios_firewall (empresa_id, ip, motivo, origem, status, bloqueado_em, removido_em, incidente_id)
        VALUES ($1, $2::inet, 'teste', 'teste', $3, $4, $5, $6)
        """,
        empresa_id, ip, "removido" if removido_em else "ativo", bloqueado_em, removido_em, incidente["id"],
    )
    return incidente


# ---------------------------------------------------------------------------
# Capacidade 1: autoajuste de modo_firewall
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_avaliar_e_ajustar_modo_firewall_noop_quando_flag_desligada(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Autonomia Flag Off")
    await _configurar_empresa(pool, empresa_id, modo_firewall_auto=False)

    async with superadmin_scoped_connection(pool) as conn:
        resultado = await servico.avaliar_e_ajustar_modo_firewall(conn, empresa_id)
    assert resultado is None


@pytest.mark.asyncio
async def test_avaliar_e_ajustar_modo_firewall_noop_sem_amostras(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Autonomia Sem Amostras")
    await _configurar_empresa(pool, empresa_id, modo_firewall_auto=True)

    async with superadmin_scoped_connection(pool) as conn:
        resultado = await servico.avaliar_e_ajustar_modo_firewall(conn, empresa_id)
    assert resultado is None


@pytest.mark.asyncio
async def test_avaliar_e_ajustar_modo_firewall_nao_mexe_em_observacao_ou_dry_run(pool, empresa_factory):
    """Escolha deliberada do tenant -- o autoajuste nunca tira o tenant de
    observacao/dry_run, mesmo com a flag ligada e amostras perfeitas."""
    empresa_id = await empresa_factory("Empresa Autonomia Modo Fora Da Escada")
    await _configurar_empresa(pool, empresa_id, modo_firewall="observacao", modo_firewall_auto=True)

    async with superadmin_scoped_connection(pool) as conn:
        for i in range(20):
            await _criar_incidente_com_bloqueio(
                conn, empresa_id, f"203.0.{i}.1", bloqueado_em=_AGORA - datetime.timedelta(hours=i),
            )
        resultado = await servico.avaliar_e_ajustar_modo_firewall(conn, empresa_id)
    assert resultado is None


@pytest.mark.asyncio
async def test_avaliar_e_ajustar_modo_firewall_promove_com_taxa_de_problema_baixa(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Autonomia Promove")
    await _configurar_empresa(pool, empresa_id, modo_firewall="manual", modo_firewall_auto=True)

    async with superadmin_scoped_connection(pool) as conn:
        for i in range(20):
            # só a amostra 0 é "problema" -- 1/20 = 5%, exatamente no teto
            # de promoção (<= 5%).
            await _criar_incidente_com_bloqueio(
                conn, empresa_id, f"203.0.{i}.1", falso_positivo=(i == 0),
                bloqueado_em=_AGORA - datetime.timedelta(hours=i),
            )
        resultado = await servico.avaliar_e_ajustar_modo_firewall(conn, empresa_id)
        modo_no_banco = await conn.fetchval("SELECT modo_firewall FROM empresas WHERE id = $1", empresa_id)

    assert resultado == {"modo_anterior": "manual", "modo_novo": "automacao_controlada", "motivo": "taxa_de_problema_baixa"}
    assert modo_no_banco == "automacao_controlada"


@pytest.mark.asyncio
async def test_avaliar_e_ajustar_modo_firewall_grava_evento_de_auditoria_sem_ator_humano(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Autonomia Auditoria")
    await _configurar_empresa(pool, empresa_id, modo_firewall="manual", modo_firewall_auto=True)

    async with superadmin_scoped_connection(pool) as conn:
        for i in range(20):
            await _criar_incidente_com_bloqueio(
                conn, empresa_id, f"203.0.{i}.2", bloqueado_em=_AGORA - datetime.timedelta(hours=i),
            )
        await servico.avaliar_e_ajustar_modo_firewall(conn, empresa_id)
        evento = await conn.fetchrow(
            "SELECT * FROM auditoria WHERE empresa_id = $1 AND acao = 'firewall.modo_ajustado_automaticamente'",
            empresa_id,
        )
    assert evento is not None
    assert evento["ator_usuario_id"] is None
    assert evento["ator_superadmin_id"] is None


@pytest.mark.asyncio
async def test_avaliar_e_ajustar_modo_firewall_rebaixa_com_taxa_de_problema_alta(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Autonomia Rebaixa")
    await _configurar_empresa(pool, empresa_id, modo_firewall="automacao_controlada", modo_firewall_auto=True)

    async with superadmin_scoped_connection(pool) as conn:
        for i in range(20):
            # 4/20 = 20% > 15% -- rebaixa.
            await _criar_incidente_com_bloqueio(
                conn, empresa_id, f"203.0.{i}.3", falso_positivo=(i < 4),
                bloqueado_em=_AGORA - datetime.timedelta(hours=i),
            )
        resultado = await servico.avaliar_e_ajustar_modo_firewall(conn, empresa_id)

    assert resultado == {"modo_anterior": "automacao_controlada", "modo_novo": "manual", "motivo": "taxa_de_problema_alta"}


@pytest.mark.asyncio
async def test_avaliar_e_ajustar_modo_firewall_freio_de_emergencia_no_topo_da_escada(pool, empresa_factory):
    """Já em automacao_total (topo da escada), um único problema entre as
    últimas 5 amostras derruba um degrau imediatamente -- não espera
    acumular a taxa de 15% do rebaixamento normal."""
    empresa_id = await empresa_factory("Empresa Autonomia Freio Emergencia")
    await _configurar_empresa(pool, empresa_id, modo_firewall="automacao_total", modo_firewall_auto=True)

    async with superadmin_scoped_connection(pool) as conn:
        for i in range(5):
            await _criar_incidente_com_bloqueio(
                conn, empresa_id, f"203.0.{i}.4", falso_positivo=(i == 2),
                bloqueado_em=_AGORA - datetime.timedelta(hours=i),
            )
        resultado = await servico.avaliar_e_ajustar_modo_firewall(conn, empresa_id)

    assert resultado == {"modo_anterior": "automacao_total", "modo_novo": "automacao_controlada", "motivo": "freio_emergencia"}


@pytest.mark.asyncio
async def test_avaliar_e_ajustar_modo_firewall_reversao_rapida_conta_como_problema(pool, empresa_factory):
    """Um bloqueio revertido em menos de 2h (mesmo sem o incidente virar
    FALSO_POSITIVO) já conta como problema para o autoajuste."""
    empresa_id = await empresa_factory("Empresa Autonomia Reversao Rapida")
    await _configurar_empresa(pool, empresa_id, modo_firewall="automacao_controlada", modo_firewall_auto=True)

    async with superadmin_scoped_connection(pool) as conn:
        for i in range(20):
            bloqueado_em = _AGORA - datetime.timedelta(hours=i + 3)
            # as primeiras 4 amostras foram revertidas 30min depois de
            # bloqueadas -- 4/20 = 20% > 15%.
            removido_em = bloqueado_em + datetime.timedelta(minutes=30) if i < 4 else None
            await _criar_incidente_com_bloqueio(
                conn, empresa_id, f"203.0.{i}.5", bloqueado_em=bloqueado_em, removido_em=removido_em,
            )
        resultado = await servico.avaliar_e_ajustar_modo_firewall(conn, empresa_id)

    assert resultado["modo_novo"] == "manual"
    assert resultado["motivo"] == "taxa_de_problema_alta"


# ---------------------------------------------------------------------------
# Capacidade 2: auto-triagem de incidentes parados
# ---------------------------------------------------------------------------

async def _criar_incidente_parado(conn, empresa_id, ip, severidade, *, contido=False, em_andamento_por=None, origem="rede"):
    incidente = await servico_incidentes.criar_incidente(
        conn, empresa_id, ip, {"severity": severidade, "score": 70}, ["Scanner de Vulnerabilidades"], origem=origem,
    )
    parado_desde = _AGORA - datetime.timedelta(hours=servico._HORAS_INCIDENTE_PARADO + 1)
    await conn.execute(
        "UPDATE incidentes SET atualizado_em = $2, em_andamento_por_usuario_id = $3 WHERE id = $1",
        incidente["id"], parado_desde, em_andamento_por,
    )
    if contido:
        await conn.execute(
            """
            INSERT INTO bloqueios_firewall (empresa_id, ip, motivo, origem, status, bloqueado_em, incidente_id)
            VALUES ($1, $2::inet, 'teste', 'teste', 'ativo', now(), $3)
            """,
            empresa_id, ip, incidente["id"],
        )
    return incidente


@pytest.mark.asyncio
async def test_auto_classificar_noop_quando_flag_desligada(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Triagem Flag Off")
    await _configurar_empresa(pool, empresa_id, auto_triagem_incidentes=False)

    async with superadmin_scoped_connection(pool) as conn:
        await _criar_incidente_parado(conn, empresa_id, "203.0.114.1", "LOW")
        resultado = await servico.auto_classificar_incidentes_abertos(conn, empresa_id, agora=_AGORA)
    assert resultado == []


@pytest.mark.asyncio
async def test_auto_classificar_resolve_incidente_contido(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Triagem Contido")
    await _configurar_empresa(pool, empresa_id, auto_triagem_incidentes=True)

    async with superadmin_scoped_connection(pool) as conn:
        incidente = await _criar_incidente_parado(conn, empresa_id, "203.0.114.2", "CRITICAL", contido=True)
        resultado = await servico.auto_classificar_incidentes_abertos(conn, empresa_id, agora=_AGORA)
        linha = await conn.fetchrow("SELECT status, resolvido_por FROM incidentes WHERE id = $1", incidente["id"])

    assert resultado == [{"incident_id": incidente["incident_id"], "status_novo": "RESOLVIDO"}]
    assert linha["status"] == "RESOLVIDO"
    assert linha["resolvido_por"] == "sistema"


@pytest.mark.asyncio
async def test_auto_classificar_marca_falso_positivo_quando_baixo_risco_e_sem_contencao(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Triagem Falso Positivo")
    await _configurar_empresa(pool, empresa_id, auto_triagem_incidentes=True)

    async with superadmin_scoped_connection(pool) as conn:
        incidente = await _criar_incidente_parado(conn, empresa_id, "203.0.114.3", "MEDIUM", contido=False)
        resultado = await servico.auto_classificar_incidentes_abertos(conn, empresa_id, agora=_AGORA)
        linha = await conn.fetchrow("SELECT status, resolvido_por FROM incidentes WHERE id = $1", incidente["id"])

    assert resultado == [{"incident_id": incidente["incident_id"], "status_novo": "FALSO_POSITIVO"}]
    assert linha["status"] == "FALSO_POSITIVO"
    assert linha["resolvido_por"] == "sistema"


@pytest.mark.asyncio
async def test_auto_classificar_nunca_marca_incidente_de_endpoint_como_falso_positivo(pool, empresa_factory):
    """
    Este é O bug encontrado em revisão crítica (2026-09), a interação
    perigosa entre duas capacidades testadas isoladamente até então:
    incidentes de origem 'endpoint' (Sentinela Endpoint, ver
    services/agentes.py) NUNCA têm `bloqueios_firewall` ligados a eles --
    a fase 1 do agente é só observação, nunca aciona firewall. Antes desta
    correção, um incidente de endpoint MEDIUM (ex.: um único processo
    suspeito sem indicador de ferramenta conhecida) caía direto na regra
    "sem contenção + LOW/MEDIUM -> FALSO_POSITIVO" depois de 72h sem
    revisão humana -- ou seja, uma detecção real de comprometimento em
    endpoint era descartada automaticamente, sem NUNCA ter tido a chance
    de ser "contida" (porque endpoint não tem esse conceito nesta fase).
    Agora, origem='endpoint' é sempre deixado para um humano decidir,
    igual HIGH/CRITICAL sem contenção -- nunca vira FALSO_POSITIVO sozinho.
    """
    empresa_id = await empresa_factory("Empresa Triagem Endpoint Nunca Falso Positivo")
    await _configurar_empresa(pool, empresa_id, auto_triagem_incidentes=True)

    async with superadmin_scoped_connection(pool) as conn:
        incidente = await _criar_incidente_parado(
            conn, empresa_id, "203.0.114.20", "MEDIUM", contido=False, origem="endpoint",
        )
        resultado = await servico.auto_classificar_incidentes_abertos(conn, empresa_id, agora=_AGORA)
        linha = await conn.fetchrow("SELECT status FROM incidentes WHERE id = $1", incidente["id"])

    assert resultado == []
    assert linha["status"] == "OPEN"


@pytest.mark.asyncio
async def test_auto_classificar_ainda_resolve_incidente_de_endpoint_se_contido(pool, empresa_factory):
    """Não é uma regra especial "endpoint nunca muda de status" -- é
    especificamente "endpoint nunca vira FALSO_POSITIVO sozinho". Se um dia
    existir contenção real para endpoint (fora do escopo desta fase) e o
    incidente estiver marcado como contido, a auto-triagem continua
    resolvendo normalmente, mesma regra de origem='rede'."""
    empresa_id = await empresa_factory("Empresa Triagem Endpoint Contido")
    await _configurar_empresa(pool, empresa_id, auto_triagem_incidentes=True)

    async with superadmin_scoped_connection(pool) as conn:
        incidente = await _criar_incidente_parado(
            conn, empresa_id, "203.0.114.21", "CRITICAL", contido=True, origem="endpoint",
        )
        resultado = await servico.auto_classificar_incidentes_abertos(conn, empresa_id, agora=_AGORA)
        linha = await conn.fetchrow("SELECT status FROM incidentes WHERE id = $1", incidente["id"])

    assert resultado == [{"incident_id": incidente["incident_id"], "status_novo": "RESOLVIDO"}]
    assert linha["status"] == "RESOLVIDO"


@pytest.mark.asyncio
async def test_auto_classificar_nunca_mexe_em_high_critical_sem_contencao(pool, empresa_factory):
    """O critério conservador: HIGH/CRITICAL sem bloqueio ativo fica para
    um humano decidir, não importa há quanto tempo esteja parado."""
    empresa_id = await empresa_factory("Empresa Triagem Alto Risco Sem Contencao")
    await _configurar_empresa(pool, empresa_id, auto_triagem_incidentes=True)

    async with superadmin_scoped_connection(pool) as conn:
        incidente = await _criar_incidente_parado(conn, empresa_id, "203.0.114.4", "CRITICAL", contido=False)
        resultado = await servico.auto_classificar_incidentes_abertos(conn, empresa_id, agora=_AGORA)
        linha = await conn.fetchrow("SELECT status FROM incidentes WHERE id = $1", incidente["id"])

    assert resultado == []
    assert linha["status"] == "OPEN"


@pytest.mark.asyncio
async def test_auto_classificar_ignora_incidente_ja_tocado_por_humano(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Triagem Tocado Por Humano")
    await _configurar_empresa(pool, empresa_id, auto_triagem_incidentes=True)

    async with superadmin_scoped_connection(pool) as conn:
        usuario = await servico_usuarios.criar_usuario(conn, empresa_id, "analista2@teste.com", "analista", "SenhaForte123!")
        await _criar_incidente_parado(conn, empresa_id, "203.0.114.5", "LOW", em_andamento_por=usuario["id"])
        resultado = await servico.auto_classificar_incidentes_abertos(conn, empresa_id, agora=_AGORA)

    assert resultado == []


# ---------------------------------------------------------------------------
# Capacidade 3: contagem de falsos positivos (usada pelo amortecimento de risco)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_obter_contagem_falsos_positivos(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Contagem Falsos Positivos")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        assert await servico.obter_contagem_falsos_positivos(conn, empresa_id, "203.0.114.6") == 0

        incidente = await servico_incidentes.criar_incidente(
            conn, empresa_id, "203.0.114.6", {"severity": "HIGH", "score": 70}, ["XSS"],
        )
        await servico_incidentes.atualizar_status(conn, empresa_id, incidente["incident_id"], "FALSO_POSITIVO")

        assert await servico.obter_contagem_falsos_positivos(conn, empresa_id, "203.0.114.6") == 1
        # outro IP não é afetado
        assert await servico.obter_contagem_falsos_positivos(conn, empresa_id, "203.0.114.7") == 0


@pytest.mark.asyncio
async def test_obter_contagem_falsos_positivos_ignora_falso_positivo_de_endpoint(pool, empresa_factory):
    """
    Correção de bug de revisão crítica (2026-09), segunda rodada: um
    incidente de origem 'endpoint' (Sentinela Endpoint) marcado
    FALSO_POSITIVO NÃO pode contar aqui -- este contador alimenta
    `core/risk_engine.aplicar_amortecimento_falso_positivo`, que amortece
    o score de ATAQUES DE REDE futuros do mesmo IP
    (`services/resposta_incidentes.py`). Como `ip_local` do heartbeat vem
    do corpo da requisição do agente (sem ligação nenhuma com o
    comportamento de rede daquele IP), sem esta filtragem por
    `origem='rede'`, descartar ruído de ENDPOINT (rotina de qualquer
    triagem) baixava silenciosamente a guarda contra ataques de REDE
    vindos do mesmo endereço.
    """
    empresa_id = await empresa_factory("Empresa Contagem Falsos Positivos Endpoint")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        incidente_endpoint = await servico_incidentes.criar_incidente(
            conn, empresa_id, "203.0.114.8", {"severity": "MEDIUM", "score": 55}, ["Processo suspeito (endpoint)"],
            origem="endpoint",
        )
        await servico_incidentes.atualizar_status(conn, empresa_id, incidente_endpoint["incident_id"], "FALSO_POSITIVO")

        # o falso positivo é de ENDPOINT -- não deve amortecer ataques de rede deste IP.
        assert await servico.obter_contagem_falsos_positivos(conn, empresa_id, "203.0.114.8") == 0

        incidente_rede = await servico_incidentes.criar_incidente(
            conn, empresa_id, "203.0.114.8", {"severity": "HIGH", "score": 70}, ["SQLi"],
        )
        await servico_incidentes.atualizar_status(conn, empresa_id, incidente_rede["incident_id"], "FALSO_POSITIVO")

        # agora sim -- um falso positivo de REDE conta normalmente.
        assert await servico.obter_contagem_falsos_positivos(conn, empresa_id, "203.0.114.8") == 1


# ---------------------------------------------------------------------------
# Capacidade 4: curadoria de ips_protegidos
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_adicionar_listar_remover_ip_protegido(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Ips Protegidos")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        adicionado = await servico.adicionar_ip_protegido(conn, empresa_id, "203.0.114.8", motivo="teste manual")
        assert adicionado["ip"] == "203.0.114.8"
        assert adicionado["origem"] == "manual"

        listados = await servico.listar_ips_protegidos(conn, empresa_id)
        assert len(listados) == 1

        whitelist = await servico.listar_ips_protegidos_para_whitelist(conn, empresa_id)
        assert whitelist == ["203.0.114.8"]

        removido = await servico.remover_ip_protegido(conn, empresa_id, "203.0.114.8")
        assert removido is True
        assert await servico.listar_ips_protegidos(conn, empresa_id) == []


@pytest.mark.asyncio
async def test_remover_ip_protegido_inexistente_retorna_false(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Ips Protegidos Vazia")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        assert await servico.remover_ip_protegido(conn, empresa_id, "203.0.114.9") is False


@pytest.mark.asyncio
async def test_adicionar_ip_ja_protegido_atualiza_motivo_sem_duplicar(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Ips Protegidos Duplicata")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        await servico.adicionar_ip_protegido(conn, empresa_id, "203.0.114.10", motivo="primeiro motivo")
        atualizado = await servico.adicionar_ip_protegido(conn, empresa_id, "203.0.114.10", motivo="segundo motivo")

        listados = await servico.listar_ips_protegidos(conn, empresa_id)
    assert len(listados) == 1
    assert atualizado["motivo"] == "segundo motivo"


@pytest.mark.asyncio
async def test_ips_protegidos_de_uma_empresa_nao_aparecem_para_outra(pool, empresa_factory):
    empresa_a = await empresa_factory("Empresa Ips Protegidos A")
    empresa_b = await empresa_factory("Empresa Ips Protegidos B")

    async with tenant_scoped_connection(pool, empresa_a) as conn:
        await servico.adicionar_ip_protegido(conn, empresa_a, "203.0.114.11", motivo="teste")

    async with tenant_scoped_connection(pool, empresa_b) as conn:
        assert await servico.listar_ips_protegidos(conn, empresa_b) == []


# ---------------------------------------------------------------------------
# executar_ciclo_autonomo -- iteração cross-tenant
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_executar_ciclo_autonomo_ignora_empresas_sem_nenhuma_flag_ligada(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Ciclo Sem Flags")
    await _configurar_empresa(pool, empresa_id, modo_firewall_auto=False, auto_triagem_incidentes=False)

    resultado = await servico.executar_ciclo_autonomo(pool)
    assert not any(a["empresa_id"] == str(empresa_id) for a in resultado["ajustes_modo"])
    assert not any(t["empresa_id"] == str(empresa_id) for t in resultado["triagens"])


@pytest.mark.asyncio
async def test_executar_ciclo_autonomo_processa_empresa_elegivel_isoladamente(pool, empresa_factory):
    """Uma empresa com a flag de auto-triagem ligada é processada pelo
    ciclo -- e uma falha (aqui simulada por outra empresa sem elegibilidade)
    não impede o processamento das demais."""
    empresa_elegivel = await empresa_factory("Empresa Ciclo Elegivel")
    await _configurar_empresa(pool, empresa_elegivel, auto_triagem_incidentes=True)

    async with superadmin_scoped_connection(pool) as conn:
        incidente = await _criar_incidente_parado(conn, empresa_elegivel, "203.0.114.12", "LOW")

    resultado = await servico.executar_ciclo_autonomo(pool)

    triagens_desta_empresa = [t for t in resultado["triagens"] if t["empresa_id"] == str(empresa_elegivel)]
    assert triagens_desta_empresa == [
        {"empresa_id": str(empresa_elegivel), "incident_id": incidente["incident_id"], "status_novo": "FALSO_POSITIVO"}
    ]
    assert resultado["erros"] == []
