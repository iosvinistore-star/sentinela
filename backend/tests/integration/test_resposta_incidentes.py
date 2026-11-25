# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testes de orquestração completa (services.resposta_incidentes) --
equivalente tenant-aware dos antigos testes de
`analisador_logs.responder_a_incidentes()` (agora em
tests/unit/test_analisador_logs.py só a parte pura, `candidatos_por_limite`).

Também é aqui que a correção da lacuna do upload é verificada em nível de
serviço: um relatório processado gera incidentes de verdade em Postgres,
escopados pela empresa do usuário logado.
"""
from unittest.mock import patch

import pytest

from sentinela.core import firewall as core_firewall
from sentinela.core import reputacao as core_reputacao
from sentinela.core.analisador_logs import processar_arquivo_logs
from sentinela.services import incidentes as servico_incidentes
from sentinela.services.resposta_incidentes import responder_a_incidentes
from tests.sql_cru import executar, valor

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_ignora_ip_no_limite_exato(db, empresa_factory, arquivo_log_exemplo):
    empresa_id = await empresa_factory("Empresa Resposta 1")
    relatorio = processar_arquivo_logs(arquivo_log_exemplo)

    with patch.object(core_reputacao, "consultar_abuseipdb") as abuse_mock, \
         patch.object(core_firewall.subprocess, "run") as run_mock:
        async with db.tenant_session(empresa_id) as conn:
            respostas = await responder_a_incidentes(conn, empresa_id, relatorio, limite_ataques=5, bloquear=True)

    assert respostas == []
    abuse_mock.assert_not_called()
    run_mock.assert_not_called()


@pytest.mark.asyncio
async def test_permitir_escalonamento_por_correlacao_e_opt_in_e_ainda_funciona(db, empresa_factory, arquivo_log_exemplo):
    """
    Mesmo cenário de `test_ignora_ip_no_limite_exato` (IP exatamente no
    limite, sem ultrapassá-lo), mas agora com
    `permitir_escalonamento_por_correlacao=True` -- confirma que a
    escalada comportamental continua disponível para quem opta por ela
    explicitamente, só não acontece mais por padrão.
    """
    empresa_id = await empresa_factory("Empresa Resposta Correlacao")
    relatorio = processar_arquivo_logs(arquivo_log_exemplo)

    with patch.object(core_reputacao, "consultar_abuseipdb", return_value={"score_abuso": 10}), \
         patch.object(core_firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(core_firewall.subprocess, "run") as run_mock:
        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = ""
        async with db.tenant_session(empresa_id) as conn:
            respostas = await responder_a_incidentes(
                conn, empresa_id, relatorio, limite_ataques=5, bloquear=True,
                permitir_escalonamento_por_correlacao=True,
            )

    assert len(respostas) == 1
    assert respostas[0]["ip"] == "203.0.113.5"
    assert respostas[0]["correlacao"]["correlacionado"] is True


@pytest.mark.asyncio
async def test_acima_do_limite_cria_incidente_de_verdade_no_postgres(db, empresa_factory, arquivo_log_exemplo):
    """A CORREÇÃO DA LACUNA: analisar um log e responder a incidentes agora
    grava em Postgres, visível depois via listar_incidentes -- não só
    desenha gráfico."""
    empresa_id = await empresa_factory("Empresa Resposta 2")
    relatorio = processar_arquivo_logs(arquivo_log_exemplo)

    with patch.object(core_reputacao, "consultar_abuseipdb", return_value={"score_abuso": 90}), \
         patch.object(core_reputacao, "consultar_virustotal", return_value={"maliciosos": 8}), \
         patch.object(core_firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(core_firewall.subprocess, "run") as run_mock:
        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = ""
        async with db.tenant_session(empresa_id) as conn:
            respostas = await responder_a_incidentes(
                conn, empresa_id, relatorio, limite_ataques=4, verificar_reputacao=True,
                bloquear=True, duracao_horas=1, origem="teste",
            )

    assert len(respostas) == 1
    assert respostas[0]["ip"] == "203.0.113.5"
    assert respostas[0]["total_ataques"] == 5
    assert respostas[0]["reputacao"]["classificacao"] == "ALTO RISCO"
    assert respostas[0]["risk"]["severity"] in ("HIGH", "CRITICAL")
    assert respostas[0]["incident_id"] is not None

    from sentinela.services import incidentes as servico_incidentes
    async with db.tenant_session(empresa_id) as conn:
        listados = await servico_incidentes.listar_incidentes(conn)
    assert len(listados) == 1
    assert listados[0]["ip"] == "203.0.113.5"


@pytest.mark.asyncio
async def test_incidente_criado_para_empresa_a_nao_aparece_para_empresa_b(db, empresa_factory, arquivo_log_exemplo):
    empresa_a = await empresa_factory("Empresa Resposta A")
    empresa_b = await empresa_factory("Empresa Resposta B")
    relatorio = processar_arquivo_logs(arquivo_log_exemplo)

    with patch.object(core_reputacao, "consultar_abuseipdb", return_value={"score_abuso": 90}), \
         patch.object(core_reputacao, "consultar_virustotal", return_value={"maliciosos": 8}):
        async with db.tenant_session(empresa_a) as conn:
            await responder_a_incidentes(conn, empresa_a, relatorio, limite_ataques=4, verificar_reputacao=True, bloquear=False)

    from sentinela.services import incidentes as servico_incidentes
    async with db.tenant_session(empresa_b) as conn:
        listados_b = await servico_incidentes.listar_incidentes(conn)
    assert listados_b == []


def _relatorio_sintetico(ips_e_contagens):
    """Constrói um `relatorio` mínimo (mesmo formato de processar_arquivo_logs)
    com um IP por entrada de `ips_e_contagens`, todos com o mesmo tipo de
    ataque -- suficiente pra exercitar `responder_a_incidentes` sem depender
    de um arquivo de log de verdade."""
    detalhes = []
    for ip, total in ips_e_contagens:
        for _ in range(total):
            detalhes.append({
                "ip": ip, "data": "01/Sep/2026:12:00:00", "requisicao": "GET /",
                "status": "200", "tipo_ataque": "SQL Injection (SQLi)",
            })
    return {
        "linhas_totais": len(detalhes),
        "linhas_nao_reconhecidas": 0,
        "total_alertas": len(detalhes),
        "ips_mais_perigosos": sorted(ips_e_contagens, key=lambda x: -x[1])[:3],
        "contagem_completa_ips": dict(ips_e_contagens),
        "detalhes_alertas": detalhes,
    }


@pytest.mark.asyncio
async def test_falha_em_um_candidato_nao_aborta_o_lote_inteiro(db, empresa_factory):
    """
    Defesa em profundidade: um candidato cuja consulta de reputação falhe
    (rede fora do ar, erro inesperado, etc.) não deve impedir os OUTROS
    candidatos do mesmo lote de serem processados e virarem incidente --
    cada candidato roda dentro do próprio SAVEPOINT (ver
    services/resposta_incidentes.py), então uma falha isolada não deixa a
    conexão/transação inutilizável para o resto do laço.
    """
    empresa_id = await empresa_factory("Empresa Resposta Isolamento")
    # "203.0.113.200" processa primeiro (candidatos_por_limite ordena do
    # mais ativo pro menos ativo) e falha; "203.0.113.201" vem depois e
    # precisa continuar funcionando normalmente.
    relatorio = _relatorio_sintetico([("203.0.113.200", 10), ("203.0.113.201", 6)])

    from sentinela.services import reputacao as servico_reputacao

    async def _reputacao_fake(conn, empresa_id_, ip, *a, **kw):
        if ip == "203.0.113.200":
            raise RuntimeError("falha simulada na consulta de reputação")
        return {"ip": ip, "classificacao": "ALTO RISCO", "abuseipdb": {"score_abuso": 90}, "virustotal": {}}

    with patch.object(servico_reputacao, "consultar_reputacao_ip", side_effect=_reputacao_fake):
        async with db.tenant_session(empresa_id) as conn:
            respostas = await responder_a_incidentes(
                conn, empresa_id, relatorio, limite_ataques=5, verificar_reputacao=True, bloquear=False,
            )

    assert len(respostas) == 2
    por_ip = {r["ip"]: r for r in respostas}
    assert "erro" in por_ip["203.0.113.200"]
    assert "erro" not in por_ip["203.0.113.201"]
    assert por_ip["203.0.113.201"]["risk"]["severity"] in ("HIGH", "CRITICAL")
    assert por_ip["203.0.113.201"]["incident_id"] is not None

    # A conexão/transação continua utilizável depois da falha (SAVEPOINT
    # isolou o erro) -- confirma consultando o incidente de verdade em
    # Postgres na mesma conexão que processou o lote.
    from sentinela.services import incidentes as servico_incidentes
    async with db.tenant_session(empresa_id) as conn2:
        listados = await servico_incidentes.listar_incidentes(conn2)
    assert len(listados) == 1
    assert listados[0]["ip"] == "203.0.113.201"


@pytest.mark.asyncio
async def test_sem_flags_nao_chama_reputacao_nem_bloqueio(db, empresa_factory, arquivo_log_exemplo):
    empresa_id = await empresa_factory("Empresa Resposta 3")
    relatorio = processar_arquivo_logs(arquivo_log_exemplo)

    with patch.object(core_reputacao, "consultar_abuseipdb") as abuse_mock, \
         patch.object(core_firewall.subprocess, "run") as run_mock:
        async with db.tenant_session(empresa_id) as conn:
            respostas = await responder_a_incidentes(
                conn, empresa_id, relatorio, limite_ataques=4, verificar_reputacao=False, bloquear=False
            )

    assert len(respostas) == 1
    assert "reputacao" not in respostas[0]
    assert "bloqueio" not in respostas[0]
    abuse_mock.assert_not_called()
    run_mock.assert_not_called()


# ---------------------------------------------------------------------------
# Itens 8-10 do plano de endurecimento pós-auditoria: kill-switch global,
# modo de firewall por tenant, e incidente_id linkado ao bloqueio.
# ---------------------------------------------------------------------------

async def _definir_modo_firewall(db, empresa_id, modo):
    async with db.superadmin_session() as conn:
        await executar(conn, "UPDATE empresas SET modo_firewall = $2 WHERE id = $1", empresa_id, modo)


@pytest.mark.asyncio
async def test_kill_switch_global_forca_dry_run_mesmo_com_bloquear_true(db, empresa_factory):
    """`automacao_habilitada=False` (o kill-switch global, ver
    Settings.firewall_automacao_habilitada) vence QUALQUER combinação de
    bloquear/modo_resposta/modo_firewall pedida pelo chamador."""
    empresa_id = await empresa_factory("Empresa Kill Switch Global")
    relatorio = _relatorio_sintetico([("203.0.113.150", 6)])

    with patch.object(core_firewall.subprocess, "run") as run_mock:
        async with db.tenant_session(empresa_id) as conn:
            respostas = await responder_a_incidentes(
                conn, empresa_id, relatorio, limite_ataques=5, verificar_reputacao=False,
                bloquear=True, automacao_habilitada=False,
            )

    assert respostas[0]["bloqueio"]["status"] == "simulado"
    # dry-run nunca chega a chamar subprocess (ver core/firewall.py:bloquear_ip).
    run_mock.assert_not_called()


@pytest.mark.asyncio
async def test_modo_firewall_observacao_nunca_bloqueia(db, empresa_factory):
    empresa_id = await empresa_factory("Empresa Modo Observacao")
    await _definir_modo_firewall(db, empresa_id, "observacao")
    relatorio = _relatorio_sintetico([("203.0.113.151", 6)])

    with patch.object(core_firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(core_firewall.subprocess, "run") as run_mock:
        async with db.tenant_session(empresa_id) as conn:
            respostas = await responder_a_incidentes(
                conn, empresa_id, relatorio, limite_ataques=5, verificar_reputacao=False, bloquear=True,
            )

    # Nem "bloqueio" simulado -- em modo observação a automação não tenta
    # nada, nem em dry-run.
    assert "bloqueio" not in respostas[0]
    run_mock.assert_not_called()


@pytest.mark.asyncio
async def test_modo_firewall_manual_desliga_resposta_automatica(db, empresa_factory):
    """"manual" -- resposta automática (a que este módulo implementa)
    desligada; o bloqueio manual continua disponível via
    POST /api/v1/firewall/bloqueios (rota separada, não afetada por este
    modo -- ver api/v1/firewall.py)."""
    empresa_id = await empresa_factory("Empresa Modo Manual")
    await _definir_modo_firewall(db, empresa_id, "manual")
    relatorio = _relatorio_sintetico([("203.0.113.152", 6)])

    with patch.object(core_firewall.subprocess, "run") as run_mock:
        async with db.tenant_session(empresa_id) as conn:
            respostas = await responder_a_incidentes(
                conn, empresa_id, relatorio, limite_ataques=5, verificar_reputacao=False, bloquear=True,
            )

    assert "bloqueio" not in respostas[0]
    run_mock.assert_not_called()
    # O incidente em si continua sendo criado normalmente -- só o bloqueio
    # automático é que fica desligado.
    assert respostas[0]["incident_id"] is not None


@pytest.mark.asyncio
async def test_modo_firewall_dry_run_forca_simulacao(db, empresa_factory):
    empresa_id = await empresa_factory("Empresa Modo Dry Run")
    await _definir_modo_firewall(db, empresa_id, "dry_run")
    relatorio = _relatorio_sintetico([("203.0.113.153", 6)])

    with patch.object(core_firewall.subprocess, "run") as run_mock:
        async with db.tenant_session(empresa_id) as conn:
            respostas = await responder_a_incidentes(
                conn, empresa_id, relatorio, limite_ataques=5, verificar_reputacao=False,
                bloquear=True, dry_run=False,  # o chamador nem pediu dry-run -- o MODO que força.
            )

    assert respostas[0]["bloqueio"]["status"] == "simulado"
    run_mock.assert_not_called()


@pytest.mark.asyncio
async def test_modo_automacao_controlada_limita_duracao_a_24h(db, empresa_factory):
    empresa_id = await empresa_factory("Empresa Modo Controlada")
    await _definir_modo_firewall(db, empresa_id, "automacao_controlada")
    relatorio = _relatorio_sintetico([("203.0.113.154", 6)])

    with patch.object(core_firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(core_firewall.subprocess, "run") as run_mock:
        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = ""
        async with db.tenant_session(empresa_id) as conn:
            respostas = await responder_a_incidentes(
                conn, empresa_id, relatorio, limite_ataques=5, verificar_reputacao=False,
                bloquear=True, duracao_horas=200,  # pede 200h -- "controlada" nunca honra isso.
            )

    bloqueio = respostas[0]["bloqueio"]
    assert bloqueio["status"] in ("bloqueado", "ja_bloqueado")
    assert bloqueio["expira_em"] is not None
    import datetime
    expira_em = datetime.datetime.fromisoformat(bloqueio["expira_em"])
    agora = datetime.datetime.now(expira_em.tzinfo) if expira_em.tzinfo else datetime.datetime.now()
    horas_restantes = (expira_em - agora).total_seconds() / 3600
    assert horas_restantes <= 24.01  # margem pequena pro tempo de execução do teste


@pytest.mark.asyncio
async def test_modo_automacao_total_honra_duracao_pedida(db, empresa_factory):
    empresa_id = await empresa_factory("Empresa Modo Total")
    await _definir_modo_firewall(db, empresa_id, "automacao_total")
    relatorio = _relatorio_sintetico([("203.0.113.155", 6)])

    with patch.object(core_firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(core_firewall.subprocess, "run") as run_mock:
        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = ""
        async with db.tenant_session(empresa_id) as conn:
            respostas = await responder_a_incidentes(
                conn, empresa_id, relatorio, limite_ataques=5, verificar_reputacao=False,
                bloquear=True, duracao_horas=200,
            )

    bloqueio = respostas[0]["bloqueio"]
    assert bloqueio["status"] in ("bloqueado", "ja_bloqueado")
    import datetime
    expira_em = datetime.datetime.fromisoformat(bloqueio["expira_em"])
    agora = datetime.datetime.now(expira_em.tzinfo) if expira_em.tzinfo else datetime.datetime.now()
    horas_restantes = (expira_em - agora).total_seconds() / 3600
    assert horas_restantes > 24  # não foi limitado -- ao contrário de "automacao_controlada"


@pytest.mark.asyncio
async def test_bloqueio_automatico_e_linkado_ao_incidente_que_o_originou(db, empresa_factory):
    """Item 10 -- rastreabilidade bloqueio -> incidente (ver
    migrations/0012_...sql: bloqueios_firewall.incidente_id)."""
    empresa_id = await empresa_factory("Empresa Rastreabilidade Bloqueio")
    relatorio = _relatorio_sintetico([("203.0.113.156", 6)])

    with patch.object(core_firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(core_firewall.subprocess, "run") as run_mock:
        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = ""
        async with db.tenant_session(empresa_id) as conn:
            respostas = await responder_a_incidentes(
                conn, empresa_id, relatorio, limite_ataques=5, verificar_reputacao=False, bloquear=True,
            )

    assert respostas[0]["incident_id"] is not None
    assert respostas[0]["bloqueio"]["incidente_id"] is not None

    async with db.superadmin_session() as conn:
        incidente_id_esperado = await valor(conn, "SELECT id FROM incidentes WHERE empresa_id = $1 AND incident_id = $2",
            empresa_id, respostas[0]["incident_id"],
        )
        incidente_id_no_bloqueio = await valor(conn, "SELECT incidente_id FROM bloqueios_firewall WHERE empresa_id = $1 AND host(ip) = $2",
            empresa_id, "203.0.113.156",
        )
    assert incidente_id_no_bloqueio == incidente_id_esperado


@pytest.mark.asyncio
async def test_historico_de_falso_positivo_amortece_o_risco(db, empresa_factory):
    """Capacidade 3 do modo autônomo (filtro de falso positivo mais
    esperto, sempre-ativo -- ver core/risk_engine.aplicar_amortecimento_falso_positivo
    e services/automacao.obter_contagem_falsos_positivos): um IP com 2+
    incidentes FALSO_POSITIVO anteriores NESTE tenant tem o risco do
    próximo incidente amortecido, comparado ao mesmo cenário sem
    histórico."""
    ip = "203.0.113.157"
    relatorio = _relatorio_sintetico([(ip, 6)])

    empresa_sem_historico = await empresa_factory("Empresa Amortecimento Sem Historico")
    empresa_com_historico = await empresa_factory("Empresa Amortecimento Com Historico")

    async with db.tenant_session(empresa_com_historico) as conn:
        for _ in range(2):
            incidente = await servico_incidentes.criar_incidente(
                conn, empresa_com_historico, ip, {"severity": "HIGH", "score": 70}, ["SQL Injection (SQLi)"],
            )
            await servico_incidentes.atualizar_status(conn, empresa_com_historico, incidente["incident_id"], "FALSO_POSITIVO")

    with patch.object(core_firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(core_firewall.subprocess, "run") as run_mock:
        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = ""

        async with db.tenant_session(empresa_sem_historico) as conn:
            resposta_sem_historico = await responder_a_incidentes(
                conn, empresa_sem_historico, relatorio, limite_ataques=5, verificar_reputacao=False,
            )
        async with db.tenant_session(empresa_com_historico) as conn:
            resposta_com_historico = await responder_a_incidentes(
                conn, empresa_com_historico, relatorio, limite_ataques=5, verificar_reputacao=False,
            )

    risco_sem_historico = resposta_sem_historico[0]["risk"]
    risco_com_historico = resposta_com_historico[0]["risk"]

    assert "amortecimento_falso_positivo" not in risco_sem_historico["fatores"]
    assert risco_com_historico["fatores"]["amortecimento_falso_positivo"] == -24  # 2 FPs * 12 pontos
    assert risco_com_historico["score"] == max(0, risco_sem_historico["score"] - 24)
