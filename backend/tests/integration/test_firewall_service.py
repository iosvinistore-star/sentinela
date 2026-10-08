# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
services.firewall: sincronização entre a "verdade do kernel" (mockada, como
em tests/unit/test_firewall_kernel.py) e a tabela Postgres bloqueios_firewall.
"""
import asyncio
import time
from unittest.mock import MagicMock, patch

import pytest

from sentinela.core import firewall as core_firewall
from sentinela.services import automacao as servico_automacao
from sentinela.services import firewall as servico
from sentinela.services import incidentes as servico_incidentes
from tests.sql_cru import buscar, buscar_um

pytestmark = pytest.mark.integration


def _resultado(returncode=0, stdout=""):
    r = MagicMock()
    r.returncode = returncode
    r.stdout = stdout
    return r


def _fake_subprocess_run(ja_bloqueado=False):
    def _run(cmd, **kwargs):
        if cmd[:2] == ["ipset", "test"]:
            return _resultado(returncode=0 if ja_bloqueado else 1)
        if cmd[:2] == ["ipset", "save"]:
            return _resultado(stdout="# mock\n")
        if cmd and cmd[0] in ("iptables-save", "ip6tables-save"):
            return _resultado(stdout="# mock\n")
        if len(cmd) >= 2 and cmd[1] == "-C":
            return _resultado(returncode=0)
        return _resultado()
    return _run


@pytest.mark.asyncio
async def test_registrar_bloqueio_persiste_linha_ativa_no_postgres(db, empresa_factory):
    empresa_id = await empresa_factory("Empresa Firewall")

    with patch.object(core_firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(core_firewall.subprocess, "run", side_effect=_fake_subprocess_run(ja_bloqueado=False)):
        async with db.tenant_session(empresa_id) as conn:
            resultado = await servico.registrar_bloqueio(
                conn, empresa_id, "203.0.113.20", "teste", dry_run=False, duracao_horas=2, origem="teste"
            )
            assert resultado["status"] == "bloqueado"

            linhas = await buscar(conn, "SELECT * FROM bloqueios_firewall WHERE empresa_id = $1", empresa_id)
    assert len(linhas) == 1
    assert linhas[0]["status"] == "ativo"
    assert str(linhas[0]["ip"]) == "203.0.113.20"


@pytest.mark.asyncio
async def test_registrar_bloqueio_dry_run_nao_persiste_linha(db, empresa_factory):
    empresa_id = await empresa_factory("Empresa Firewall Dry Run")

    with patch.object(core_firewall.subprocess, "run") as run_mock:
        async with db.tenant_session(empresa_id) as conn:
            resultado = await servico.registrar_bloqueio(
                conn, empresa_id, "203.0.113.21", "teste", dry_run=True, duracao_horas=2, origem="teste"
            )
            assert resultado["status"] == "simulado"
            linhas = await buscar(conn, "SELECT * FROM bloqueios_firewall WHERE empresa_id = $1", empresa_id)
    assert linhas == []
    run_mock.assert_not_called()


@pytest.mark.asyncio
async def test_remover_bloqueio_marca_linha_como_removida(db, empresa_factory):
    empresa_id = await empresa_factory("Empresa Firewall Remover")

    with patch.object(core_firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(core_firewall.subprocess, "run", side_effect=_fake_subprocess_run(ja_bloqueado=False)):
        async with db.tenant_session(empresa_id) as conn:
            await servico.registrar_bloqueio(conn, empresa_id, "203.0.113.22", "teste", dry_run=False)
            resultado = await servico.remover_bloqueio(conn, db, empresa_id, "203.0.113.22", origem="teste")
            assert resultado["status"] == "desbloqueado"

            linha = await buscar_um(conn, "SELECT status FROM bloqueios_firewall WHERE empresa_id=$1 AND ip='203.0.113.22'", empresa_id
            )
    assert linha["status"] == "removido"


@pytest.mark.asyncio
async def test_remover_bloqueio_sem_registro_proprio_nao_toca_kernel(db, empresa_factory):
    """Antes da correção, `remover_bloqueio` chamava `core_firewall.desbloquear_ip`
    incondicionalmente -- uma empresa conseguia desbloquear no host QUALQUER
    IP, mesmo um que ela nunca bloqueou (nenhuma linha própria em
    bloqueios_firewall). Agora isso é recusado antes de tocar o kernel."""
    empresa_id = await empresa_factory("Empresa Firewall Sem Registro Proprio")

    with patch.object(core_firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(core_firewall.subprocess, "run") as run_mock:
        async with db.tenant_session(empresa_id) as conn:
            resultado = await servico.remover_bloqueio(conn, db, empresa_id, "203.0.113.30", origem="teste")

    assert resultado["status"] == "erro"
    assert "nenhum bloqueio ativo" in resultado["motivo"]
    run_mock.assert_not_called()


@pytest.mark.asyncio
async def test_remover_bloqueio_nao_desbloqueia_kernel_se_outra_empresa_depende(db, empresa_factory):
    """Duas empresas bloqueando o MESMO IP (host-wide) e uma delas revertendo
    o próprio bloqueio não pode desfazer a proteção da outra -- o registro
    Postgres desta empresa é removido, mas o kernel (ipset) não é tocado."""
    empresa_a = await empresa_factory("Empresa Firewall Compartilhado A")
    empresa_b = await empresa_factory("Empresa Firewall Compartilhado B")
    ip = "203.0.113.31"

    with patch.object(core_firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(core_firewall.subprocess, "run", side_effect=_fake_subprocess_run(ja_bloqueado=False)):
        async with db.tenant_session(empresa_a) as conn:
            await servico.registrar_bloqueio(conn, empresa_a, ip, "teste-a", dry_run=False)
        async with db.tenant_session(empresa_b) as conn:
            await servico.registrar_bloqueio(conn, empresa_b, ip, "teste-b", dry_run=False)

        with patch.object(core_firewall, "desbloquear_ip") as desbloquear_mock:
            async with db.tenant_session(empresa_a) as conn:
                resultado = await servico.remover_bloqueio(conn, db, empresa_a, ip, origem="teste")

    assert resultado["status"] == "removido_apenas_do_registro"
    desbloquear_mock.assert_not_called()  # kernel intocado -- empresa_b ainda depende

    async with db.tenant_session(empresa_a) as conn:
        linha_a = await buscar_um(conn, "SELECT status FROM bloqueios_firewall WHERE empresa_id=$1 AND ip=$2", empresa_a, ip
        )
    assert linha_a["status"] == "removido"

    async with db.tenant_session(empresa_b) as conn:
        linha_b = await buscar_um(conn, "SELECT status FROM bloqueios_firewall WHERE empresa_id=$1 AND ip=$2", empresa_b, ip
        )
    assert linha_b["status"] == "ativo"  # empresa_b nunca pediu nada -- continua protegida


@pytest.mark.asyncio
async def test_registrar_e_remover_bloqueio_do_mesmo_ip_serializam_entre_tenants(db, empresa_factory):
    """
    Repro do achado 4 da revisão crítica (2026-09): antes da correção, a
    checagem "outra empresa depende deste IP?" + a mutação de kernel de
    `remover_bloqueio` (tenant A) não eram atômicas em relação a uma
    chamada CONCORRENTE de `registrar_bloqueio` de OUTRO tenant (B) para o
    MESMO IP -- um TOCTOU: A podia ler "ninguém mais depende", B commitar
    seu bloqueio bem no meio dessa janela, e A seguir e desbloquear o
    kernel de qualquer forma -- deixando a linha de B em Postgres como
    'ativo' com o enforcement real (kernel) já removido.

    Este teste injeta um atraso mensurável (via `time.sleep` dentro de
    `asyncio.to_thread`, que só bloqueia a thread, não o event loop) nas
    duas funções de kernel (`bloquear_ip`/`desbloquear_ip`) para abrir uma
    janela real onde a corrida aconteceria sem o `pg_advisory_xact_lock`, e
    prova que as chamadas de kernel de `registrar_bloqueio` (tenant B) e
    `remover_bloqueio` (tenant A) NUNCA executam ao mesmo tempo -- uma só
    começa depois que a outra já terminou -- e que o estado final é sempre
    consistente entre Postgres e "kernel".
    """
    empresa_a = await empresa_factory("Empresa Firewall Race A")
    empresa_b = await empresa_factory("Empresa Firewall Race B")
    ip = "203.0.113.77"

    janelas_kernel = []  # (label, inicio, fim) -- só da chamada de kernel, não da função inteira

    def _bloquear_lento(ip_chamado, *args, **kwargs):
        inicio = time.monotonic()
        time.sleep(0.15)
        fim = time.monotonic()
        janelas_kernel.append(("bloquear (registrar_b)", inicio, fim))
        return {"ip": ip_chamado, "status": "bloqueado", "comando": "mock", "expira_em": None, "persistencia": {}}

    def _desbloquear_lento(ip_chamado, *args, **kwargs):
        inicio = time.monotonic()
        time.sleep(0.15)
        fim = time.monotonic()
        janelas_kernel.append(("desbloquear (remover_a)", inicio, fim))
        return {"ip": ip_chamado, "status": "desbloqueado"}

    with patch.object(core_firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(core_firewall, "bloquear_ip", side_effect=_bloquear_lento), \
         patch.object(core_firewall, "desbloquear_ip", side_effect=_desbloquear_lento):

        # Setup: empresa_a já tem um bloqueio ativo próprio para este IP
        # (pré-requisito de remover_bloqueio -- ver
        # test_remover_bloqueio_sem_registro_proprio_nao_toca_kernel).
        async with db.tenant_session(empresa_a) as conn:
            await servico.registrar_bloqueio(conn, empresa_a, ip, "setup-a", dry_run=False)
        janelas_kernel.clear()  # ignora a chamada de kernel do setup, só interessa a corrida abaixo

        async def _remover_a():
            async with db.tenant_session(empresa_a) as conn:
                return await servico.remover_bloqueio(conn, db, empresa_a, ip, origem="teste")

        async def _registrar_b():
            async with db.tenant_session(empresa_b) as conn:
                return await servico.registrar_bloqueio(conn, empresa_b, ip, "teste-b", dry_run=False)

        resultado_remover, resultado_registrar = await asyncio.gather(_remover_a(), _registrar_b())

    # As DUAS chamadas de kernel nunca podem se sobrepor -- é exatamente
    # essa invariante que o advisory lock garante (sem ele, com o atraso
    # artificial de 0.15s em cada uma, uma sobreposição seria extremamente
    # provável, já que as duas coroutines começam praticamente juntas via
    # asyncio.gather).
    # Quem ganha o lock primeiro varia com o agendamento: se remover_a ganha, as duas chamadas de kernel
    # acontecem (uma depois da outra); se registrar_b ganha, remover_a vê "empresa_b depende" e nem toca o
    # kernel (uma só janela). Em ambos os casos o que importa é nunca haver sobreposição.
    assert 1 <= len(janelas_kernel) <= 2, janelas_kernel
    janelas_kernel.sort(key=lambda j: j[1])
    for (_, _, fim_anterior), (_, inicio_seguinte, _) in zip(janelas_kernel, janelas_kernel[1:], strict=False):
        assert inicio_seguinte >= fim_anterior, (
            f"chamadas de kernel concorrentes para o mesmo IP se sobrepuseram (corrida não fechada): {janelas_kernel}"
        )

    # E o estado final é sempre consistente: a linha de empresa_b (que
    # sempre acaba 'ativo', já que registrar_bloqueio nunca falha aqui)
    # precisa corresponder a um kernel que reflete isso -- nunca a
    # combinação inconsistente que o bug original produzia (linha 'ativo'
    # com o kernel já desbloqueado por baixo).
    assert resultado_registrar["status"] == "bloqueado"
    async with db.tenant_session(empresa_b) as conn:
        linha_b = await buscar_um(conn, "SELECT status FROM bloqueios_firewall WHERE empresa_id=$1 AND ip=$2", empresa_b, ip
        )
    assert linha_b["status"] == "ativo"
    # A ordem das chamadas de kernel diz qual dos dois desfechos consistentes
    # aconteceu: se remover_a rodou primeiro, ela viu "ninguém mais depende"
    # (empresa_b ainda não tinha commitado) e DESBLOQUEOU o kernel -- mas aí
    # registrar_b (depois) BLOQUEOU de novo, então o kernel termina
    # bloqueado de qualquer forma. Se registrar_b rodou primeiro, remover_a
    # (depois) viu "empresa_b depende" e nem tocou o kernel.
    ultima_chamada = janelas_kernel[-1][0]
    assert "bloquear" in ultima_chamada or resultado_remover["status"] == "removido_apenas_do_registro"


@pytest.mark.asyncio
async def test_listar_bloqueios_so_mostra_os_desta_empresa(db, empresa_factory):
    empresa_a = await empresa_factory("Empresa Firewall Listar A")
    empresa_b = await empresa_factory("Empresa Firewall Listar B")

    saida_v4 = "Members:\n203.0.113.23 timeout 3600\n203.0.113.24 timeout 3600\n"

    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["ipset", "list"] and cmd[2] == core_firewall.IPSET_V4:
            return _resultado(stdout=saida_v4)
        if cmd[:2] == ["ipset", "list"] and cmd[2] == core_firewall.IPSET_V6:
            return _resultado(stdout="Members:\n")
        return _resultado()

    with patch.object(core_firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(core_firewall.subprocess, "run", side_effect=fake_run):
        async with db.tenant_session(empresa_a) as conn:
            await servico.registrar_bloqueio(conn, empresa_a, "203.0.113.23", "teste-a", dry_run=False)
        async with db.tenant_session(empresa_b) as conn:
            await servico.registrar_bloqueio(conn, empresa_b, "203.0.113.24", "teste-b", dry_run=False)

        async with db.tenant_session(empresa_a) as conn:
            listados_a = await servico.listar_bloqueios(conn, empresa_a)

    assert len(listados_a) == 1
    assert str(listados_a[0]["ip"]) == "203.0.113.23"
    assert listados_a[0]["ainda_ativo_no_kernel"] is True


@pytest.mark.asyncio
async def test_sincronizar_bloqueios_expirados_atualiza_status_cross_tenant(db, empresa_factory):
    empresa_a = await empresa_factory("Empresa Firewall Sync A")
    empresa_b = await empresa_factory("Empresa Firewall Sync B")

    with patch.object(core_firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(core_firewall.subprocess, "run", side_effect=_fake_subprocess_run(ja_bloqueado=False)):
        async with db.tenant_session(empresa_a) as conn:
            await servico.registrar_bloqueio(conn, empresa_a, "203.0.113.25", "teste", dry_run=False)
        async with db.tenant_session(empresa_b) as conn:
            await servico.registrar_bloqueio(conn, empresa_b, "203.0.113.26", "teste", dry_run=False)

    # Kernel agora só reporta .25 como ainda ativo -- .26 "expirou".
    def fake_run_pos_expiracao(cmd, **kwargs):
        if cmd[:2] == ["ipset", "list"] and cmd[2] == core_firewall.IPSET_V4:
            return _resultado(stdout="Members:\n203.0.113.25 timeout 1800\n")
        return _resultado(stdout="Members:\n")

    with patch.object(core_firewall.subprocess, "run", side_effect=fake_run_pos_expiracao):
        resultado = await servico.sincronizar_bloqueios_expirados(db)

    linhas = {r["ip"]: r for r in resultado["linhas_expiradas_no_postgres"]}
    assert "203.0.113.26" in {str(ip) for ip in linhas}
    assert "203.0.113.25" not in {str(ip) for ip in linhas}


@pytest.mark.asyncio
async def test_registrar_bloqueio_ignora_ip_da_whitelist_persistida(db, empresa_factory):
    """Capacidade 4 do modo autônomo (services/automacao.py, ver
    migrations/0014_...sql): um IP em `ips_protegidos` nunca é bloqueado de
    novo, mesmo que o chamador não passe `whitelist` explicitamente."""
    empresa_id = await empresa_factory("Empresa Firewall Whitelist Persistida")

    with patch.object(core_firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(core_firewall.subprocess, "run", side_effect=_fake_subprocess_run(ja_bloqueado=False)) as run_mock:
        async with db.tenant_session(empresa_id) as conn:
            await servico_automacao.adicionar_ip_protegido(conn, empresa_id, "203.0.113.27", motivo="teste")
            resultado = await servico.registrar_bloqueio(conn, empresa_id, "203.0.113.27", "teste", dry_run=False)

            linhas = await buscar(conn, "SELECT * FROM bloqueios_firewall WHERE empresa_id = $1", empresa_id)

    assert resultado["status"] == "ignorado"
    assert linhas == []
    run_mock.assert_not_called()


@pytest.mark.asyncio
async def test_remover_bloqueio_automatico_revertido_rapido_protege_ip_automaticamente(db, empresa_factory):
    """Reverso da capacidade 4: um HUMANO derrubando um bloqueio AUTOMÁTICO
    (incidente_id não nulo) minutos depois de criado é tratado como sinal
    de falso positivo -- o IP entra em `ips_protegidos` com origem
    'automatico', sem exigir nenhuma ação extra do admin."""
    empresa_id = await empresa_factory("Empresa Firewall Auto Protecao")
    risco = {"severity": "HIGH", "score": 70}

    with patch.object(core_firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(core_firewall.subprocess, "run", side_effect=_fake_subprocess_run(ja_bloqueado=False)):
        async with db.tenant_session(empresa_id) as conn:
            incidente = await servico_incidentes.criar_incidente(conn, empresa_id, "203.0.113.28", risco, ["XSS"])
            await servico.registrar_bloqueio(
                conn, empresa_id, "203.0.113.28", "teste", dry_run=False, incidente_id=incidente["id"],
            )
            await servico.remover_bloqueio(conn, db, empresa_id, "203.0.113.28", origem="teste", usuario_id=None)

            protegidos = await servico_automacao.listar_ips_protegidos(conn, empresa_id)

    assert len(protegidos) == 1
    assert protegidos[0]["ip"] == "203.0.113.28"
    assert protegidos[0]["origem"] == "automatico"


@pytest.mark.asyncio
async def test_remover_bloqueio_manual_nao_protege_ip_automaticamente(db, empresa_factory):
    """Contraste com o teste acima: um bloqueio MANUAL (sem incidente_id)
    revertido não é sinal de falso positivo da automação -- é só um admin
    mudando de ideia sobre a própria ação."""
    empresa_id = await empresa_factory("Empresa Firewall Sem Auto Protecao")

    with patch.object(core_firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(core_firewall.subprocess, "run", side_effect=_fake_subprocess_run(ja_bloqueado=False)):
        async with db.tenant_session(empresa_id) as conn:
            await servico.registrar_bloqueio(conn, empresa_id, "203.0.113.29", "teste", dry_run=False)
            await servico.remover_bloqueio(conn, db, empresa_id, "203.0.113.29", origem="teste")

            protegidos = await servico_automacao.listar_ips_protegidos(conn, empresa_id)

    assert protegidos == []
