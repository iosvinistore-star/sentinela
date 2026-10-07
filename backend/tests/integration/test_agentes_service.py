# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
services.agentes: gestão de agentes do Sentinela Endpoint (criação,
listagem, revogação) e o pipeline de heartbeat (evento bruto + avaliação de
risco + incidente com origem='endpoint' quando há processo suspeito) --
ver migrations/0016_agentes_endpoint.sql.

Segue a mesma convenção de tests/integration/test_automacao_service.py:
conexão tenant-scoped de verdade (RLS real), sem mockar nada do Postgres.
"""
import json
import uuid

import pytest

from sentinela.auth.agentes import autenticar_agente
from sentinela.db.pool import superadmin_scoped_connection, tenant_scoped_connection
from sentinela.services import agentes as servico
from sentinela.services import incidentes as servico_incidentes
from sentinela.services import licenciamento as servico_licenciamento

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# avaliar_risco_endpoint -- heurística pura, sem banco
# ---------------------------------------------------------------------------

def test_avaliar_risco_sem_processos_suspeitos_e_low_score_zero():
    assert servico.avaliar_risco_endpoint([]) == {"score": 0, "severity": "LOW"}


def test_avaliar_risco_um_processo_suspeito_e_medium():
    # score base (_SCORE_BASE_PROCESSO_SUSPEITO=55) fica abaixo do corte de
    # HIGH (>=60) -- um único processo suspeito começa em MEDIUM, não HIGH.
    # Nome deliberadamente genérico (não bate com nenhum _INDICADORES_CRITICOS)
    # -- este teste cobre a heurística PURA de contagem, não a escalada por
    # indicador conhecido (ver test_avaliar_risco_indicador_critico_* abaixo).
    risco = servico.avaliar_risco_endpoint([{"nome": "unknown123.exe"}])
    assert risco == {"score": 55, "severity": "MEDIUM"}


def test_avaliar_risco_dois_processos_suspeitos_e_high():
    risco = servico.avaliar_risco_endpoint([{"nome": "unknown123.exe"}, {"nome": "outro_proc.exe"}])
    assert risco == {"score": 70, "severity": "HIGH"}


def test_avaliar_risco_varios_processos_suspeitos_sobe_para_critical_e_tem_teto():
    risco = servico.avaliar_risco_endpoint(
        [{"nome": "unknown123.exe"}, {"nome": "outro_proc.exe"}, {"nome": "mais_um.exe"}]
    )
    assert risco["severity"] == "CRITICAL"
    assert risco["score"] == 85  # 55 + 15*2

    risco_muitos = servico.avaliar_risco_endpoint([{"nome": f"p{i}"} for i in range(10)])
    assert risco_muitos["score"] == 95  # teto (_SCORE_TETO), não 55 + 15*9


# ---------------------------------------------------------------------------
# avaliar_risco_endpoint -- escalada por indicador de ferramenta conhecida
# (correção do bug de revisão crítica 2026-09: severidade não pode ser só
# contagem, uma ferramenta de ataque conhecida é sempre CRITICAL mesmo
# sozinha)
# ---------------------------------------------------------------------------

def test_avaliar_risco_indicador_critico_no_nome_forca_critical_mesmo_sozinho():
    risco = servico.avaliar_risco_endpoint([{"nome": "mimikatz.exe"}])
    assert risco == {"score": 95, "severity": "CRITICAL"}


def test_avaliar_risco_indicador_critico_e_case_insensitive():
    risco = servico.avaliar_risco_endpoint([{"nome": "MimiKatz.EXE"}])
    assert risco["severity"] == "CRITICAL"


def test_avaliar_risco_indicador_critico_via_linha_de_comando_mesmo_com_nome_generico():
    # O nome do processo pode ser inócuo/disfarçado -- o indicador também
    # precisa ser detectado na linha de comando completa.
    processos = [{"nome": "svchost.exe", "linha_de_comando": "svchost.exe -k netsvcs -p mimikatz.exe --dump"}]
    risco = servico.avaliar_risco_endpoint(processos)
    assert risco["severity"] == "CRITICAL"


def test_avaliar_risco_indicador_critico_entre_varios_processos_nao_criticos():
    processos = [{"nome": "unknown123.exe"}, {"nome": "cobaltstrike beacon"}]
    risco = servico.avaliar_risco_endpoint(processos)
    assert risco["severity"] == "CRITICAL"
    assert risco["score"] == 95


def test_avaliar_risco_sem_indicador_critico_nao_e_afetado():
    # Processo com "nc" no nome não deve casar por substring com nenhum
    # indicador -- confirma que a lista é de indicadores específicos, não
    # de fragmentos genéricos demais.
    risco = servico.avaliar_risco_endpoint([{"nome": "nc"}])
    assert risco == {"score": 55, "severity": "MEDIUM"}


# ---------------------------------------------------------------------------
# criar_agente / listar_agentes / revogar_agente
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_criar_agente_devolve_token_em_claro_uma_unica_vez(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Agentes Criar")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        agente, token = await servico.criar_agente(conn, empresa_id, "servidor-web-01")

    assert agente["hostname"] == "servidor-web-01"
    assert agente["status"] == "ativo"
    assert agente["empresa_id"] == str(empresa_id)
    assert "token_hash" not in agente
    assert token.startswith("agt_")


@pytest.mark.asyncio
async def test_criar_agente_com_hostname_duplicado_na_mesma_empresa_retorna_none(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Agentes Duplicado")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        await servico.criar_agente(conn, empresa_id, "servidor-duplicado")
        agente_2, token_2 = await servico.criar_agente(conn, empresa_id, "servidor-duplicado")

    assert agente_2 is None
    assert token_2 is None


@pytest.mark.asyncio
async def test_criar_agente_apos_revogar_o_anterior_com_mesmo_hostname_funciona(pool, empresa_factory):
    """
    Correção de bug de revisão crítica (2026-09): a UNIQUE constraint
    original (0016_agentes_endpoint.sql) era de tabela inteira, sem
    escopo de status -- revogar um agente (que nunca apaga a linha, ver
    revogar_agente) travava aquele hostname PARA SEMPRE, mesmo sem nenhum
    agente ativo usando-o. migrations/0017_agentes_hostname_unico_ativo.sql
    troca isso por um índice único PARCIAL (`WHERE status = 'ativo'`) --
    este teste é a regressão de ponta a ponta: revogar e depois recriar o
    MESMO hostname na MESMA empresa precisa funcionar.
    """
    empresa_id = await empresa_factory("Empresa Agentes Reemitir Apos Revogar")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        agente_1, token_1 = await servico.criar_agente(conn, empresa_id, "servidor-reemitir")
        assert agente_1 is not None

        revogado = await servico.revogar_agente(conn, empresa_id, agente_1["id"])
        assert revogado["status"] == "revogado"

        agente_2, token_2 = await servico.criar_agente(conn, empresa_id, "servidor-reemitir")
        assert agente_2 is not None
        assert token_2 is not None
        assert agente_2["id"] != agente_1["id"]  # linha nova, a antiga (revogada) continua intacta
        assert agente_2["status"] == "ativo"
        assert token_2 != token_1

        listados = await servico.listar_agentes(conn)
    # as DUAS linhas continuam existindo -- revogar nunca apaga histórico,
    # mesmo quando um novo agente ativo reusa o hostname.
    assert sorted(a["id"] for a in listados) == sorted([agente_1["id"], agente_2["id"]])
    assert {a["status"] for a in listados if a["id"] == agente_1["id"]} == {"revogado"}
    assert {a["status"] for a in listados if a["id"] == agente_2["id"]} == {"ativo"}


@pytest.mark.asyncio
async def test_criar_agente_com_dois_ativos_mesmo_hostname_ainda_falha(pool, empresa_factory):
    """Confirma que o índice parcial continua protegendo o caso original --
    dois agentes ATIVOS simultâneos para o mesmo hostname na mesma empresa
    continua sendo um 409, exatamente como antes da correção."""
    empresa_id = await empresa_factory("Empresa Agentes Dois Ativos Mesmo Hostname")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        agente_1, _ = await servico.criar_agente(conn, empresa_id, "servidor-dois-ativos")
        assert agente_1 is not None

        agente_2, token_2 = await servico.criar_agente(conn, empresa_id, "servidor-dois-ativos")
    assert agente_2 is None
    assert token_2 is None


@pytest.mark.asyncio
async def test_mesmo_hostname_em_empresas_diferentes_nao_colide(pool, empresa_factory):
    empresa_a = await empresa_factory("Empresa Agentes Hostname A")
    empresa_b = await empresa_factory("Empresa Agentes Hostname B")

    async with tenant_scoped_connection(pool, empresa_a) as conn_a:
        agente_a, _ = await servico.criar_agente(conn_a, empresa_a, "servidor-mesmo-nome")
    async with tenant_scoped_connection(pool, empresa_b) as conn_b:
        agente_b, _ = await servico.criar_agente(conn_b, empresa_b, "servidor-mesmo-nome")

    assert agente_a is not None
    assert agente_b is not None
    assert agente_a["id"] != agente_b["id"]


@pytest.mark.asyncio
async def test_listar_agentes_de_uma_empresa_nao_mostra_agente_de_outra(pool, empresa_factory):
    empresa_a = await empresa_factory("Empresa Agentes Listar A")
    empresa_b = await empresa_factory("Empresa Agentes Listar B")

    async with tenant_scoped_connection(pool, empresa_a) as conn_a:
        await servico.criar_agente(conn_a, empresa_a, "host-a-1")

    async with tenant_scoped_connection(pool, empresa_b) as conn_b:
        await servico.criar_agente(conn_b, empresa_b, "host-b-1")
        listados_b = await servico.listar_agentes(conn_b)

    assert [a["hostname"] for a in listados_b] == ["host-b-1"]


@pytest.mark.asyncio
async def test_revogar_agente_e_idempotente_e_preserva_a_linha(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Agentes Revogar")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        agente, _ = await servico.criar_agente(conn, empresa_id, "servidor-a-revogar")

        revogado_1 = await servico.revogar_agente(conn, empresa_id, agente["id"])
        assert revogado_1["status"] == "revogado"

        # revogar de novo não é erro -- só reafirma o mesmo estado
        revogado_2 = await servico.revogar_agente(conn, empresa_id, agente["id"])
        assert revogado_2["status"] == "revogado"

        listados = await servico.listar_agentes(conn)
    assert any(a["id"] == agente["id"] for a in listados)  # revogar nunca apaga a linha


@pytest.mark.asyncio
async def test_revogar_agente_inexistente_retorna_none(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Agentes Revogar Inexistente")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        assert await servico.revogar_agente(conn, empresa_id, str(uuid.uuid4())) is None


@pytest.mark.asyncio
async def test_revogar_agente_de_outra_empresa_nao_afeta_nada(pool, empresa_factory):
    """RLS por si só já impediria a UPDATE de enxergar a linha (`WHERE ...
    AND empresa_id = $2` é redundante com a policy), mas o teste confirma
    o comportamento de ponta a ponta pela camada de serviço."""
    empresa_a = await empresa_factory("Empresa Agentes Revogar Cross A")
    empresa_b = await empresa_factory("Empresa Agentes Revogar Cross B")

    async with tenant_scoped_connection(pool, empresa_a) as conn_a:
        agente_a, _ = await servico.criar_agente(conn_a, empresa_a, "host-cross-a")

    async with tenant_scoped_connection(pool, empresa_b) as conn_b:
        resultado = await servico.revogar_agente(conn_b, empresa_b, agente_a["id"])
    assert resultado is None

    async with tenant_scoped_connection(pool, empresa_a) as conn_a:
        linha = await conn_a.fetchrow("SELECT status FROM agentes WHERE id = $1", agente_a["id"])
    assert linha["status"] == "ativo"


# ---------------------------------------------------------------------------
# revogar_agente <-> services.licenciamento.liberar_endpoint (correção
# pós-auditoria, GAP_REPORT_V3.1.md Fase 18 -- ver docstring de
# revogar_agente para o porquê e para os limites explícitos desta correção).
# ---------------------------------------------------------------------------

async def _plano_id_teste(pool, max_endpoints=5):
    """Plano isolado por teste (nome único) -- evita depender do valor exato
    seedado para 'starter', que pode mudar (mesmo padrão já usado em
    test_licenciamento_service.py:test_registrar_endpoint_recusa_acima_do_limite_do_plano)."""
    async with superadmin_scoped_connection(pool) as conn_admin:
        return await conn_admin.fetchval(
            "INSERT INTO planos (codigo, nome_exibicao, max_endpoints) VALUES ($1, $2, $3) RETURNING id",
            f"teste-revogar-agente-{uuid.uuid4().hex[:8]}", "Plano De Teste Revogar Agente", max_endpoints,
        )


@pytest.mark.asyncio
async def test_revogar_agente_libera_a_vaga_de_endpoint_que_ele_ocupava(pool, empresa_factory):
    """Antes desta correção, `liberar_endpoint` existia mas nunca era
    chamada por `revogar_agente` -- um agente revogado continuava contando
    para sempre contra `planos.max_endpoints` (vazamento de vaga). Cria um
    plano de 1 vaga só, ocupa com o agente, revoga o agente, e confirma que
    a vaga liberada aceita um agente novo -- ponta a ponta, não só o
    UPDATE isolado (que já é coberto por
    test_licenciamento_service.py:test_liberar_endpoint_abre_vaga_para_um_agente_novo)."""
    empresa_id = await empresa_factory("Empresa Revogar Agente Libera Vaga")
    plano_id = await _plano_id_teste(pool, max_endpoints=1)

    async with tenant_scoped_connection(pool, empresa_id) as conn:
        licenca, _ = await servico_licenciamento.criar_licenca(conn, empresa_id, plano_id)
        agente_1, _ = await servico.criar_agente(conn, empresa_id, "host-revogar-libera-1")
        await servico_licenciamento.registrar_endpoint(conn, empresa_id, licenca["id"], agente_1["id"])

        ocupadas_antes = await conn.fetchval(
            "SELECT count(*) FROM licencas_endpoints WHERE licenca_id = $1 AND liberado_em IS NULL", licenca["id"],
        )
        assert ocupadas_antes == 1

        await servico.revogar_agente(conn, empresa_id, agente_1["id"])

        vaga = await conn.fetchrow(
            "SELECT liberado_em FROM licencas_endpoints WHERE agente_id = $1", agente_1["id"],
        )
        assert vaga["liberado_em"] is not None

        # a vaga liberada aceita um agente DIFERENTE -- prova de ponta a
        # ponta de que o plano de 1 vaga não ficou permanentemente ocupado
        # por um agente que já foi revogado.
        agente_2, _ = await servico.criar_agente(conn, empresa_id, "host-revogar-libera-2")
        vaga_nova = await servico_licenciamento.registrar_endpoint(conn, empresa_id, licenca["id"], agente_2["id"])
        assert vaga_nova["agente_id"] == str(agente_2["id"])


@pytest.mark.asyncio
async def test_revogar_agente_grava_na_auditoria_se_havia_vaga_para_liberar(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Revogar Agente Auditoria Vaga")
    plano_id = await _plano_id_teste(pool)

    async with tenant_scoped_connection(pool, empresa_id) as conn:
        licenca, _ = await servico_licenciamento.criar_licenca(conn, empresa_id, plano_id)
        agente, _ = await servico.criar_agente(conn, empresa_id, "host-revogar-auditoria-com-vaga")
        await servico_licenciamento.registrar_endpoint(conn, empresa_id, licenca["id"], agente["id"])

        await servico.revogar_agente(conn, empresa_id, agente["id"])

        auditoria = await conn.fetchrow(
            "SELECT detalhes FROM auditoria WHERE empresa_id = $1 AND acao = 'agente.revogado' ORDER BY criado_em DESC LIMIT 1",
            empresa_id,
        )
    detalhes = auditoria["detalhes"] if isinstance(auditoria["detalhes"], dict) else json.loads(auditoria["detalhes"])
    assert detalhes["vaga_endpoint_liberada"] is True


@pytest.mark.asyncio
async def test_revogar_agente_sem_vaga_nenhuma_nao_falha_e_audita_honestamente(pool, empresa_factory):
    """Um agente que nunca ocupou vaga nenhuma (nenhum registrar_endpoint
    chamado para ele) precisa continuar revogável normalmente --
    `liberar_endpoint` devolve None nesse caso, e o payload de auditoria
    reflete isso (`vaga_endpoint_liberada: False`) em vez de fingir que uma
    vaga foi liberada."""
    empresa_id = await empresa_factory("Empresa Revogar Agente Sem Vaga")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        agente, _ = await servico.criar_agente(conn, empresa_id, "host-revogar-sem-vaga")

        revogado = await servico.revogar_agente(conn, empresa_id, agente["id"])
        assert revogado["status"] == "revogado"

        auditoria = await conn.fetchrow(
            "SELECT detalhes FROM auditoria WHERE empresa_id = $1 AND acao = 'agente.revogado' ORDER BY criado_em DESC LIMIT 1",
            empresa_id,
        )
    detalhes = auditoria["detalhes"] if isinstance(auditoria["detalhes"], dict) else json.loads(auditoria["detalhes"])
    assert detalhes["vaga_endpoint_liberada"] is False


# ---------------------------------------------------------------------------
# criar_agente <-> vínculo automático com a licença ativa da empresa
# (Fase D / D1 -- ver ARQUITETURA_LICENCIAMENTO.md §10 para a decisão de
# arquitetura completa: por que na CRIAÇÃO do agente, não na ativação da
# licença nem numa rota administrativa dedicada).
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_criar_agente_vincula_automaticamente_a_licenca_ativa_da_empresa(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Agentes D1 Autobind")
    plano_id = await _plano_id_teste(pool, max_endpoints=5)
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        licenca, _ = await servico_licenciamento.criar_licenca(conn, empresa_id, plano_id)
        agente, _ = await servico.criar_agente(conn, empresa_id, "host-d1-autobind")

        vaga = await conn.fetchrow(
            "SELECT licenca_id, liberado_em FROM licencas_endpoints WHERE agente_id = $1", agente["id"],
        )
    assert vaga is not None
    assert vaga["liberado_em"] is None
    assert vaga["licenca_id"] == uuid.UUID(licenca["id"])


@pytest.mark.asyncio
async def test_criar_agente_sem_licenca_ativa_nao_cria_nenhum_vinculo(pool, empresa_factory):
    """Uma empresa sem NENHUMA licença ativa (licenciamento continua
    opcional -- ver migrations/0019_licenciamento.sql) cria agentes
    normalmente, sem vínculo nenhum. Cobre também o caso "a única licença
    que existe já foi revogada" -- não é só "nunca teve licença nenhuma"."""
    empresa_id = await empresa_factory("Empresa Agentes D1 Sem Licenca Ativa")
    plano_id = await _plano_id_teste(pool)
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        licenca, _ = await servico_licenciamento.criar_licenca(conn, empresa_id, plano_id)
        await servico_licenciamento.revogar_licenca(conn, empresa_id, licenca["id"])

        agente, _ = await servico.criar_agente(conn, empresa_id, "host-d1-sem-licenca-ativa")

        vaga = await conn.fetchrow("SELECT id FROM licencas_endpoints WHERE agente_id = $1", agente["id"])
    assert agente is not None
    assert vaga is None


@pytest.mark.asyncio
async def test_criar_agente_alem_do_limite_da_licenca_falha_e_reverte_a_criacao_inteira(pool, empresa_factory):
    """O limite de `planos.max_endpoints` agora é aplicado NA CRIAÇÃO do
    agente (D1), não só numa chamada manual a registrar_endpoint -- e a
    falha reverte a transação INTEIRA (o agente não fica com uma linha
    'órfã' sem vaga): `LimiteEndpointsExcedidoError` só é levantada depois
    do INSERT de `agentes`, então só um rollback de verdade (exceção
    escapando de `tenant_scoped_connection`, não só capturada com
    pytest.raises dentro do mesmo bloco) prova que nada ficou persistido."""
    empresa_id = await empresa_factory("Empresa Agentes D1 Limite Reverte Criacao")
    plano_id = await _plano_id_teste(pool, max_endpoints=1)
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        licenca, _ = await servico_licenciamento.criar_licenca(conn, empresa_id, plano_id)
        await servico.criar_agente(conn, empresa_id, "host-d1-limite-criacao-1")  # ocupa a única vaga

    with pytest.raises(servico_licenciamento.LimiteEndpointsExcedidoError):
        async with tenant_scoped_connection(pool, empresa_id) as conn:
            await servico.criar_agente(conn, empresa_id, "host-d1-limite-criacao-2")

    async with tenant_scoped_connection(pool, empresa_id) as conn:
        linha = await conn.fetchrow(
            "SELECT id FROM agentes WHERE empresa_id = $1 AND hostname = $2",
            empresa_id, "host-d1-limite-criacao-2",
        )
        ocupadas = await conn.fetchval(
            "SELECT count(*) FROM licencas_endpoints WHERE licenca_id = $1 AND liberado_em IS NULL", licenca["id"],
        )
    assert linha is None  # o INSERT do agente foi revertido junto com o resto da transação
    assert ocupadas == 1  # continua só a vaga do primeiro agente


# ---------------------------------------------------------------------------
# registrar_heartbeat -- evento bruto sempre, incidente só quando há sinal
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_heartbeat_com_hostname_divergente_e_rejeitado_sem_gravar_nada(pool, empresa_factory):
    """
    Item "should fix" (6) da revisão crítica (2026-09): o token identifica
    UM agente ligado a UM hostname registrado na criação -- o campo
    `hostname` do corpo do heartbeat não pode ser uma alegação livre. Um
    hostname divergente é rejeitado (`AgenteHostnameDivergenteError`) ANTES
    de qualquer INSERT/UPDATE de heartbeat normal (nenhum evento
    'heartbeat' ou 'processo_suspeito' é gravado), mas GERA um evento de
    auditoria específico da divergência -- o sinal de "token X afirmou ser
    hostname Y" não deveria simplesmente desaparecer.
    """
    empresa_id = await empresa_factory("Empresa Agentes Heartbeat Hostname Divergente")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        agente, _ = await servico.criar_agente(conn, empresa_id, "host-verdadeiro")

        with pytest.raises(servico.AgenteHostnameDivergenteError):
            await servico.registrar_heartbeat(
                conn, empresa_id, agente["id"], "host-fingido", "linux", "0.1.0", 42, [], None,
            )

        eventos_heartbeat = await conn.fetch(
            "SELECT tipo FROM agentes_eventos WHERE agente_id = $1", agente["id"],
        )
        linha_agente = await conn.fetchrow(
            "SELECT ultimo_heartbeat_em FROM agentes WHERE id = $1", agente["id"],
        )
        auditoria = await conn.fetchrow(
            "SELECT acao, detalhes FROM auditoria WHERE empresa_id = $1 AND acao = 'agente.heartbeat_hostname_divergente'",
            empresa_id,
        )

    assert eventos_heartbeat == []  # nenhum heartbeat normal foi gravado
    assert linha_agente["ultimo_heartbeat_em"] is None  # nem o timestamp de heartbeat avançou
    assert auditoria is not None
    detalhes = json.loads(auditoria["detalhes"])
    assert detalhes["hostname_registrado"] == "host-verdadeiro"
    assert detalhes["hostname_recebido"] == "host-fingido"


@pytest.mark.asyncio
async def test_heartbeat_tolera_diferenca_de_maiuscula_e_espaco_no_hostname(pool, empresa_factory):
    """
    Correção de bug de revisão crítica (2026-09), segunda rodada: a
    comparação de hostname original era um `==` byte a byte -- hostname do
    Windows é case-insensitive por natureza do SO, e o valor "registrado"
    vem de texto livre digitado por um admin humano no cadastro. Uma
    diferença de caixa ou um espaço colado por engano bastaria para deixar
    um agente recém-provisionado incapaz de mandar um único heartbeat.
    Agora a comparação tolera isso (strip + casefold), sem mudar o que fica
    persistido/exibido em `agentes.hostname`.
    """
    empresa_id = await empresa_factory("Empresa Agentes Heartbeat Hostname Tolerante")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        agente, _ = await servico.criar_agente(conn, empresa_id, "Servidor-Web-01")

        # diferença só de caixa
        incidente = await servico.registrar_heartbeat(
            conn, empresa_id, agente["id"], "servidor-web-01", "linux", "0.1.0", 10, [], None,
        )
        assert incidente is None  # não suspeito, mas não deveria levantar AgenteHostnameDivergenteError

        # diferença de caixa + espaço nas pontas
        incidente_2 = await servico.registrar_heartbeat(
            conn, empresa_id, agente["id"], "  SERVIDOR-WEB-01  ", "linux", "0.1.0", 11, [], None,
        )
        assert incidente_2 is None

        linha_agente = await conn.fetchrow("SELECT hostname FROM agentes WHERE id = $1", agente["id"])
    # o valor PERSISTIDO/exibido nunca muda -- só a comparação ficou tolerante.
    assert linha_agente["hostname"] == "Servidor-Web-01"


@pytest.mark.asyncio
async def test_heartbeat_ainda_rejeita_hostname_realmente_diferente_apos_normalizar(pool, empresa_factory):
    """A tolerância é só para maiúscula/espaço -- um hostname genuinamente
    diferente continua rejeitado."""
    empresa_id = await empresa_factory("Empresa Agentes Heartbeat Hostname Ainda Rejeita")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        agente, _ = await servico.criar_agente(conn, empresa_id, "servidor-a")
        with pytest.raises(servico.AgenteHostnameDivergenteError):
            await servico.registrar_heartbeat(
                conn, empresa_id, agente["id"], "servidor-b", "linux", "0.1.0", 10, [], None,
            )


@pytest.mark.asyncio
async def test_heartbeat_sem_processos_suspeitos_nao_cria_incidente_mas_grava_evento(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Agentes Heartbeat Limpo")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        agente, _ = await servico.criar_agente(conn, empresa_id, "host-heartbeat-limpo")

        incidente = await servico.registrar_heartbeat(
            conn, empresa_id, agente["id"], "host-heartbeat-limpo", "linux", "0.1.0", 42, [], None,
        )
        eventos = await conn.fetch(
            "SELECT tipo FROM agentes_eventos WHERE agente_id = $1", agente["id"],
        )
        linha_agente = await conn.fetchrow(
            "SELECT ultimo_heartbeat_em, sistema_operacional FROM agentes WHERE id = $1", agente["id"],
        )

    assert incidente is None
    assert [e["tipo"] for e in eventos] == ["heartbeat"]
    assert linha_agente["ultimo_heartbeat_em"] is not None
    assert linha_agente["sistema_operacional"] == "linux"


@pytest.mark.asyncio
async def test_heartbeat_com_processo_suspeito_cria_incidente_origem_endpoint(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Agentes Heartbeat Suspeito")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        agente, _ = await servico.criar_agente(conn, empresa_id, "host-heartbeat-suspeito")

        # Nome genérico (não bate com _INDICADORES_CRITICOS) -- este teste
        # cobre o pipeline de heartbeat->incidente com a heurística PURA de
        # contagem. A interação com indicador crítico conhecido tem teste
        # próprio logo abaixo.
        processos = [{"pid": 1234, "nome": "processo_desconhecido.exe", "usuario": "SYSTEM", "linha_de_comando": "processo_desconhecido.exe --run"}]
        incidente = await servico.registrar_heartbeat(
            conn, empresa_id, agente["id"], "host-heartbeat-suspeito", "windows", "0.1.0", 100, processos, None,
        )
        tipos_evento = {
            r["tipo"] for r in await conn.fetch(
                "SELECT tipo FROM agentes_eventos WHERE agente_id = $1", agente["id"],
            )
        }

    assert incidente is not None
    assert incidente["origem"] == "endpoint"
    assert incidente["severidade"] == "MEDIUM"  # 1 processo suspeito, sem indicador crítico == score 55 (ver avaliar_risco_endpoint)
    assert incidente["ip"] == "0.0.0.0"  # sem ip_local informado -- placeholder para a coluna NOT NULL herdada
    assert tipos_evento == {"heartbeat", "processo_suspeito"}


@pytest.mark.asyncio
async def test_heartbeat_com_indicador_critico_conhecido_cria_incidente_critical(pool, empresa_factory):
    """
    Correção de bug de revisão crítica (2026-09): um único processo
    batendo com um indicador de ferramenta de ataque conhecida (ex.:
    mimikatz) precisa abrir um incidente CRITICAL, não MEDIUM -- é
    exatamente esta interação (severidade subestimada + auto-triage, ver
    tests/integration/test_automacao_service.py) que permitia uma detecção
    real de comprometimento ser descartada como falso positivo depois de
    72h sem revisão humana.
    """
    empresa_id = await empresa_factory("Empresa Agentes Heartbeat Indicador Critico")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        agente, _ = await servico.criar_agente(conn, empresa_id, "host-heartbeat-indicador-critico")
        processos = [{"pid": 4321, "nome": "mimikatz", "usuario": "SYSTEM", "linha_de_comando": "mimikatz.exe"}]
        incidente = await servico.registrar_heartbeat(
            conn, empresa_id, agente["id"], "host-heartbeat-indicador-critico", "windows", "0.1.0", 100, processos, None,
        )

    assert incidente is not None
    assert incidente["origem"] == "endpoint"
    assert incidente["severidade"] == "CRITICAL"


@pytest.mark.asyncio
async def test_heartbeats_consecutivos_do_mesmo_processo_nao_abrem_incidente_novo_a_cada_ciclo(pool, empresa_factory):
    """
    Correção de bug de revisão crítica (2026-09), segunda rodada: um
    processo suspeito RESIDENTE (mimikatz que continua rodando) abria um
    incidente CRITICAL novo a cada heartbeat -- a cada 15-30s,
    indefinidamente -- inundando a tabela de incidentes. Agora, enquanto o
    agente já tem um incidente OPEN, a detecção seguinte é ANEXADA ao
    mesmo incidente (nunca abre um segundo), e os ataques de cada heartbeat
    ficam todos registrados (histórico completo, não sobrescrito).
    """
    empresa_id = await empresa_factory("Empresa Agentes Heartbeat Dedup")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        agente, _ = await servico.criar_agente(conn, empresa_id, "host-heartbeat-dedup")
        processos = [{"pid": 4321, "nome": "mimikatz", "usuario": "SYSTEM", "linha_de_comando": "mimikatz.exe"}]

        incidente_1 = await servico.registrar_heartbeat(
            conn, empresa_id, agente["id"], "host-heartbeat-dedup", "windows", "0.1.0", 100, processos, None,
        )
        incidente_2 = await servico.registrar_heartbeat(
            conn, empresa_id, agente["id"], "host-heartbeat-dedup", "windows", "0.1.0", 100, processos, None,
        )
        incidente_3 = await servico.registrar_heartbeat(
            conn, empresa_id, agente["id"], "host-heartbeat-dedup", "windows", "0.1.0", 100, processos, None,
        )

        total_incidentes = await conn.fetchval(
            "SELECT count(*) FROM incidentes WHERE empresa_id = $1 AND agente_id = $2", empresa_id, agente["id"],
        )
        linha = await conn.fetchrow(
            "SELECT ataques FROM incidentes WHERE incident_id = $1", incidente_1["incident_id"],
        )

    assert incidente_1["incident_id"] == incidente_2["incident_id"] == incidente_3["incident_id"]
    assert total_incidentes == 1  # nunca um segundo incidente para o mesmo agente
    ataques = json.loads(linha["ataques"])
    assert len(ataques) == 3  # os 3 heartbeats ficaram registrados, nenhum sobrescrito


@pytest.mark.asyncio
async def test_heartbeat_abre_novo_incidente_apos_o_anterior_ser_resolvido(pool, empresa_factory):
    """A deduplicação só vale enquanto o incidente anterior está
    OPEN/EM_ANDAMENTO -- depois de RESOLVIDO/FALSO_POSITIVO (um humano ou a
    auto-triagem já julgou aquele caso), uma detecção nova abre um
    incidente NOVO de propósito."""
    empresa_id = await empresa_factory("Empresa Agentes Heartbeat Dedup Reaberto")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        agente, _ = await servico.criar_agente(conn, empresa_id, "host-heartbeat-dedup-reaberto")
        processos = [{"pid": 1, "nome": "mimikatz"}]

        incidente_1 = await servico.registrar_heartbeat(
            conn, empresa_id, agente["id"], "host-heartbeat-dedup-reaberto", "windows", "0.1.0", 100, processos, None,
        )
        await servico_incidentes.atualizar_status(conn, empresa_id, incidente_1["incident_id"], "RESOLVIDO")

        incidente_2 = await servico.registrar_heartbeat(
            conn, empresa_id, agente["id"], "host-heartbeat-dedup-reaberto", "windows", "0.1.0", 100, processos, None,
        )

        total_incidentes = await conn.fetchval(
            "SELECT count(*) FROM incidentes WHERE empresa_id = $1 AND agente_id = $2", empresa_id, agente["id"],
        )

    assert incidente_2["incident_id"] != incidente_1["incident_id"]
    assert total_incidentes == 2


@pytest.mark.asyncio
async def test_heartbeat_dedup_escala_severidade_mas_nunca_rebaixa(pool, empresa_factory):
    """Um processo indicador crítico (CRITICAL/95) seguido de um processo
    genérico (MEDIUM/55) no mesmo incidente aberto NÃO deve rebaixar a
    severidade -- e o caminho inverso (genérico depois crítico) deve
    escalar."""
    empresa_id = await empresa_factory("Empresa Agentes Heartbeat Dedup Severidade")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        agente, _ = await servico.criar_agente(conn, empresa_id, "host-heartbeat-dedup-severidade")

        incidente_1 = await servico.registrar_heartbeat(
            conn, empresa_id, agente["id"], "host-heartbeat-dedup-severidade", "windows", "0.1.0", 100,
            [{"pid": 1, "nome": "mimikatz"}], None,
        )
        assert incidente_1["severidade"] == "CRITICAL"

        incidente_2 = await servico.registrar_heartbeat(
            conn, empresa_id, agente["id"], "host-heartbeat-dedup-severidade", "windows", "0.1.0", 100,
            [{"pid": 2, "nome": "processo_desconhecido.exe"}], None,
        )

    assert incidente_2["incident_id"] == incidente_1["incident_id"]
    assert incidente_2["severidade"] == "CRITICAL"  # nunca rebaixa para MEDIUM


@pytest.mark.asyncio
async def test_heartbeat_usa_ip_local_quando_informado(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Agentes Heartbeat IP")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        agente, _ = await servico.criar_agente(conn, empresa_id, "host-heartbeat-ip")
        incidente = await servico.registrar_heartbeat(
            conn, empresa_id, agente["id"], "host-heartbeat-ip", "linux", "0.1.0", 10,
            [{"pid": 1, "nome": "nc"}], "10.0.0.5",
        )
    assert incidente["ip"] == "10.0.0.5"


@pytest.mark.asyncio
async def test_heartbeats_de_agentes_de_empresas_diferentes_nao_se_misturam(pool, empresa_factory):
    empresa_a = await empresa_factory("Empresa Agentes Heartbeat Cross A")
    empresa_b = await empresa_factory("Empresa Agentes Heartbeat Cross B")

    async with tenant_scoped_connection(pool, empresa_a) as conn_a:
        agente_a, _ = await servico.criar_agente(conn_a, empresa_a, "host-cross-hb-a")
        await servico.registrar_heartbeat(
            conn_a, empresa_a, agente_a["id"], "host-cross-hb-a", "linux", "0.1.0", 5,
            [{"pid": 1, "nome": "nmap"}], None,
        )

    async with tenant_scoped_connection(pool, empresa_b) as conn_b:
        incidentes_b = await conn_b.fetch("SELECT incident_id FROM incidentes WHERE origem = 'endpoint'")
    assert incidentes_b == []


# ---------------------------------------------------------------------------
# autenticar_agente (auth/agentes.py) contra dados reais -- prefixo, hash,
# status='ativo'/'revogado', empresa/agentes_endpoint_habilitado (esta
# última checagem em si é de conexao_tenant_agente, testada em
# tests/api/test_agentes_api.py; aqui só o lookup do TOKEN em si).
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_autenticar_agente_com_token_valido(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Agentes Autenticar")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        agente, token = await servico.criar_agente(conn, empresa_id, "host-autenticar")

    resultado = await autenticar_agente(pool, token)
    # autenticar_agente devolve o Record cru do asyncpg (não passa por
    # _publico()) -- agente_id/empresa_id saem como uuid.UUID, não str.
    assert resultado == {"agente_id": uuid.UUID(agente["id"]), "empresa_id": empresa_id, "hostname": "host-autenticar"}


@pytest.mark.asyncio
async def test_autenticar_agente_com_token_errado_falha(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Agentes Autenticar Errado")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        await servico.criar_agente(conn, empresa_id, "host-autenticar-errado")

    assert await autenticar_agente(pool, "agt_000000000000_token-forjado-qualquer") is None
    assert await autenticar_agente(pool, "token-sem-formato-nenhum") is None


@pytest.mark.asyncio
async def test_autenticar_agente_revogado_falha(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Agentes Autenticar Revogado")
    async with tenant_scoped_connection(pool, empresa_id) as conn:
        agente, token = await servico.criar_agente(conn, empresa_id, "host-autenticar-revogado")
        await servico.revogar_agente(conn, empresa_id, agente["id"])

    assert await autenticar_agente(pool, token) is None
