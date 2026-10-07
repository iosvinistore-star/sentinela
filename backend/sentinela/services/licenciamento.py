# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Regras de negócio de licenciamento (planos, licenças, ocupação de vagas de
endpoint) -- ver ARQUITETURA_LICENCIAMENTO.md para o desenho completo.

Convenção seguida do resto de services/*.py: toda função recebe uma conexão
JÁ escopada (tenant_scoped_connection ou superadmin_scoped_connection,
dependendo da rota) -- nunca abre conexão própria. Ações administrativas
chamam `services/auditoria.py:registrar_evento` na MESMA transação (atômico
com a ação); validações de alta frequência do Agent gravam em
`licencas_eventos` em vez de `auditoria`, pelo motivo documentado na
migration 0019 (não poluir o audit log administrativo com ruído de
heartbeat).
"""
import json

from sentinela.auth.licencas import gerar_token
from sentinela.auth.security import hash_senha
from sentinela.services import auditoria as servico_auditoria

STATUS_VALIDOS = {"ativa", "suspensa", "expirada", "revogada"}


class PlanoInvalidoError(ValueError):
    """Levantado quando `plano_id` não corresponde a um plano existente/ativo."""


class LimiteEndpointsExcedidoError(ValueError):
    """
    Levantado por `registrar_endpoint` quando a licença já está usando todas
    as vagas que `planos.max_endpoints` permite. A rota traduz isto para
    HTTP 409 -- nunca deixa o agente novo "furar" o limite silenciosamente.
    """


def _publico_licenca(row):
    if row is None:
        return None
    d = dict(row)
    for campo in ("id", "empresa_id", "plano_id", "criado_por_usuario_id", "criado_por_superadmin_id"):
        if d.get(campo) is not None:
            d[campo] = str(d[campo])
    # token_hash NUNCA sai desta função para fora do serviço -- nem em
    # resposta de API nem em log. Mesmo cuidado de services/agentes.py.
    d.pop("token_hash", None)
    return d


def _publico_plano(row):
    if row is None:
        return None
    d = dict(row)
    d["id"] = str(d["id"])
    # asyncpg devolve jsonb já decodificado como dict/list/str conforme o
    # driver -- mas por segurança (algumas configurações de codec
    # devolvem string crua) normaliza aqui.
    if isinstance(d.get("recursos"), str):
        d["recursos"] = json.loads(d["recursos"])
    return d


async def listar_planos(conn):
    rows = await conn.fetch("SELECT * FROM planos WHERE ativo = true ORDER BY max_endpoints ASC")
    return [_publico_plano(r) for r in rows]


async def obter_plano(conn, plano_id):
    row = await conn.fetchrow("SELECT * FROM planos WHERE id = $1", plano_id)
    return _publico_plano(row)


async def listar_licencas(conn):
    """Conn tenant-scoped -> RLS já filtra pra empresa do chamador."""
    rows = await conn.fetch("SELECT * FROM licencas ORDER BY criado_em DESC")
    return [_publico_licenca(r) for r in rows]


async def criar_licenca(conn, empresa_id, plano_id, expira_em=None,
                          ator_usuario_id=None, ator_superadmin_id=None):
    """
    Cria uma licença nova para `empresa_id`. Retorna (licenca_publica,
    token_completo) -- o token só existe aqui, uma vez; depois disso só o
    hash persiste (mesma filosofia de services/agentes.py:criar_agente e de
    criar_superadmins.py). Levanta PlanoInvalidoError se `plano_id` não
    existir/não estiver ativo -- checado explicitamente para não deixar
    vazar um asyncpg.ForeignKeyViolationError cru (mesmo raciocínio do
    comentário equivalente em api/v1/admin.py:criar_usuario_da_empresa).
    """
    plano = await conn.fetchrow("SELECT id FROM planos WHERE id = $1 AND ativo = true", plano_id)
    if plano is None:
        raise PlanoInvalidoError("plano inválido ou inativo")

    token_completo, prefixo = gerar_token()
    token_hash = hash_senha(token_completo)
    row = await conn.fetchrow(
        """
        INSERT INTO licencas (empresa_id, plano_id, token_prefixo, token_hash, expira_em,
                               criado_por_usuario_id, criado_por_superadmin_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
        """,
        empresa_id, plano_id, prefixo, token_hash, expira_em, ator_usuario_id, ator_superadmin_id,
    )
    await servico_auditoria.registrar_evento(
        conn, empresa_id, "licenca.criada", {"licenca_id": str(row["id"]), "plano_id": str(plano_id)},
        ator_usuario_id=ator_usuario_id, ator_superadmin_id=ator_superadmin_id,
    )
    await _registrar_evento_licenca(conn, empresa_id, row["id"], "licenca.criada", {})
    return _publico_licenca(row), token_completo


async def _registrar_evento_licenca(conn, empresa_id, licenca_id, tipo: str, detalhes: dict):
    """Grava em `licencas_eventos` -- histórico de alta frequência, separado
    da tabela `auditoria` genérica (ver docstring do módulo)."""
    await conn.execute(
        "INSERT INTO licencas_eventos (empresa_id, licenca_id, tipo, detalhes) VALUES ($1, $2, $3, $4::jsonb)",
        empresa_id, licenca_id, tipo, json.dumps(detalhes, ensure_ascii=False, default=str),
    )


"""
As quatro funções abaixo (ativar_licenca/validar_licenca/
obter_status_licenca/desativar_licenca) recebem `conn` (tenant-scoped) e
`licenca` (o dict resolvido pelo token -- ver auth/dependencies.py:
licenca_atual + conexao_tenant_licenca, que espelham agente_atual +
conexao_tenant_agente): a resolução do token via BYPASSRLS e a abertura da
conexão escopada acontecem na camada de dependências do FastAPI, exatamente
como já acontece para agentes -- este módulo nunca abre conexão própria,
mesma convenção do restante de services/*.py.
"""


async def ativar_licenca(conn, licenca: dict):
    """
    Primeiro contato do Agent. Idempotente -- reativar um token já ativo não
    é erro, só não sobrescreve `ativada_em` se já estiver preenchido (a
    primeira ativação é a que conta para fins de contabilidade/relatório).

    Retorna o dict público da licença (incluindo `status` -- quem chama
    decide se um status != 'ativa' vira 403 na rota).
    """
    row = await conn.fetchrow(
        "UPDATE licencas SET ativada_em = COALESCE(ativada_em, now()) WHERE id = $1 RETURNING *",
        licenca["licenca_id"],
    )
    if row is None:
        return None
    await _registrar_evento_licenca(conn, licenca["empresa_id"], licenca["licenca_id"], "licenca.ativada", {})
    return _publico_licenca(row)


async def validar_licenca(conn, licenca: dict):
    """
    Validação periódica do Agent. Sempre atualiza `ultima_validacao_em`
    (mesmo para uma licença suspensa/expirada/revogada -- o backend registra
    QUE alguém tentou validar, independentemente do resultado; é o dado que
    um dashboard futuro usaria para saber "este agente ainda está tentando
    falar comigo"). Também devolve o plano (limites/recursos, incluindo
    `grace_period_dias` -- ver ARQUITETURA_LICENCIAMENTO.md §6) para o Agent
    calcular sua própria janela de tolerância offline.

    Nunca levanta exceção por status inválido -- devolve o status tal como
    está, quem chama (a rota) decide o HTTPException.
    """
    row = await conn.fetchrow(
        "UPDATE licencas SET ultima_validacao_em = now() WHERE id = $1 RETURNING *",
        licenca["licenca_id"],
    )
    if row is None:
        return None
    plano = await conn.fetchrow("SELECT * FROM planos WHERE id = $1", row["plano_id"])
    await _registrar_evento_licenca(
        conn, licenca["empresa_id"], licenca["licenca_id"], "licenca.validada", {"status": row["status"]},
    )
    publico = _publico_licenca(row)
    publico["plano"] = _publico_plano(plano)
    return publico


async def obter_status_licenca(conn, licenca: dict):
    """Leitura simples, sem side-effect (GET /licencas/status) -- não grava
    evento nem atualiza `ultima_validacao_em` (isso é papel de `validate`,
    que o Agent chama periodicamente; `status` é para inspeção pontual)."""
    row = await conn.fetchrow("SELECT * FROM licencas WHERE id = $1", licenca["licenca_id"])
    return _publico_licenca(row)


async def desativar_licenca(conn, licenca: dict):
    """
    O próprio Agent avisando que está sendo desinstalado (best-effort -- ver
    ARQUITETURA_LICENCIAMENTO.md §5). Não muda `status` da licença (ela
    continua 'ativa' do ponto de vista comercial -- desinstalar o Agent não
    é o mesmo que cancelar a licença, que é uma decisão administrativa via
    `revogar_licenca`/`suspender_licenca`); só registra o evento para
    visibilidade futura.
    """
    await _registrar_evento_licenca(conn, licenca["empresa_id"], licenca["licenca_id"], "licenca.desativada_pelo_agente", {})
    row = await conn.fetchrow("SELECT * FROM licencas WHERE id = $1", licenca["licenca_id"])
    return _publico_licenca(row)


async def _mudar_status(conn, empresa_id, licenca_id, novo_status: str, tipo_evento: str,
                          ator_usuario_id=None, ator_superadmin_id=None):
    row = await conn.fetchrow(
        "UPDATE licencas SET status = $2 WHERE id = $1 RETURNING *", licenca_id, novo_status,
    )
    if row is None:
        return None
    await servico_auditoria.registrar_evento(
        conn, empresa_id, tipo_evento, {"licenca_id": str(licenca_id), "novo_status": novo_status},
        ator_usuario_id=ator_usuario_id, ator_superadmin_id=ator_superadmin_id,
    )
    await _registrar_evento_licenca(conn, empresa_id, licenca_id, tipo_evento, {})
    return _publico_licenca(row)


async def suspender_licenca(conn, empresa_id, licenca_id, ator_usuario_id=None, ator_superadmin_id=None):
    return await _mudar_status(conn, empresa_id, licenca_id, "suspensa", "licenca.suspensa",
                                 ator_usuario_id, ator_superadmin_id)


async def revogar_licenca(conn, empresa_id, licenca_id, ator_usuario_id=None, ator_superadmin_id=None):
    """Nunca DELETE -- preserva o histórico (mesma filosofia de
    services/agentes.py:revogar_agente). Uma licença revogada nunca volta a
    ficar ativa; para "desfazer", cria-se uma licença nova."""
    return await _mudar_status(conn, empresa_id, licenca_id, "revogada", "licenca.revogada",
                                 ator_usuario_id, ator_superadmin_id)


async def renovar_licenca(conn, empresa_id, licenca_id, nova_expiracao=None,
                            ator_usuario_id=None, ator_superadmin_id=None):
    """
    Renovação manual (o "payment confirmed -> license created/renewed" do
    item 6 do escopo original -- hoje acionado só por um superadmin/admin,
    já que cobrança automática está explicitamente fora desta etapa). Volta
    o status para 'ativa' -- uma licença suspensa/expirada que é renovada
    recupera o acesso; uma revogada NÃO (revogação é definitiva, ver
    revogar_licenca).
    """
    row_atual = await conn.fetchrow("SELECT status FROM licencas WHERE id = $1", licenca_id)
    if row_atual is None:
        return None
    if row_atual["status"] == "revogada":
        raise ValueError("licença revogada não pode ser renovada -- crie uma licença nova")
    row = await conn.fetchrow(
        "UPDATE licencas SET status = 'ativa', expira_em = $2 WHERE id = $1 RETURNING *",
        licenca_id, nova_expiracao,
    )
    await servico_auditoria.registrar_evento(
        conn, empresa_id, "licenca.renovada", {"licenca_id": str(licenca_id), "nova_expiracao": str(nova_expiracao)},
        ator_usuario_id=ator_usuario_id, ator_superadmin_id=ator_superadmin_id,
    )
    await _registrar_evento_licenca(conn, empresa_id, licenca_id, "licenca.renovada", {})
    return _publico_licenca(row)


async def registrar_endpoint(conn, empresa_id, licenca_id, agente_id):
    """
    Ocupa uma vaga de endpoint para `agente_id` sob `licenca_id`, aplicando
    o limite `planos.max_endpoints`. Idempotente para o MESMO agente
    (UNIQUE em licencas_endpoints.agente_id -- reprocessar o mesmo agente
    não conta uma segunda vaga, só devolve a vaga já existente).

    Levanta LimiteEndpointsExcedidoError se a licença já estiver usando
    todas as vagas do plano -- a rota traduz para HTTP 409.
    """
    existente = await conn.fetchrow(
        "SELECT * FROM licencas_endpoints WHERE agente_id = $1 AND liberado_em IS NULL", agente_id,
    )
    if existente is not None:
        return dict(existente, id=str(existente["id"]), empresa_id=str(existente["empresa_id"]),
                     licenca_id=str(existente["licenca_id"]), agente_id=str(existente["agente_id"]))

    licenca = await conn.fetchrow("SELECT plano_id FROM licencas WHERE id = $1", licenca_id)
    if licenca is None:
        raise PlanoInvalidoError("licença não encontrada")
    plano = await conn.fetchrow("SELECT max_endpoints FROM planos WHERE id = $1", licenca["plano_id"])
    ocupadas = await conn.fetchval(
        "SELECT count(*) FROM licencas_endpoints WHERE licenca_id = $1 AND liberado_em IS NULL", licenca_id,
    )
    if ocupadas >= plano["max_endpoints"]:
        await _registrar_evento_licenca(
            conn, empresa_id, licenca_id, "licenca.endpoint_negado_limite",
            {"agente_id": str(agente_id), "max_endpoints": plano["max_endpoints"]},
        )
        raise LimiteEndpointsExcedidoError(
            f"limite de {plano['max_endpoints']} endpoints do plano já atingido"
        )

    row = await conn.fetchrow(
        "INSERT INTO licencas_endpoints (empresa_id, licenca_id, agente_id) VALUES ($1, $2, $3) RETURNING *",
        empresa_id, licenca_id, agente_id,
    )
    await _registrar_evento_licenca(conn, empresa_id, licenca_id, "licenca.endpoint_registrado", {"agente_id": str(agente_id)})
    return dict(row, id=str(row["id"]), empresa_id=str(row["empresa_id"]),
                 licenca_id=str(row["licenca_id"]), agente_id=str(row["agente_id"]))


async def liberar_endpoint(conn, empresa_id, agente_id):
    """Soft-release da vaga ocupada por `agente_id` (ex.: quando o agente é
    revogado -- fiação com o fluxo de revogação de agente fica para uma
    etapa futura; a função já existe pronta para ser chamada de lá)."""
    row = await conn.fetchrow(
        "UPDATE licencas_endpoints SET liberado_em = now() WHERE agente_id = $1 AND liberado_em IS NULL RETURNING *",
        agente_id,
    )
    if row is None:
        return None
    await _registrar_evento_licenca(conn, empresa_id, row["licenca_id"], "licenca.endpoint_liberado", {"agente_id": str(agente_id)})
    return dict(row, id=str(row["id"]), empresa_id=str(row["empresa_id"]),
                 licenca_id=str(row["licenca_id"]), agente_id=str(row["agente_id"]))
