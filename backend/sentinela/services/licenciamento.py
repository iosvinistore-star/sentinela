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
import asyncio

from sentinela.auth.licencas import gerar_token
from sentinela.auth.security import hash_senha
from sentinela.repositories.licencas import LicencaRepositorio
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


def _publico_licenca(licenca):
    if licenca is None:
        return None
    d = licenca.para_dict()
    for campo in ("id", "empresa_id", "plano_id", "criado_por_usuario_id", "criado_por_superadmin_id"):
        if d.get(campo) is not None:
            d[campo] = str(d[campo])
    # token_hash NUNCA sai desta função para fora do serviço -- nem em
    # resposta de API nem em log. Mesmo cuidado de services/agentes.py.
    d.pop("token_hash", None)
    return d


def _publico_plano(plano):
    if plano is None:
        return None
    d = plano.para_dict()
    d["id"] = str(d["id"])
    return d


def _publico_vaga(vaga):
    d = vaga.para_dict()
    for campo in ("id", "empresa_id", "licenca_id", "agente_id"):
        d[campo] = str(d[campo])
    return d


async def listar_planos(sessao):
    return [_publico_plano(p) for p in await LicencaRepositorio(sessao).listar_planos_ativos()]


async def obter_plano(sessao, plano_id):
    return _publico_plano(await LicencaRepositorio(sessao).obter_plano(plano_id))


async def listar_licencas(sessao):
    """Conn tenant-scoped -> RLS já filtra pra empresa do chamador."""
    return [_publico_licenca(r) for r in await LicencaRepositorio(sessao).listar()]


async def criar_licenca(sessao, empresa_id, plano_id, expira_em=None,
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
    repo = LicencaRepositorio(sessao)
    if not await repo.plano_ativo_existe(plano_id):
        raise PlanoInvalidoError("plano inválido ou inativo")
    token_completo, prefixo = gerar_token()
    token_hash = await asyncio.to_thread(hash_senha, token_completo)
    row = await repo.criar(
        empresa_id=empresa_id, plano_id=plano_id, token_prefixo=prefixo, token_hash=token_hash,
        expira_em=expira_em, criado_por_usuario_id=ator_usuario_id, criado_por_superadmin_id=ator_superadmin_id,
    )
    await servico_auditoria.registrar_evento(
        sessao, empresa_id, "licenca.criada", {"licenca_id": str(row.id), "plano_id": str(plano_id)},
        ator_usuario_id=ator_usuario_id, ator_superadmin_id=ator_superadmin_id,
    )
    await _registrar_evento_licenca(sessao, empresa_id, row.id, "licenca.criada", {})
    return _publico_licenca(row), token_completo


async def _registrar_evento_licenca(sessao, empresa_id, licenca_id, tipo: str, detalhes: dict):
    """Grava em `licencas_eventos` -- histórico de alta frequência, separado
    da tabela `auditoria` genérica (ver docstring do módulo)."""
    await LicencaRepositorio(sessao).registrar_evento(empresa_id, licenca_id, tipo, detalhes)


"""
As quatro funções abaixo (ativar_licenca/validar_licenca/
obter_status_licenca/desativar_licenca) recebem `sessao` (tenant-scoped) e
`licenca` (o dict resolvido pelo token -- ver auth/dependencies.py:
licenca_atual + conexao_tenant_licenca, que espelham agente_atual +
conexao_tenant_agente): a resolução do token via BYPASSRLS e a abertura da
conexão escopada acontecem na camada de dependências do FastAPI, exatamente
como já acontece para agentes -- este módulo nunca abre conexão própria,
mesma convenção do restante de services/*.py.
"""


async def ativar_licenca(sessao, licenca: dict):
    """
    Primeiro contato do Agent. Idempotente -- reativar um token já ativo não
    é erro, só não sobrescreve `ativada_em` se já estiver preenchido (a
    primeira ativação é a que conta para fins de contabilidade/relatório).

    Retorna o dict público da licença (incluindo `status` -- quem chama
    decide se um status != 'ativa' vira 403 na rota).
    """
    row = await LicencaRepositorio(sessao).marcar_ativada(licenca["licenca_id"])
    if row is None:
        return None
    await _registrar_evento_licenca(sessao, licenca["empresa_id"], licenca["licenca_id"], "licenca.ativada", {})
    return _publico_licenca(row)


async def validar_licenca(sessao, licenca: dict):
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
    repo = LicencaRepositorio(sessao)
    row = await repo.marcar_validada(licenca["licenca_id"])
    if row is None:
        return None
    plano = await repo.obter_plano(row.plano_id)
    await _registrar_evento_licenca(
        sessao, licenca["empresa_id"], licenca["licenca_id"], "licenca.validada", {"status": row.status},
    )
    publico = _publico_licenca(row)
    publico["plano"] = _publico_plano(plano)
    return publico


async def obter_status_licenca(sessao, licenca: dict):
    """Leitura simples, sem side-effect (GET /licencas/status) -- não grava
    evento nem atualiza `ultima_validacao_em` (isso é papel de `validate`,
    que o Agent chama periodicamente; `status` é para inspeção pontual)."""
    return _publico_licenca(await LicencaRepositorio(sessao).obter(licenca["licenca_id"]))


async def desativar_licenca(sessao, licenca: dict):
    """
    O próprio Agent avisando que está sendo desinstalado (best-effort -- ver
    ARQUITETURA_LICENCIAMENTO.md §5). Não muda `status` da licença (ela
    continua 'ativa' do ponto de vista comercial -- desinstalar o Agent não
    é o mesmo que cancelar a licença, que é uma decisão administrativa via
    `revogar_licenca`/`suspender_licenca`); só registra o evento para
    visibilidade futura.
    """
    await _registrar_evento_licenca(sessao, licenca["empresa_id"], licenca["licenca_id"], "licenca.desativada_pelo_agente", {})
    return _publico_licenca(await LicencaRepositorio(sessao).obter(licenca["licenca_id"]))


async def _mudar_status(sessao, empresa_id, licenca_id, novo_status: str, tipo_evento: str,
                          ator_usuario_id=None, ator_superadmin_id=None):
    row = await LicencaRepositorio(sessao).mudar_status(licenca_id, novo_status)
    if row is None:
        return None
    await servico_auditoria.registrar_evento(
        sessao, empresa_id, tipo_evento, {"licenca_id": str(licenca_id), "novo_status": novo_status},
        ator_usuario_id=ator_usuario_id, ator_superadmin_id=ator_superadmin_id,
    )
    await _registrar_evento_licenca(sessao, empresa_id, licenca_id, tipo_evento, {})
    return _publico_licenca(row)


async def suspender_licenca(sessao, empresa_id, licenca_id, ator_usuario_id=None, ator_superadmin_id=None):
    return await _mudar_status(sessao, empresa_id, licenca_id, "suspensa", "licenca.suspensa",
                                 ator_usuario_id, ator_superadmin_id)


async def revogar_licenca(sessao, empresa_id, licenca_id, ator_usuario_id=None, ator_superadmin_id=None):
    """Nunca DELETE -- preserva o histórico (mesma filosofia de
    services/agentes.py:revogar_agente). Uma licença revogada nunca volta a
    ficar ativa; para "desfazer", cria-se uma licença nova."""
    return await _mudar_status(sessao, empresa_id, licenca_id, "revogada", "licenca.revogada",
                                 ator_usuario_id, ator_superadmin_id)


async def renovar_licenca(sessao, empresa_id, licenca_id, nova_expiracao=None,
                            ator_usuario_id=None, ator_superadmin_id=None):
    """
    Renovação manual (o "payment confirmed -> license created/renewed" do
    item 6 do escopo original -- hoje acionado só por um superadmin/admin,
    já que cobrança automática está explicitamente fora desta etapa). Volta
    o status para 'ativa' -- uma licença suspensa/expirada que é renovada
    recupera o acesso; uma revogada NÃO (revogação é definitiva, ver
    revogar_licenca).
    """
    repo = LicencaRepositorio(sessao)
    atual = await repo.obter(licenca_id)
    if atual is None:
        return None
    if atual.status == "revogada":
        raise ValueError("licença revogada não pode ser renovada -- crie uma licença nova")
    row = await repo.renovar(licenca_id, nova_expiracao)
    await servico_auditoria.registrar_evento(
        sessao, empresa_id, "licenca.renovada", {"licenca_id": str(licenca_id), "nova_expiracao": str(nova_expiracao)},
        ator_usuario_id=ator_usuario_id, ator_superadmin_id=ator_superadmin_id,
    )
    await _registrar_evento_licenca(sessao, empresa_id, licenca_id, "licenca.renovada", {})
    return _publico_licenca(row)


async def registrar_endpoint(sessao, empresa_id, licenca_id, agente_id):
    """
    Ocupa uma vaga de endpoint para `agente_id` sob `licenca_id`, aplicando
    o limite `planos.max_endpoints`. Idempotente para o MESMO agente
    (UNIQUE em licencas_endpoints.agente_id -- reprocessar o mesmo agente
    não conta uma segunda vaga, só devolve a vaga já existente).

    Levanta LimiteEndpointsExcedidoError se a licença já estiver usando
    todas as vagas do plano -- a rota traduz para HTTP 409.
    """
    repo = LicencaRepositorio(sessao)
    existente = await repo.obter_vaga_aberta(agente_id)
    if existente is not None:
        return _publico_vaga(existente)
    # FOR UPDATE na linha da licença: serializa registros concorrentes sob a
    # mesma licença. Sem isso, "conta as vagas" e "ocupa a vaga" formavam um
    # TOCTOU e duas máquinas simultâneas podiam furar `max_endpoints`.
    licenca = await repo.obter(licenca_id, para_atualizar=True)
    if licenca is None:
        raise PlanoInvalidoError("licença não encontrada")
    plano = await repo.obter_plano(licenca.plano_id)
    ocupadas = await repo.contar_vagas_ocupadas(licenca_id)
    if ocupadas >= plano.max_endpoints:
        await _registrar_evento_licenca(
            sessao, empresa_id, licenca_id, "licenca.endpoint_negado_limite",
            {"agente_id": str(agente_id), "max_endpoints": plano.max_endpoints},
        )
        raise LimiteEndpointsExcedidoError(
            f"limite de {plano.max_endpoints} endpoints do plano já atingido"
        )
    vaga = await repo.ocupar_vaga(empresa_id, licenca_id, agente_id)
    await _registrar_evento_licenca(sessao, empresa_id, licenca_id, "licenca.endpoint_registrado", {"agente_id": str(agente_id)})
    return _publico_vaga(vaga)


async def liberar_endpoint(sessao, empresa_id, agente_id):
    """Soft-release da vaga ocupada por `agente_id` (ex.: quando o agente é
    revogado -- fiação com o fluxo de revogação de agente fica para uma
    etapa futura; a função já existe pronta para ser chamada de lá)."""
    vaga = await LicencaRepositorio(sessao).liberar_vaga(agente_id)
    if vaga is None:
        return None
    await _registrar_evento_licenca(sessao, empresa_id, vaga.licenca_id, "licenca.endpoint_liberado", {"agente_id": str(agente_id)})
    return _publico_vaga(vaga)
