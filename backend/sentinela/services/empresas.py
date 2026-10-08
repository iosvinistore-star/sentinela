# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Gestão global de empresas -- só faz sentido via `conexao_superadmin`
(BYPASSRLS): a tabela `empresas` não tem RLS (não poderia ter -- é ela
quem DEFINE os tenants), então só o superadmin deve enxergá-la por inteiro.
"""
from sentinela.repositories.empresas import EmpresaRepositorio
from sentinela.services import auditoria as servico_auditoria

STATUS_VALIDOS = {"ativa", "suspensa", "cancelada"}
# Ver migrations/0012_firewall_modo_e_incidente.sql e
# services/resposta_incidentes.py para o que cada modo significa.
MODOS_FIREWALL_VALIDOS = {"observacao", "dry_run", "manual", "automacao_controlada", "automacao_total"}


class StatusEmpresaInvalidoError(ValueError):
    """Levantado por `atualizar_empresa` quando `status` não é um dos valores aceitos.

    A tabela já tem um CHECK constraint (ver migrations/0001_tabelas.sql)
    que impediria a gravação de qualquer forma, mas validar aqui também dá
    um erro de aplicação claro (422) em vez de deixar vazar um
    `asyncpg.CheckViolationError` cru até a rota."""


class ModoFirewallInvalidoError(ValueError):
    """Mesmo raciocínio de `StatusEmpresaInvalidoError`, para `modo_firewall`."""


def _publico(empresa):
    if empresa is None:
        return None
    d = empresa.para_dict()
    d["id"] = str(d["id"])
    return d


async def listar_empresas(sessao):
    return [_publico(e) for e in await EmpresaRepositorio(sessao).listar()]


async def obter_empresa(sessao, empresa_id):
    return _publico(await EmpresaRepositorio(sessao).obter(empresa_id))


async def criar_empresa(sessao, nome: str, plano: str = "padrao", ator_superadmin_id=None):
    empresa = await EmpresaRepositorio(sessao).criar(nome, plano)
    await servico_auditoria.registrar_evento(
        sessao, empresa.id, "empresa.criada", {"nome": nome, "plano": plano},
        ator_superadmin_id=ator_superadmin_id,
    )
    return _publico(empresa)


async def atualizar_empresa(sessao, empresa_id, nome: str | None = None, plano: str | None = None,
                              status: str | None = None, modo_firewall: str | None = None,
                              modo_firewall_auto: bool | None = None,
                              auto_triagem_incidentes: bool | None = None,
                              agentes_endpoint_habilitado: bool | None = None,
                              ator_superadmin_id=None):
    """
    `modo_firewall_auto`/`auto_triagem_incidentes` (migrations/
    0014_autonomia_operacional.sql, ver services/automacao.py) e
    `agentes_endpoint_habilitado` (migrations/0016_agentes_endpoint.sql,
    ver services/agentes.py): chaves opt-in de capacidades automáticas/
    novas. Ficam AQUI (junto de `modo_firewall`, admin-only) de propósito
    -- ligar autoajuste/auto-triagem/agente local é uma decisão
    operacional/de risco do mesmo tipo que escolher o modo de firewall, não
    algo que o próprio tenant deveria conseguir ativar sozinho sem o
    provedor do SOC saber. Uma vez ligado, o DIA A DIA de gerenciar os
    próprios agentes (criar/revogar token) já é self-service do admin da
    empresa -- ver api/v1/agentes.py -- só o LIGAR/DESLIGAR da capacidade
    em si é superadmin-only, aqui.
    """
    if status is not None and status not in STATUS_VALIDOS:
        raise StatusEmpresaInvalidoError(f"status inválido -- use um de {sorted(STATUS_VALIDOS)}")
    if modo_firewall is not None and modo_firewall not in MODOS_FIREWALL_VALIDOS:
        raise ModoFirewallInvalidoError(f"modo_firewall inválido -- use um de {sorted(MODOS_FIREWALL_VALIDOS)}")
    campos = {
        k: v for k, v in (
            ("nome", nome), ("plano", plano), ("status", status), ("modo_firewall", modo_firewall),
            ("modo_firewall_auto", modo_firewall_auto), ("auto_triagem_incidentes", auto_triagem_incidentes),
            ("agentes_endpoint_habilitado", agentes_endpoint_habilitado),
        ) if v is not None
    }
    row = await EmpresaRepositorio(sessao).atualizar(empresa_id, campos)
    if row is not None:
        await servico_auditoria.registrar_evento(
            sessao, empresa_id, "empresa.atualizada",
            {
                "nome": nome, "plano": plano, "status": status, "modo_firewall": modo_firewall,
                "modo_firewall_auto": modo_firewall_auto, "auto_triagem_incidentes": auto_triagem_incidentes,
                "agentes_endpoint_habilitado": agentes_endpoint_habilitado,
            },
            ator_superadmin_id=ator_superadmin_id,
        )
    return _publico(row)


async def nome_da_empresa_com_cnpj(sessao, cnpj: str, exceto_id=None) -> str | None:
    """Nome da empresa que já usa este CNPJ (ignorando `exceto_id`), ou None se estiver livre."""
    return await EmpresaRepositorio(sessao).buscar_nome_por_cnpj(cnpj, exceto_id)


async def gravar_dados_contrato(sessao, empresa_id, cnpj: str | None, contrato: dict, habilitar_agentes: bool = False):
    """Grava os dados comerciais (CNPJ, responsável, contrato...). Campos None são gravados como NULL."""
    campos = {"cnpj": cnpj, **contrato}
    if habilitar_agentes:
        campos["agentes_endpoint_habilitado"] = True
    return _publico(await EmpresaRepositorio(sessao).atualizar(empresa_id, campos))


async def habilitar_agentes_endpoint(sessao, empresa_id) -> None:
    await EmpresaRepositorio(sessao).atualizar(empresa_id, {"agentes_endpoint_habilitado": True})
