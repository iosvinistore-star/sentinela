# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Fase D / D3 -- enrollment self-service de agentes: geração/revogação de
tokens de enrollment (sessão humana, tenant-scoped) e a troca desse token
pela identidade PERMANENTE de um agente (chamada pela máquina, sem sessão).
Ver ARQUITETURA_LICENCIAMENTO.md §12 para o desenho completo.

Convenção do resto de services/*.py: toda função recebe uma conexão JÁ
escopada -- nunca abre conexão própria. Ações administrativas (criar/
revogar) chamam `services/auditoria.py:registrar_evento` na MESMA
transação.
"""
import asyncio
from datetime import datetime, timezone

from sentinela.auth.enrollment import gerar_token
from sentinela.auth.security import hash_senha
from sentinela.repositories.agentes import EnrollmentRepositorio
from sentinela.services import agentes as servico_agentes
from sentinela.services import auditoria as servico_auditoria


class TokenEnrollmentInvalidoError(ValueError):
    """
    Levantado por `trocar_por_agente` quando o token já foi resolvido pela
    camada de autenticação (`auth/enrollment.py:autenticar_enrollment`
    encontrou a linha -- token EXISTE), mas não pode mais ser usado:
    revogado, expirado, ou já esgotou `max_usos`. A mensagem identifica
    qual dos três motivos -- a rota traduz para HTTP 403 (nunca 401, que já
    é reservado para "este token não existe/não bate com nenhum registro",
    mesmo padrão de auth/licencas.py:autenticar_licenca vs. status != 'ativa'
    da própria licença).
    """


def _publico(token):
    if token is None:
        return None
    d = token.para_dict()
    for campo in ("id", "empresa_id", "criado_por_usuario_id"):
        if d.get(campo) is not None:
            d[campo] = str(d[campo])
    # token_hash nunca sai desta camada -- mesmo cuidado de
    # services/agentes.py:_publico e services/licenciamento.py:_publico_licenca.
    d.pop("token_hash", None)
    return d


async def criar_token_enrollment(sessao, empresa_id, expira_em, max_usos=None, ator_usuario_id=None, ator_superadmin_id=None):
    """
    Cria um token de enrollment novo para `empresa_id`. Retorna
    (token_publico, token_completo) -- o token só existe aqui, uma vez,
    mesma filosofia de services/agentes.py:criar_agente/
    services/licenciamento.py:criar_licenca (só o hash bcrypt persiste
    depois disso).
    """
    token_completo, prefixo = gerar_token()
    token_hash = await asyncio.to_thread(hash_senha, token_completo)
    row = await EnrollmentRepositorio(sessao).criar(empresa_id, prefixo, token_hash, expira_em, max_usos, ator_usuario_id)
    await servico_auditoria.registrar_evento(
        sessao, empresa_id, "agente.enrollment_criado",
        {"enrollment_id": str(row.id), "expira_em": str(expira_em), "max_usos": max_usos},
        ator_usuario_id=ator_usuario_id, ator_superadmin_id=ator_superadmin_id,
    )
    return _publico(row), token_completo


async def listar_tokens_enrollment(sessao):
    """Conn tenant-scoped -> RLS já filtra pra empresa do chamador."""
    return [_publico(r) for r in await EnrollmentRepositorio(sessao).listar()]


async def revogar_token_enrollment(sessao, empresa_id, enrollment_id, ator_usuario_id=None):
    """Nunca DELETE -- preserva o histórico (mesma filosofia do resto do
    projeto). Idempotente: revogar um token já revogado não é erro."""
    row = await EnrollmentRepositorio(sessao).revogar(empresa_id, enrollment_id)
    if row is None:
        return None
    await servico_auditoria.registrar_evento(
        sessao, empresa_id, "agente.enrollment_revogado", {"enrollment_id": str(enrollment_id)},
        ator_usuario_id=ator_usuario_id,
    )
    return _publico(row)


async def trocar_por_agente(sessao, enrollment: dict, hostname: str):
    """
    O passo central do D3: reserva atomicamente um uso do token de
    enrollment e, se a reserva for aceita, cria o agente permanente (via
    `services/agentes.py:criar_agente` -- o mesmo caminho que uma criação
    manual via `POST /agentes` já usa, incluindo o auto-bind à licença
    ativa da empresa, Fase D / D1).

    A reserva (`UPDATE ... WHERE ... RETURNING`) é a fonte de verdade e
    roda ANTES de qualquer outra coisa -- evita a corrida óbvia de duas
    máquinas lendo "ainda há uso disponível" ao mesmo tempo (ver
    ARQUITETURA_LICENCIAMENTO.md §12 para o trade-off consciente: um uso
    reservado não é devolvido se `criar_agente` falhar depois, ex.:
    hostname duplicado).

    Levanta TokenEnrollmentInvalidoError se a reserva for recusada
    (revogado/expirado/esgotado) -- a consulta de acompanhamento abaixo só
    existe para dar uma mensagem PRECISA sobre qual dos três motivos, não
    é ela quem decide (podendo já não refletir o estado exato no
    micro-instante da reserva, mas isso nunca é um problema de segurança
    aqui, só de texto de erro).

    Propaga `services.licenciamento.LimiteEndpointsExcedidoError` sem
    capturar -- a rota já sabe traduzir isso para 409 (mesmo comportamento
    de uma criação manual). Retorna (agente_publico, token_completo), ou
    (None, None) se o hostname já está em uso por um agente ATIVO desta
    empresa (mesmo contrato de `criar_agente`).
    """
    repo = EnrollmentRepositorio(sessao)
    reservado = await repo.reservar_uso(enrollment["enrollment_id"])
    if reservado is None:
        linha = await repo.obter_status(enrollment["enrollment_id"])
        if linha is None:
            raise TokenEnrollmentInvalidoError("token de enrollment não encontrado")
        if linha.status != "ativo":
            raise TokenEnrollmentInvalidoError("token de enrollment revogado")
        if linha.expira_em <= datetime.now(timezone.utc):
            raise TokenEnrollmentInvalidoError("token de enrollment expirado")
        raise TokenEnrollmentInvalidoError("token de enrollment esgotou o limite de usos")
    agente, token = await servico_agentes.criar_agente(sessao, enrollment["empresa_id"], hostname)
    if agente is not None:
        # Evento próprio (além do "agente.criado" que criar_agente já
        # grava) -- liga o agente novo ao token de enrollment usado, para
        # um admin conseguir ver depois "quais máquinas entraram por qual
        # token" (útil quando vários tokens de enrollment coexistem, ex.:
        # um por lote de instalação).
        await servico_auditoria.registrar_evento(
            sessao, enrollment["empresa_id"], "agente.criado_via_enrollment",
            {"enrollment_id": str(enrollment["enrollment_id"]), "agente_id": agente["id"], "hostname": hostname},
        )
    return agente, token
