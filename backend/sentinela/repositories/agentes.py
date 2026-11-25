# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Acesso a dados de agentes de endpoint: `agentes`, `agentes_eventos` e `agentes_enrollment_tokens`."""
from sqlalchemy import func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from sentinela.models import Agente, AgenteEnrollmentToken, AgenteEvento
from sentinela.repositories.base import RepositorioBase


class AgenteRepositorio(RepositorioBase):
    async def inserir_se_hostname_livre(self, empresa_id, hostname, prefixo, token_hash, criado_por) -> Agente | None:
        """
        ON CONFLICT precisa espelhar o predicado do índice parcial
        `idx_agentes_empresa_hostname_ativo` (status = 'ativo'): é assim que o
        Postgres escolhe qual índice o conflito mira.
        """
        stmt = (
            pg_insert(Agente)
            .values(empresa_id=empresa_id, hostname=hostname, token_prefixo=prefixo, token_hash=token_hash,
                    criado_por_usuario_id=criado_por)
            .on_conflict_do_nothing(index_elements=["empresa_id", "hostname"], index_where=text("status = 'ativo'"))
            .returning(Agente)
        )
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    async def listar(self) -> list[Agente]:
        return list((await self.sessao.execute(select(Agente).order_by(Agente.criado_em.desc()))).scalars())

    async def obter(self, agente_id) -> Agente | None:
        return await self.sessao.get(Agente, agente_id)

    async def obter_hostname(self, agente_id) -> str | None:
        return (await self.sessao.execute(select(Agente.hostname).where(Agente.id == agente_id))).scalar_one_or_none()

    async def revogar(self, empresa_id, agente_id) -> Agente | None:
        stmt = (
            update(Agente).where(Agente.id == agente_id, Agente.empresa_id == empresa_id)
            .values(status="revogado").returning(Agente).execution_options(synchronize_session=False)
        )
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    async def definir_habilitado(self, empresa_id, agente_id, habilitado: bool) -> Agente | None:
        stmt = (
            update(Agente).where(Agente.id == agente_id, Agente.empresa_id == empresa_id)
            .values(habilitado=habilitado).returning(Agente).execution_options(synchronize_session=False)
        )
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    async def registrar_heartbeat(self, agente_id, sistema_operacional: str, versao_agente: str) -> None:
        await self.sessao.execute(
            update(Agente).where(Agente.id == agente_id)
            .values(ultimo_heartbeat_em=func.now(), sistema_operacional=sistema_operacional, versao_agente=versao_agente)
            .execution_options(synchronize_session=False)
        )

    async def registrar_evento(self, empresa_id, agente_id, tipo: str, payload: dict) -> None:
        self.sessao.add(AgenteEvento(empresa_id=empresa_id, agente_id=agente_id, tipo=tipo, payload=payload))
        await self.sessao.flush()

    async def buscar_ativo_por_prefixo(self, prefixo: str) -> dict | None:
        """Para autenticar o token do agente (sessão superadmin: ainda não se sabe o tenant)."""
        stmt = select(Agente.id, Agente.empresa_id, Agente.hostname, Agente.token_hash).where(
            Agente.token_prefixo == prefixo, Agente.status == "ativo"
        )
        linha = (await self.sessao.execute(stmt)).one_or_none()
        return dict(linha._mapping) if linha else None

    async def atualizar_token_hash(self, agente_id, token_hash: str) -> None:
        await self.sessao.execute(
            update(Agente).where(Agente.id == agente_id).values(token_hash=token_hash)
            .execution_options(synchronize_session=False)
        )

    async def esta_habilitado(self, agente_id, empresa_id) -> bool:
        stmt = select(Agente.habilitado).where(Agente.id == agente_id, Agente.empresa_id == empresa_id)
        return bool((await self.sessao.execute(stmt)).scalar_one_or_none())


class EnrollmentRepositorio(RepositorioBase):
    async def criar(self, empresa_id, prefixo, token_hash, expira_em, max_usos, criado_por) -> AgenteEnrollmentToken:
        token = AgenteEnrollmentToken(
            empresa_id=empresa_id, token_prefixo=prefixo, token_hash=token_hash, expira_em=expira_em,
            max_usos=max_usos, criado_por_usuario_id=criado_por,
        )
        self.sessao.add(token)
        await self.sessao.flush()
        await self.sessao.refresh(token)
        return token

    async def listar(self) -> list[AgenteEnrollmentToken]:
        stmt = select(AgenteEnrollmentToken).order_by(AgenteEnrollmentToken.criado_em.desc())
        return list((await self.sessao.execute(stmt)).scalars())

    async def revogar(self, empresa_id, enrollment_id) -> AgenteEnrollmentToken | None:
        stmt = (
            update(AgenteEnrollmentToken)
            .where(AgenteEnrollmentToken.id == enrollment_id, AgenteEnrollmentToken.empresa_id == empresa_id)
            .values(status="revogado").returning(AgenteEnrollmentToken).execution_options(synchronize_session=False)
        )
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    async def reservar_uso(self, enrollment_id) -> int | None:
        """Reserva atômica de um uso (UPDATE ... WHERE ... RETURNING); None se revogado/expirado/esgotado."""
        t = AgenteEnrollmentToken
        stmt = (
            update(t)
            .where(
                t.id == enrollment_id, t.status == "ativo", t.expira_em > func.now(),
                (t.max_usos.is_(None)) | (t.usos < t.max_usos),
            )
            .values(usos=t.usos + 1).returning(t.usos).execution_options(synchronize_session=False)
        )
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    async def obter_status(self, enrollment_id):
        t = AgenteEnrollmentToken
        return (await self.sessao.execute(select(t.status, t.expira_em).where(t.id == enrollment_id))).one_or_none()

    async def buscar_por_prefixo(self, prefixo: str) -> dict | None:
        """Resolve o token de enrollment (de QUALQUER status: quem decide é o serviço)."""
        t = AgenteEnrollmentToken
        stmt = select(t.id, t.empresa_id, t.status, t.expira_em, t.max_usos, t.usos, t.token_hash).where(
            t.token_prefixo == prefixo
        )
        linha = (await self.sessao.execute(stmt)).one_or_none()
        return dict(linha._mapping) if linha else None
