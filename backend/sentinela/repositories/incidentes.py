# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Acesso a dados da tabela `incidentes` e das agregações do dashboard."""
from datetime import timedelta

from sqlalchemy import Integer, Text, case, cast, func, literal, select, text, update
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import insert as pg_insert

from sentinela.models import BloqueioFirewall, Incidente
from sentinela.repositories.base import RepositorioBase


class IncidenteRepositorio(RepositorioBase):
    async def inserir_ignorando_duplicata(self, **campos) -> Incidente | None:
        """INSERT ... ON CONFLICT (empresa_id, incident_id) DO NOTHING; None se colidiu."""
        stmt = (
            pg_insert(Incidente)
            .values(**campos)
            .on_conflict_do_nothing(index_elements=["empresa_id", "incident_id"])
            .returning(Incidente)
        )
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    async def obter_endpoint_aberto(self, empresa_id, agente_id) -> Incidente | None:
        stmt = (
            select(Incidente)
            .where(
                Incidente.empresa_id == empresa_id,
                Incidente.agente_id == agente_id,
                Incidente.status.in_(("OPEN", "EM_ANDAMENTO")),
            )
            .order_by(Incidente.criado_em.desc())
            .limit(1)
        )
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    async def acrescentar_deteccoes(self, empresa_id, incident_id: str, ataques_novos: list, score: int, severidade: str):
        """Anexa ataques e só ESCALA severidade/score (nunca rebaixa)."""
        stmt = (
            update(Incidente)
            .where(Incidente.empresa_id == empresa_id, Incidente.incident_id == incident_id)
            .values(
                ataques=Incidente.ataques.op("||")(cast(ataques_novos, JSONB)),
                severidade=case((score > Incidente.pontuacao_risco, literal(severidade, type_=Text)), else_=Incidente.severidade),
                pontuacao_risco=func.greatest(Incidente.pontuacao_risco, score),
                atualizado_em=func.now(),
            )
            .returning(Incidente)
            .execution_options(synchronize_session=False)
        )
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    async def listar(self, status: str | None, limite: int) -> list[Incidente]:
        stmt = select(Incidente).order_by(Incidente.criado_em.desc()).limit(limite)
        if status:
            stmt = stmt.where(Incidente.status == status)
        return list((await self.sessao.execute(stmt)).scalars())

    async def obter(self, empresa_id, incident_id: str) -> Incidente | None:
        stmt = select(Incidente).where(Incidente.empresa_id == empresa_id, Incidente.incident_id == incident_id)
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    async def atualizar_status(
        self, empresa_id, incident_id: str, status: str, observacoes: str, em_andamento_usuario, resolvido_por
    ) -> Incidente | None:
        stmt = (
            update(Incidente)
            .where(Incidente.empresa_id == empresa_id, Incidente.incident_id == incident_id)
            .values(
                status=status,
                observacoes=func.coalesce(func.nullif(literal(observacoes, type_=Text), ""), Incidente.observacoes),
                atualizado_em=func.now(),
                em_andamento_por_usuario_id=func.coalesce(
                    Incidente.em_andamento_por_usuario_id,
                    literal(em_andamento_usuario, type_=Incidente.em_andamento_por_usuario_id.type),
                ),
                resolvido_por=func.coalesce(literal(resolvido_por, type_=Text), Incidente.resolvido_por),
            )
            .returning(Incidente)
            .execution_options(synchronize_session=False)
        )
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    # --- agregações do dashboard -------------------------------------------------

    async def contagens(self, empresa_id) -> dict:
        stmt = select(
            func.count().label("total"),
            func.count().filter(Incidente.severidade == "CRITICAL").label("critical"),
            func.count().filter(Incidente.severidade == "HIGH").label("high"),
            func.count().filter(Incidente.severidade == "MEDIUM").label("medium"),
            func.count().filter(Incidente.severidade == "LOW").label("low"),
            func.count().filter(Incidente.status.in_(("OPEN", "EM_ANDAMENTO"))).label("abertos"),
            func.count().filter(Incidente.criado_em >= func.now() - timedelta(hours=24)).label("ultimas_24h"),
            func.count().filter(Incidente.criado_em >= func.now() - timedelta(hours=1)).label("ultima_hora"),
        ).where(Incidente.empresa_id == empresa_id)
        return dict((await self.sessao.execute(stmt)).one()._mapping)

    async def contagem_bloqueios(self, empresa_id) -> dict:
        stmt = select(
            func.count().filter(BloqueioFirewall.status == "ativo").label("ativos"),
            func.count().label("total"),
        ).where(BloqueioFirewall.empresa_id == empresa_id)
        return dict((await self.sessao.execute(stmt)).one()._mapping)

    async def top_ips_24h(self, empresa_id, limite: int = 10) -> list[dict]:
        stmt = (
            select(
                cast(Incidente.ip, Text).label("ip"),
                cast(func.count(), Integer).label("incidentes"),
                cast(func.max(Incidente.pontuacao_risco), Integer).label("maior_risco"),
            )
            .where(Incidente.empresa_id == empresa_id, Incidente.criado_em >= func.now() - timedelta(hours=24))
            .group_by(Incidente.ip)
            .order_by(text("incidentes DESC"), text("maior_risco DESC"))
            .limit(limite)
        )
        return [dict(r._mapping) for r in await self.sessao.execute(stmt)]

    async def recentes(self, empresa_id, limite: int = 8) -> list[dict]:
        stmt = (
            select(
                Incidente.incident_id,
                cast(Incidente.ip, Text).label("ip"),
                Incidente.severidade,
                Incidente.pontuacao_risco,
                Incidente.status,
                Incidente.criado_em,
            )
            .where(Incidente.empresa_id == empresa_id)
            .order_by(Incidente.criado_em.desc())
            .limit(limite)
        )
        return [dict(r._mapping) for r in await self.sessao.execute(stmt)]
