# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Acesso a dados de licenciamento: `planos`, `licencas`, `licencas_endpoints`, `licencas_eventos`."""
from sqlalchemy import func, select, update

from sentinela.models import Licenca, LicencaEndpoint, LicencaEvento, Plano
from sentinela.repositories.base import RepositorioBase


class LicencaRepositorio(RepositorioBase):
    # --- planos -----------------------------------------------------------
    async def listar_planos_ativos(self) -> list[Plano]:
        stmt = select(Plano).where(Plano.ativo.is_(True)).order_by(Plano.max_endpoints.asc())
        return list((await self.sessao.execute(stmt)).scalars())

    async def obter_plano(self, plano_id) -> Plano | None:
        return await self.sessao.get(Plano, plano_id)

    async def plano_ativo_existe(self, plano_id) -> bool:
        stmt = select(Plano.id).where(Plano.id == plano_id, Plano.ativo.is_(True))
        return (await self.sessao.execute(stmt)).first() is not None

    # --- licenças ---------------------------------------------------------
    async def listar(self) -> list[Licenca]:
        return list((await self.sessao.execute(select(Licenca).order_by(Licenca.criado_em.desc()))).scalars())

    async def obter(self, licenca_id, para_atualizar: bool = False) -> Licenca | None:
        stmt = select(Licenca).where(Licenca.id == licenca_id)
        if para_atualizar:
            stmt = stmt.with_for_update()
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    async def obter_ativa_mais_recente(self, empresa_id):
        """Id da licença 'ativa' mais recente da empresa, ou None."""
        stmt = (
            select(Licenca.id).where(Licenca.empresa_id == empresa_id, Licenca.status == "ativa")
            .order_by(Licenca.criado_em.desc()).limit(1)
        )
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    async def criar(self, **campos) -> Licenca:
        licenca = Licenca(**campos)
        self.sessao.add(licenca)
        await self.sessao.flush()
        await self.sessao.refresh(licenca)
        return licenca

    async def _atualizar(self, licenca_id, **valores) -> Licenca | None:
        stmt = (
            update(Licenca).where(Licenca.id == licenca_id).values(**valores)
            .returning(Licenca).execution_options(synchronize_session=False)
        )
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    async def marcar_ativada(self, licenca_id) -> Licenca | None:
        return await self._atualizar(licenca_id, ativada_em=func.coalesce(Licenca.ativada_em, func.now()))

    async def marcar_validada(self, licenca_id) -> Licenca | None:
        return await self._atualizar(licenca_id, ultima_validacao_em=func.now())

    async def mudar_status(self, licenca_id, status: str) -> Licenca | None:
        return await self._atualizar(licenca_id, status=status)

    async def renovar(self, licenca_id, expira_em) -> Licenca | None:
        return await self._atualizar(licenca_id, status="ativa", expira_em=expira_em)

    # --- vagas de endpoint --------------------------------------------------
    async def obter_vaga_aberta(self, agente_id) -> LicencaEndpoint | None:
        stmt = select(LicencaEndpoint).where(LicencaEndpoint.agente_id == agente_id, LicencaEndpoint.liberado_em.is_(None))
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    async def contar_vagas_ocupadas(self, licenca_id) -> int:
        stmt = select(func.count()).select_from(LicencaEndpoint).where(
            LicencaEndpoint.licenca_id == licenca_id, LicencaEndpoint.liberado_em.is_(None)
        )
        return (await self.sessao.execute(stmt)).scalar_one()

    async def ocupar_vaga(self, empresa_id, licenca_id, agente_id) -> LicencaEndpoint:
        vaga = LicencaEndpoint(empresa_id=empresa_id, licenca_id=licenca_id, agente_id=agente_id)
        self.sessao.add(vaga)
        await self.sessao.flush()
        await self.sessao.refresh(vaga)
        return vaga

    async def liberar_vaga(self, agente_id) -> LicencaEndpoint | None:
        stmt = (
            update(LicencaEndpoint)
            .where(LicencaEndpoint.agente_id == agente_id, LicencaEndpoint.liberado_em.is_(None))
            .values(liberado_em=func.now()).returning(LicencaEndpoint).execution_options(synchronize_session=False)
        )
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    # --- histórico ----------------------------------------------------------
    async def registrar_evento(self, empresa_id, licenca_id, tipo: str, detalhes: dict) -> None:
        self.sessao.add(LicencaEvento(empresa_id=empresa_id, licenca_id=licenca_id, tipo=tipo, detalhes=detalhes))
        await self.sessao.flush()
