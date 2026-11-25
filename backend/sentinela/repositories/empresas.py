# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Acesso a dados de `empresas` (sem RLS: só via sessão superadmin)."""
from sqlalchemy import select, update

from sentinela.models import Empresa
from sentinela.repositories.base import RepositorioBase


class EmpresaRepositorio(RepositorioBase):
    async def listar(self) -> list[Empresa]:
        return list((await self.sessao.execute(select(Empresa).order_by(Empresa.criada_em.desc()))).scalars())

    async def obter(self, empresa_id) -> Empresa | None:
        return await self.sessao.get(Empresa, empresa_id)

    async def criar(self, nome: str, plano: str) -> Empresa:
        empresa = Empresa(nome=nome, plano=plano)
        self.sessao.add(empresa)
        await self.sessao.flush()
        await self.sessao.refresh(empresa)
        return empresa

    async def atualizar(self, empresa_id, campos: dict) -> Empresa | None:
        """Só grava os campos informados (não-None); sem nenhum, apenas devolve a linha."""
        if not campos:
            return await self.obter(empresa_id)
        stmt = (
            update(Empresa).where(Empresa.id == empresa_id).values(**campos)
            .returning(Empresa).execution_options(synchronize_session=False)
        )
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    async def obter_config_firewall(self, empresa_id):
        """(modo_firewall, modo_firewall_auto) ou None."""
        stmt = select(Empresa.modo_firewall, Empresa.modo_firewall_auto).where(Empresa.id == empresa_id)
        return (await self.sessao.execute(stmt)).one_or_none()

    async def definir_modo_firewall(self, empresa_id, modo: str) -> None:
        await self.sessao.execute(
            update(Empresa).where(Empresa.id == empresa_id).values(modo_firewall=modo)
            .execution_options(synchronize_session=False)
        )

    async def auto_triagem_ligada(self, empresa_id) -> bool:
        stmt = select(Empresa.auto_triagem_incidentes).where(Empresa.id == empresa_id)
        return bool((await self.sessao.execute(stmt)).scalar_one_or_none())

    async def listar_ids_com_autonomia(self) -> list:
        """Empresas ativas com ao menos uma flag de autonomia ligada."""
        stmt = select(Empresa.id).where(
            Empresa.status == "ativa", Empresa.modo_firewall_auto | Empresa.auto_triagem_incidentes
        )
        return list((await self.sessao.execute(stmt)).scalars())

    async def obter_status(self, empresa_id) -> str | None:
        return (await self.sessao.execute(select(Empresa.status).where(Empresa.id == empresa_id))).scalar_one_or_none()

    async def obter_status_e_agentes(self, empresa_id):
        """(status, agentes_endpoint_habilitado) ou None."""
        stmt = select(Empresa.status, Empresa.agentes_endpoint_habilitado).where(Empresa.id == empresa_id)
        return (await self.sessao.execute(stmt)).one_or_none()

    async def buscar_nome_por_cnpj(self, cnpj: str, exceto_id=None) -> str | None:
        stmt = select(Empresa.nome).where(Empresa.cnpj == cnpj)
        if exceto_id is not None:
            stmt = stmt.where(Empresa.id != exceto_id)
        return (await self.sessao.execute(stmt)).scalars().first()
