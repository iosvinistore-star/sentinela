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
