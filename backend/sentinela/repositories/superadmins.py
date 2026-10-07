# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Acesso a dados de `superadmins` (contas da plataforma SaaS)."""
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from sentinela.models import Superadmin
from sentinela.repositories.base import RepositorioBase

_COLUNAS_PUBLICAS = (Superadmin.id, Superadmin.email, Superadmin.papel, Superadmin.criado_em)


class SuperadminRepositorio(RepositorioBase):
    async def listar(self) -> list[dict]:
        stmt = select(*_COLUNAS_PUBLICAS).order_by(Superadmin.criado_em)
        return [dict(r._mapping) for r in await self.sessao.execute(stmt)]

    async def inserir_ignorando_email_duplicado(self, email, senha_hash, papel) -> dict | None:
        stmt = (
            pg_insert(Superadmin).values(email=email, senha_hash=senha_hash, papel=papel)
            .on_conflict_do_nothing(index_elements=["email"]).returning(*_COLUNAS_PUBLICAS)
        )
        linha = (await self.sessao.execute(stmt)).one_or_none()
        return dict(linha._mapping) if linha else None

    async def obter_senha_hash(self, superadmin_id) -> str | None:
        stmt = select(Superadmin.senha_hash).where(Superadmin.id == superadmin_id)
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    async def trocar_senha(self, superadmin_id, senha_hash: str) -> int | None:
        stmt = (
            update(Superadmin).where(Superadmin.id == superadmin_id)
            .values(senha_hash=senha_hash, token_version=Superadmin.token_version + 1)
            .returning(Superadmin.token_version).execution_options(synchronize_session=False)
        )
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    async def buscar_para_login(self, email: str):
        stmt = select(
            Superadmin.id, Superadmin.email, Superadmin.senha_hash, Superadmin.token_version,
            Superadmin.papel, Superadmin.mfa_habilitado,
        ).where(Superadmin.email == email)
        linha = (await self.sessao.execute(stmt)).one_or_none()
        return dict(linha._mapping) if linha else None
