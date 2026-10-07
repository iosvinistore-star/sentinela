# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Acesso a dados de `usuarios` (tenant-scoped via RLS, salvo sessão superadmin)."""
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from sentinela.models import Empresa, Usuario
from sentinela.repositories.base import RepositorioBase

# Colunas expostas pela API -- nunca `senha_hash`/segredos de MFA.
_COLUNAS_PUBLICAS = (Usuario.id, Usuario.empresa_id, Usuario.email, Usuario.papel, Usuario.ativo, Usuario.criado_em)


class UsuarioRepositorio(RepositorioBase):
    async def listar(self, empresa_id=None) -> list[dict]:
        stmt = select(*_COLUNAS_PUBLICAS).order_by(Usuario.criado_em)
        if empresa_id is not None:
            stmt = stmt.where(Usuario.empresa_id == empresa_id)
        return [dict(r._mapping) for r in await self.sessao.execute(stmt)]

    async def inserir_ignorando_email_duplicado(self, empresa_id, email, papel, senha_hash) -> dict | None:
        stmt = (
            pg_insert(Usuario)
            .values(empresa_id=empresa_id, email=email, papel=papel, senha_hash=senha_hash)
            .on_conflict_do_nothing(index_elements=["email"])
            .returning(*_COLUNAS_PUBLICAS)
        )
        linha = (await self.sessao.execute(stmt)).one_or_none()
        return dict(linha._mapping) if linha else None

    async def atualizar(self, empresa_id, usuario_id, campos: dict) -> dict | None:
        if not campos:
            stmt = select(*_COLUNAS_PUBLICAS).where(Usuario.id == usuario_id, Usuario.empresa_id == empresa_id)
        else:
            stmt = (
                update(Usuario).where(Usuario.id == usuario_id, Usuario.empresa_id == empresa_id)
                .values(**campos).returning(*_COLUNAS_PUBLICAS).execution_options(synchronize_session=False)
            )
        linha = (await self.sessao.execute(stmt)).one_or_none()
        return dict(linha._mapping) if linha else None

    async def obter_senha_hash(self, usuario_id) -> str | None:
        return (await self.sessao.execute(select(Usuario.senha_hash).where(Usuario.id == usuario_id))).scalar_one_or_none()

    async def trocar_senha(self, usuario_id, senha_hash: str) -> int | None:
        """Grava a senha e incrementa `token_version` (invalida as outras sessões). Devolve o novo valor."""
        stmt = (
            update(Usuario).where(Usuario.id == usuario_id)
            .values(senha_hash=senha_hash, token_version=Usuario.token_version + 1)
            .returning(Usuario.token_version).execution_options(synchronize_session=False)
        )
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    async def buscar_ativo_para_login(self, email: str):
        """Usuário ativo + status da empresa, ou None. Exige sessão superadmin (antes do tenant ser conhecido)."""
        stmt = (
            select(
                Usuario.id, Usuario.empresa_id, Usuario.email, Usuario.papel, Usuario.senha_hash,
                Usuario.token_version, Usuario.mfa_habilitado, Empresa.status.label("empresa_status"),
            )
            .join(Empresa, Empresa.id == Usuario.empresa_id)
            .where(Usuario.email == email, Usuario.ativo.is_(True))
        )
        linha = (await self.sessao.execute(stmt)).one_or_none()
        return dict(linha._mapping) if linha else None

    async def obter_id_ativo_por_email(self, email: str):
        stmt = select(Usuario.id).where(Usuario.email == email, Usuario.ativo.is_(True))
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    async def obter_para_sessao(self, usuario_id, empresa_id):
        """(ativo, papel, token_version) para reconferir a sessão em tempo real, ou None."""
        stmt = select(Usuario.ativo, Usuario.papel, Usuario.token_version).where(
            Usuario.id == usuario_id, Usuario.empresa_id == empresa_id
        )
        return (await self.sessao.execute(stmt)).one_or_none()

    async def obter_para_refresh(self, usuario_id):
        stmt = select(
            Usuario.id, Usuario.empresa_id, Usuario.email, Usuario.papel, Usuario.token_version, Usuario.ativo
        ).where(Usuario.id == usuario_id)
        linha = (await self.sessao.execute(stmt)).one_or_none()
        return dict(linha._mapping) if linha else None
