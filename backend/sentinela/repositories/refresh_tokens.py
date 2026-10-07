# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Acesso a dados de `refresh_tokens` (rotação com detecção de reuso)."""
from sqlalchemy import func, select, update

from sentinela.models import RefreshToken, Superadmin, Usuario
from sentinela.repositories.base import RepositorioBase


class RefreshTokenRepositorio(RepositorioBase):
    async def inserir(self, family_id, token_hash, conta_tipo, conta_id, token_version, expira_em) -> None:
        self.sessao.add(RefreshToken(
            family_id=family_id, token_hash=token_hash, conta_tipo=conta_tipo, conta_id=conta_id,
            token_version=token_version, expira_em=expira_em,
        ))
        await self.sessao.flush()

    async def obter_para_rotacao(self, token_hash: str) -> RefreshToken | None:
        """`FOR UPDATE`: duas rotações concorrentes do mesmo token serializam."""
        stmt = select(RefreshToken).where(RefreshToken.token_hash == token_hash).with_for_update()
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    async def revogar_familia(self, family_id) -> None:
        stmt = (
            update(RefreshToken)
            .where(RefreshToken.family_id == family_id, RefreshToken.revogado_em.is_(None))
            .values(revogado_em=func.now()).execution_options(synchronize_session=False)
        )
        await self.sessao.execute(stmt)

    async def invalidar_sessoes_da_conta(self, conta_tipo: str, conta_id) -> None:
        """Reuso de refresh token = possível roubo: sobe o `token_version` da conta (derruba as sessões de acesso)."""
        modelo = Superadmin if conta_tipo == "superadmin" else Usuario
        stmt = (
            update(modelo).where(modelo.id == conta_id)
            .values(token_version=modelo.token_version + 1).execution_options(synchronize_session=False)
        )
        await self.sessao.execute(stmt)

    async def marcar_usado(self, token_id) -> None:
        stmt = (
            update(RefreshToken).where(RefreshToken.id == token_id)
            .values(usado_em=func.now()).execution_options(synchronize_session=False)
        )
        await self.sessao.execute(stmt)
