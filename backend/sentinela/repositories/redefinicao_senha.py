# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Acesso a dados de `redefinicoes_senha` (token de "esqueci minha senha")."""
from sqlalchemy import func, update

from sentinela.models import RedefinicaoSenha, Usuario
from sentinela.repositories.base import RepositorioBase


class RedefinicaoSenhaRepositorio(RepositorioBase):
    async def criar(self, usuario_id, token_hash: str, expira_em) -> None:
        self.sessao.add(RedefinicaoSenha(usuario_id=usuario_id, token_hash=token_hash, expira_em=expira_em))
        await self.sessao.flush()

    async def consumir(self, token_hash: str):
        """Marca o token como usado se ainda for válido (não usado, não expirado). Devolve o usuario_id ou None."""
        stmt = (
            update(RedefinicaoSenha)
            .where(
                RedefinicaoSenha.token_hash == token_hash,
                RedefinicaoSenha.usado_em.is_(None),
                RedefinicaoSenha.expira_em > func.now(),
            )
            .values(usado_em=func.now())
            .returning(RedefinicaoSenha.usuario_id)
            .execution_options(synchronize_session=False)
        )
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    async def trocar_senha_do_usuario(self, usuario_id, senha_hash: str) -> None:
        stmt = (
            update(Usuario).where(Usuario.id == usuario_id)
            .values(senha_hash=senha_hash, token_version=Usuario.token_version + 1)
            .execution_options(synchronize_session=False)
        )
        await self.sessao.execute(stmt)
