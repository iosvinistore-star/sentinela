# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Acesso a dados da tabela `auditoria`."""
from sqlalchemy import select

from sentinela.models import Auditoria
from sentinela.repositories.base import RepositorioBase


class AuditoriaRepositorio(RepositorioBase):
    async def inserir(self, empresa_id, acao: str, detalhes: dict, ator_usuario_id=None, ator_superadmin_id=None) -> Auditoria:
        registro = Auditoria(
            empresa_id=empresa_id,
            ator_usuario_id=ator_usuario_id,
            ator_superadmin_id=ator_superadmin_id,
            acao=acao,
            detalhes=detalhes,
        )
        self.sessao.add(registro)
        await self.sessao.flush()
        await self.sessao.refresh(registro)
        return registro

    async def listar_recentes(self, limite: int) -> list[Auditoria]:
        resultado = await self.sessao.execute(select(Auditoria).order_by(Auditoria.criado_em.desc()).limit(limite))
        return list(resultado.scalars())
