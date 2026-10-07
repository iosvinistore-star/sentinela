# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Acesso a dados de `reputacao_cache` (tenant-scoped via RLS)."""
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from sentinela.models import ReputacaoCache
from sentinela.repositories.base import RepositorioBase


class ReputacaoRepositorio(RepositorioBase):
    async def obter(self, empresa_id, ip: str) -> ReputacaoCache | None:
        stmt = select(ReputacaoCache).where(ReputacaoCache.empresa_id == empresa_id, ReputacaoCache.ip == ip)
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    async def salvar(self, empresa_id, ip: str, dados: dict, classificacao: str) -> None:
        novo = pg_insert(ReputacaoCache).values(
            empresa_id=empresa_id, ip=ip, dados=dados, classificacao=classificacao, consultado_em=func.now()
        )
        await self.sessao.execute(
            novo.on_conflict_do_update(
                index_elements=["empresa_id", "ip"],
                set_={"dados": novo.excluded.dados, "classificacao": novo.excluded.classificacao, "consultado_em": func.now()},
            )
        )
