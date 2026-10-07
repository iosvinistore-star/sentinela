# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Acesso a dados de `push_inscricoes` (Web Push)."""
from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from sentinela.models import PushInscricao
from sentinela.repositories.base import RepositorioBase


class PushRepositorio(RepositorioBase):
    async def upsert(self, endpoint, p256dh, auth, aparelho, empresa_id, usuario_id, superadmin_id):
        """Navegadores renovam a inscrição reenviando o MESMO endpoint com chaves novas: upsert, não duplicata."""
        novo = pg_insert(PushInscricao).values(
            empresa_id=empresa_id, usuario_id=usuario_id, superadmin_id=superadmin_id, endpoint=endpoint,
            chave_p256dh=p256dh, chave_auth=auth, aparelho=aparelho,
        )
        stmt = novo.on_conflict_do_update(
            index_elements=["endpoint"],
            set_={
                "chave_p256dh": novo.excluded.chave_p256dh, "chave_auth": novo.excluded.chave_auth,
                "aparelho": novo.excluded.aparelho, "empresa_id": novo.excluded.empresa_id,
                "usuario_id": novo.excluded.usuario_id, "superadmin_id": novo.excluded.superadmin_id,
                "falhas_seguidas": 0,
            },
        ).returning(PushInscricao.id, PushInscricao.criada_em)
        return (await self.sessao.execute(stmt)).one()

    async def apagar_por_endpoint(self, endpoint: str) -> int:
        return (await self.sessao.execute(delete(PushInscricao).where(PushInscricao.endpoint == endpoint))).rowcount

    async def listar_da_empresa(self, empresa_id) -> list:
        stmt = (
            select(PushInscricao.id, PushInscricao.aparelho, PushInscricao.criada_em, PushInscricao.usada_em)
            .where(PushInscricao.empresa_id == empresa_id).order_by(PushInscricao.criada_em)
        )
        return list((await self.sessao.execute(stmt)).all())

    async def listar_para_envio(self, empresa_id) -> list[dict]:
        stmt = select(
            PushInscricao.id, PushInscricao.endpoint, PushInscricao.chave_p256dh, PushInscricao.chave_auth
        ).where(PushInscricao.empresa_id == empresa_id)
        return [dict(r._mapping) for r in await self.sessao.execute(stmt)]

    async def marcar_entregue(self, inscricao_id) -> None:
        await self.sessao.execute(
            update(PushInscricao).where(PushInscricao.id == inscricao_id)
            .values(usada_em=func.now(), falhas_seguidas=0)
        )

    async def apagar(self, inscricao_id) -> None:
        await self.sessao.execute(delete(PushInscricao).where(PushInscricao.id == inscricao_id))

    async def registrar_falha(self, inscricao_id, max_falhas: int) -> None:
        """Soma uma falha e apaga a inscrição que atingiu o limite."""
        await self.sessao.execute(
            update(PushInscricao).where(PushInscricao.id == inscricao_id)
            .values(falhas_seguidas=PushInscricao.falhas_seguidas + 1)
        )
        await self.sessao.execute(
            delete(PushInscricao).where(PushInscricao.id == inscricao_id, PushInscricao.falhas_seguidas >= max_falhas)
        )
