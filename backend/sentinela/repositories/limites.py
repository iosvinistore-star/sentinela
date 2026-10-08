# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Acesso a dados dos limitadores de abuso compartilhados entre réplicas (`limite_tentativas`, `limite_upload_eventos`)."""
from datetime import datetime

from sqlalchemy import case, delete, func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from sentinela.models import LimiteTentativa, LimiteUploadEvento
from sentinela.repositories.base import RepositorioBase


class LimiteTentativaRepositorio(RepositorioBase):
    async def bloqueado_ate(self, chave: str) -> datetime | None:
        stmt = select(LimiteTentativa.bloqueado_ate).where(LimiteTentativa.chave == chave)
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    async def contar_tentativa(self, chave: str, agora: datetime, inicio_janela_valida: datetime):
        """
        Um único UPSERT atômico decide se a janela expirou (reseta para 1) ou incrementa; o lock de linha do
        `INSERT ... ON CONFLICT` (mantido até o fim da transação) serializa chamadas concorrentes da MESMA chave.
        Devolve `(contador, bloqueado_ate)`.
        """
        novo = pg_insert(LimiteTentativa).values(chave=chave, janela_inicio=agora, contador=1, bloqueado_ate=None)
        expirou = LimiteTentativa.janela_inicio <= inicio_janela_valida
        stmt = novo.on_conflict_do_update(
            index_elements=["chave"],
            set_={
                "janela_inicio": _case(expirou, agora, LimiteTentativa.janela_inicio),
                "contador": _case(expirou, 1, LimiteTentativa.contador + 1),
            },
        ).returning(LimiteTentativa.contador, LimiteTentativa.bloqueado_ate)
        linha = (await self.sessao.execute(stmt)).one()
        return linha.contador, linha.bloqueado_ate

    async def bloquear(self, chave: str, ate: datetime) -> None:
        await self.sessao.execute(
            update(LimiteTentativa).where(LimiteTentativa.chave == chave)
            .values(bloqueado_ate=ate, contador=0).execution_options(synchronize_session=False)
        )

    async def devolver(self, chave: str, agora: datetime) -> None:
        """Desfaz UMA reserva, sem mexer num bloqueio já ativo."""
        await self.sessao.execute(
            update(LimiteTentativa)
            .where(
                LimiteTentativa.chave == chave,
                (LimiteTentativa.bloqueado_ate.is_(None)) | (LimiteTentativa.bloqueado_ate <= agora),
            )
            .values(contador=func.greatest(LimiteTentativa.contador - 1, 0)).execution_options(synchronize_session=False)
        )

    async def remover(self, chave: str) -> None:
        await self.sessao.execute(delete(LimiteTentativa).where(LimiteTentativa.chave == chave))

    async def limpar_expiradas(self, limite: datetime) -> None:
        """Remove só quem NÃO está bloqueado e cuja janela já expirou."""
        await self.sessao.execute(
            delete(LimiteTentativa).where(LimiteTentativa.bloqueado_ate.is_(None), LimiteTentativa.janela_inicio <= limite)
        )

    async def limpar_tudo(self) -> None:
        await self.sessao.execute(delete(LimiteTentativa))


def _case(condicao, se_verdadeiro, senao):
    return case((condicao, se_verdadeiro), else_=senao)


class LimiteUploadRepositorio(RepositorioBase):
    async def travar(self, chave: str) -> None:
        """Lock consultivo por chave até o fim da transação: fecha o 'check then act' entre uploads concorrentes."""
        await self.sessao.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:chave, 0))"), {"chave": chave})

    async def somar_janela(self, chave: str, limite: datetime) -> int:
        stmt = select(func.coalesce(func.sum(LimiteUploadEvento.bytes), 0)).where(
            LimiteUploadEvento.chave == chave, LimiteUploadEvento.ocorrido_em > limite
        )
        return int((await self.sessao.execute(stmt)).scalar_one())

    async def registrar(self, chaves: list[str], ocorrido_em: datetime, tamanho: int) -> None:
        await self.sessao.execute(
            pg_insert(LimiteUploadEvento),
            [{"chave": c, "ocorrido_em": ocorrido_em, "bytes": tamanho} for c in chaves],
        )

    async def limpar_antigos(self, limite: datetime) -> None:
        await self.sessao.execute(delete(LimiteUploadEvento).where(LimiteUploadEvento.ocorrido_em <= limite))

    async def limpar_tudo(self) -> None:
        await self.sessao.execute(delete(LimiteUploadEvento))
