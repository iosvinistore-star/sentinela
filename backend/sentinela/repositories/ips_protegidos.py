# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Acesso a dados de `ips_protegidos` (whitelist persistida por tenant)."""
from sqlalchemy import delete, func, select

from sentinela.models import IpProtegido
from sentinela.repositories.base import RepositorioBase


class IpProtegidoRepositorio(RepositorioBase):
    async def listar(self, empresa_id) -> list[IpProtegido]:
        stmt = select(IpProtegido).where(IpProtegido.empresa_id == empresa_id).order_by(IpProtegido.criado_em.desc())
        return list((await self.sessao.execute(stmt)).scalars())

    async def substituir(self, empresa_id, ip, motivo, origem, criado_por) -> IpProtegido:
        """
        DELETE + INSERT, não `ON CONFLICT DO UPDATE`: `app_tenant` deliberadamente
        NÃO tem GRANT UPDATE nesta tabela (uma entrada é criada ou removida,
        nunca editada -- preserva o rastro). Chamador envolve num SAVEPOINT.
        """
        await self.sessao.execute(delete(IpProtegido).where(IpProtegido.empresa_id == empresa_id, IpProtegido.ip == ip))
        novo = IpProtegido(empresa_id=empresa_id, ip=ip, motivo=motivo, origem=origem, criado_por_usuario_id=criado_por)
        self.sessao.add(novo)
        await self.sessao.flush()
        await self.sessao.refresh(novo)
        return novo

    async def remover(self, empresa_id, ip) -> bool:
        stmt = delete(IpProtegido).where(IpProtegido.empresa_id == empresa_id, IpProtegido.ip == ip).returning(IpProtegido.id)
        return (await self.sessao.execute(stmt)).first() is not None

    async def listar_enderecos(self, empresa_id) -> list[str]:
        stmt = select(func.host(IpProtegido.ip)).where(IpProtegido.empresa_id == empresa_id)
        return list((await self.sessao.execute(stmt)).scalars())
