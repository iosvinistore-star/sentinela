# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Acesso a dados de `bloqueios_firewall`."""
from sqlalchemy import exists, func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from sentinela.models import BloqueioFirewall
from sentinela.repositories.base import RepositorioBase


class FirewallRepositorio(RepositorioBase):
    async def travar_ip(self, ip: str) -> None:
        """
        Lock consultivo até o fim da transação, chaveado só pelo IP: o
        enforcement do kernel é HOST-WIDE, então a serialização também
        precisa ser entre QUALQUER tenant que mexa neste IP.
        """
        await self.sessao.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:ip, 0))"), {"ip": ip})

    async def registrar_ativo(self, empresa_id, ip, motivo, origem, expira_em, usuario_id, incidente_id) -> None:
        novo = pg_insert(BloqueioFirewall).values(
            empresa_id=empresa_id, ip=ip, motivo=motivo, origem=origem, status="ativo",
            bloqueado_em=func.now(), expira_em=expira_em,
            criado_por_usuario_id=usuario_id, incidente_id=incidente_id,
        )
        await self.sessao.execute(
            novo.on_conflict_do_update(
                index_elements=["empresa_id", "ip"],
                index_where=BloqueioFirewall.status == "ativo",
                set_={
                    "motivo": novo.excluded.motivo,
                    "expira_em": novo.excluded.expira_em,
                    "bloqueado_em": func.now(),
                    "incidente_id": func.coalesce(novo.excluded.incidente_id, BloqueioFirewall.incidente_id),
                },
            )
        )

    async def tem_ativo_proprio(self, empresa_id, ip: str) -> bool:
        stmt = select(
            exists().where(
                BloqueioFirewall.empresa_id == empresa_id,
                BloqueioFirewall.ip == ip,
                BloqueioFirewall.status == "ativo",
            )
        )
        return bool((await self.sessao.execute(stmt)).scalar())

    async def outra_empresa_depende(self, empresa_id, ip: str) -> bool:
        """Só enxerga bloqueios de TODAS as empresas numa sessão superadmin (BYPASSRLS)."""
        stmt = select(
            exists().where(
                BloqueioFirewall.ip == ip,
                BloqueioFirewall.status == "ativo",
                BloqueioFirewall.empresa_id != empresa_id,
            )
        )
        return bool((await self.sessao.execute(stmt)).scalar())

    async def marcar_removido(self, empresa_id, ip: str):
        stmt = (
            update(BloqueioFirewall)
            .where(
                BloqueioFirewall.empresa_id == empresa_id,
                BloqueioFirewall.ip == ip,
                BloqueioFirewall.status == "ativo",
            )
            .values(status="removido", removido_em=func.now())
            .returning(BloqueioFirewall.bloqueado_em, BloqueioFirewall.removido_em, BloqueioFirewall.incidente_id)
            .execution_options(synchronize_session=False)
        )
        return (await self.sessao.execute(stmt)).one_or_none()

    async def listar_ativos(self, empresa_id) -> list[BloqueioFirewall]:
        stmt = (
            select(BloqueioFirewall)
            .where(BloqueioFirewall.empresa_id == empresa_id, BloqueioFirewall.status == "ativo")
            .order_by(BloqueioFirewall.bloqueado_em.desc())
        )
        return list((await self.sessao.execute(stmt)).scalars())

    async def expirar_fora_do_kernel(self, ips_ainda_ativos: list[str]) -> list[dict]:
        """Marca 'expirado' o que o kernel já não tem. host(ip), não ip::text (este inclui /32)."""
        stmt = (
            update(BloqueioFirewall)
            .where(
                BloqueioFirewall.status == "ativo",
                func.host(BloqueioFirewall.ip).not_in(ips_ainda_ativos),
            )
            .values(status="expirado")
            .returning(BloqueioFirewall.empresa_id, BloqueioFirewall.ip)
            .execution_options(synchronize_session=False)
        )
        return [dict(r._mapping) for r in await self.sessao.execute(stmt)]
