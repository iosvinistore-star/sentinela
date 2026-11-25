# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Escrita idempotente usada pelo script de migração do sentinela.db legado (single-tenant) para o Postgres."""
from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from sentinela.models import Auditoria, BloqueioFirewall, Empresa, Incidente, Usuario
from sentinela.repositories.base import RepositorioBase


class MigracaoLegadoRepositorio(RepositorioBase):
    async def garantir_empresa(self, empresa_id, nome: str) -> None:
        stmt = pg_insert(Empresa).values(id=empresa_id, nome=nome, plano="legado", status="ativa").on_conflict_do_nothing(
            index_elements=["id"]
        )
        await self.sessao.execute(stmt)

    async def garantir_admin(self, empresa_id, email: str, senha_hash: str) -> None:
        stmt = pg_insert(Usuario).values(
            empresa_id=empresa_id, email=email, papel="admin", senha_hash=senha_hash
        ).on_conflict_do_nothing(index_elements=["email"])
        await self.sessao.execute(stmt)

    async def inserir_incidente(self, empresa_id, m: dict) -> bool:
        """True se inseriu; False se o incident_id já existia (reexecução idempotente)."""
        stmt = (
            pg_insert(Incidente)
            .values(
                empresa_id=empresa_id, incident_id=m["incident_id"], ip=m["ip"], severidade=m["severidade"],
                pontuacao_risco=m["pontuacao_risco"], status=m["status"], ataques=m["ataques"],
                observacoes=m["observacoes"], criado_em=m["criado_em"], atualizado_em=m["atualizado_em"],
            )
            .on_conflict_do_nothing(index_elements=["empresa_id", "incident_id"])
            .returning(Incidente.id)
        )
        return (await self.sessao.execute(stmt)).first() is not None

    async def inserir_bloqueio(self, empresa_id, ip, motivo, origem, bloqueado_em, expira_em) -> bool:
        stmt = (
            pg_insert(BloqueioFirewall)
            .values(
                empresa_id=empresa_id, ip=ip, motivo=motivo, origem=origem, status="ativo",
                bloqueado_em=bloqueado_em, expira_em=expira_em,
            )
            .on_conflict_do_nothing(index_elements=["empresa_id", "ip"], index_where=text("status = 'ativo'"))
            .returning(BloqueioFirewall.id)
        )
        return (await self.sessao.execute(stmt)).first() is not None

    async def inserir_auditoria(self, empresa_id, acao: str, detalhes: dict, criado_em) -> None:
        self.sessao.add(Auditoria(
            empresa_id=empresa_id, ator_usuario_id=None, acao=acao, detalhes=detalhes,
            **({"criado_em": criado_em} if criado_em else {}),
        ))
        await self.sessao.flush()

    async def contar_incidentes(self, empresa_id) -> int:
        stmt = select(func.count()).select_from(Incidente).where(Incidente.empresa_id == empresa_id)
        return (await self.sessao.execute(stmt)).scalar_one()

    async def contar_bloqueios_ativos(self, empresa_id) -> int:
        stmt = select(func.count()).select_from(BloqueioFirewall).where(
            BloqueioFirewall.empresa_id == empresa_id, BloqueioFirewall.status == "ativo"
        )
        return (await self.sessao.execute(stmt)).scalar_one()

    async def amostra_de_incidentes(self, empresa_id, tamanho: int) -> list[dict]:
        stmt = (
            select(Incidente.incident_id, func.host(Incidente.ip).label("ip"), Incidente.severidade, Incidente.pontuacao_risco)
            .where(Incidente.empresa_id == empresa_id).order_by(func.random()).limit(tamanho)
        )
        return [dict(r._mapping) for r in await self.sessao.execute(stmt)]
