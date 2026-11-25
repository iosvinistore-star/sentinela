# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Acesso a dados do SIEM: eventos, fontes, correlações, Sigma, SOAR, CTI, UEBA e EDR."""
from datetime import timedelta
from typing import Any

from sqlalchemy import delete, desc, exists, func, literal, literal_column, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from sentinela.models import (
    CtiIndicador,
    EdrTelemetria,
    EventoSiem,
    EventoSiemCold,
    SiemAgenteFonte,
    SiemCorrelacao,
    SiemFonte,
    SigmaAlerta,
    SigmaRegra,
    SoarExecucao,
    SoarPlaybook,
    UebaAnomalia,
)
from sentinela.repositories.base import RepositorioBase


def _linhas(resultado) -> list[dict]:
    return [dict(r._mapping) for r in resultado]


def _janela(horas: int):
    return func.now() - timedelta(hours=horas)


class EventoSiemRepositorio(RepositorioBase):
    async def inserir_lote(self, linhas: list[dict[str, Any]]) -> list[int]:
        """INSERT multi-linha; devolve os ids na MESMA ordem do lote (garantido pelo `insertmanyvalues`)."""
        resultado = await self.sessao.execute(pg_insert(EventoSiem).returning(EventoSiem.id), linhas)
        return list(resultado.scalars())

    async def consultar(self, empresa_id, limite: int, severidade: str | None, source_type: str | None) -> list[dict]:
        stmt = select(
            EventoSiem.id, EventoSiem.timestamp, EventoSiem.source, EventoSiem.source_type, EventoSiem.hostname,
            func.host(EventoSiem.source_ip).label("source_ip"), EventoSiem.event_type, EventoSiem.action,
            EventoSiem.severity, EventoSiem.message, EventoSiem.tags, EventoSiem.mitre_techniques, EventoSiem.iocs,
        ).where(EventoSiem.empresa_id == empresa_id)
        if severidade:
            stmt = stmt.where(EventoSiem.severity == severidade)
        if source_type:
            stmt = stmt.where(EventoSiem.source_type == source_type)
        return _linhas(await self.sessao.execute(stmt.order_by(EventoSiem.timestamp.desc()).limit(limite)))

    async def obter_para_sigma(self, empresa_id, evento_id: int) -> dict | None:
        stmt = select(
            EventoSiem.id, EventoSiem.timestamp, EventoSiem.source, EventoSiem.source_type, EventoSiem.hostname,
            func.host(EventoSiem.source_ip).label("source_ip"),
            func.host(EventoSiem.destination_ip).label("destination_ip"),
            EventoSiem.source_port, EventoSiem.destination_port, EventoSiem.protocol, EventoSiem.username,
            EventoSiem.event_type, EventoSiem.action, EventoSiem.severity, EventoSiem.message, EventoSiem.raw_event,
        ).where(EventoSiem.id == evento_id, EventoSiem.empresa_id == empresa_id)
        linha = (await self.sessao.execute(stmt)).one_or_none()
        return dict(linha._mapping) if linha else None

    async def recentes_para_ueba(self, empresa_id, limite: int) -> list[dict]:
        stmt = (
            select(
                EventoSiem.id, EventoSiem.source_type, EventoSiem.hostname,
                func.host(EventoSiem.source_ip).label("source_ip"), EventoSiem.username, EventoSiem.event_type,
                EventoSiem.severity,
            )
            .where(EventoSiem.empresa_id == empresa_id, EventoSiem.timestamp >= _janela(1))
            .order_by(EventoSiem.id.desc()).limit(limite)
        )
        return _linhas(await self.sessao.execute(stmt))

    # --- painéis -------------------------------------------------------------
    async def contar(self, empresa_id, horas: int, severidades: tuple[str, ...] | None = None) -> int:
        stmt = select(func.count()).select_from(EventoSiem).where(
            EventoSiem.empresa_id == empresa_id, EventoSiem.timestamp >= _janela(horas)
        )
        if severidades:
            stmt = stmt.where(EventoSiem.severity.in_(severidades))
        return (await self.sessao.execute(stmt)).scalar_one()

    async def por_tipo_de_fonte(self, empresa_id, horas: int) -> list[dict]:
        stmt = (
            select(
                EventoSiem.source_type,
                func.count().label("eventos"),
                func.count(func.distinct(EventoSiem.source)).label("fontes"),
            )
            .where(EventoSiem.empresa_id == empresa_id, EventoSiem.timestamp >= _janela(horas))
            .group_by(EventoSiem.source_type).order_by(desc("eventos"))
        )
        return _linhas(await self.sessao.execute(stmt))

    async def por_severidade(self, empresa_id, horas: int) -> list[dict]:
        stmt = (
            select(EventoSiem.severity, func.count().label("eventos"))
            .where(EventoSiem.empresa_id == empresa_id, EventoSiem.timestamp >= _janela(horas))
            .group_by(EventoSiem.severity).order_by(desc("eventos"))
        )
        return _linhas(await self.sessao.execute(stmt))

    async def por_minuto(self, empresa_id, horas: int, limite: int = 120) -> list[dict]:
        minuto = func.date_trunc("minute", EventoSiem.timestamp).label("minuto")
        stmt = (
            select(minuto, func.count().label("eventos"))
            .where(EventoSiem.empresa_id == empresa_id, EventoSiem.timestamp >= _janela(horas))
            .group_by(minuto).order_by(desc(minuto)).limit(limite)
        )
        return _linhas(await self.sessao.execute(stmt))

    async def fontes_ativas(self, empresa_id, limite: int = 500) -> list[dict]:
        ultimo = func.max(EventoSiem.timestamp).label("ultimo_evento")
        stmt = (
            select(
                EventoSiem.source, EventoSiem.source_type, ultimo,
                func.count().filter(EventoSiem.timestamp >= func.now() - timedelta(minutes=15)).label("eventos_15m"),
            )
            .where(EventoSiem.empresa_id == empresa_id, EventoSiem.timestamp >= _janela(24))
            .group_by(EventoSiem.source, EventoSiem.source_type)
            .order_by(desc(ultimo).nulls_last()).limit(limite)
        )
        return _linhas(await self.sessao.execute(stmt))

    async def volume_da_entidade(self, empresa_id, tipo: str, valor: str) -> tuple[int, float]:
        """(eventos na última hora, média horária das 24h anteriores) de uma entidade (usuário/ip/host)."""
        coluna = {"usuario": EventoSiem.username, "ip": EventoSiem.source_ip, "host": EventoSiem.hostname}[tipo]
        stmt = select(
            func.count().filter(EventoSiem.timestamp >= _janela(1)).label("atual"),
            (func.count().filter(EventoSiem.timestamp < _janela(1)) / literal(24.0)).label("media"),
        ).where(EventoSiem.empresa_id == empresa_id, coluna == valor, EventoSiem.timestamp >= _janela(25))
        linha = (await self.sessao.execute(stmt)).one()
        return int(linha.atual or 0), float(linha.media or 0)


class SiemFonteRepositorio(RepositorioBase):
    async def listar(self, empresa_id) -> list[SiemFonte]:
        stmt = select(SiemFonte).where(SiemFonte.empresa_id == empresa_id).order_by(SiemFonte.nome)
        return list((await self.sessao.execute(stmt)).scalars())

    async def criar(self, empresa_id, nome, tipo, configuracao, ativo) -> SiemFonte:
        fonte = SiemFonte(empresa_id=empresa_id, nome=nome, tipo=tipo, configuracao=configuracao, ativo=ativo)
        self.sessao.add(fonte)
        await self.sessao.flush()
        await self.sessao.refresh(fonte)
        return fonte

    async def atualizar(self, empresa_id, fonte_id: int, nome, tipo, configuracao, ativo) -> SiemFonte | None:
        stmt = (
            update(SiemFonte).where(SiemFonte.empresa_id == empresa_id, SiemFonte.id == fonte_id)
            .values(nome=nome, tipo=tipo, configuracao=configuracao, ativo=ativo)
            .returning(SiemFonte).execution_options(synchronize_session=False)
        )
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    async def excluir(self, empresa_id, fonte_id: int) -> bool:
        stmt = delete(SiemFonte).where(SiemFonte.empresa_id == empresa_id, SiemFonte.id == fonte_id)
        return (await self.sessao.execute(stmt)).rowcount > 0


class SiemAgenteFonteRepositorio(RepositorioBase):
    async def somar_lote(self, empresa_id, agente_id, por_tipo: dict) -> None:
        """Soma SÓ o lote atual por tipo de fonte. `sorted()`: ordem de lock determinística entre lotes concorrentes."""
        for tipo, (ultimo_em, total) in sorted(por_tipo.items()):
            novo = pg_insert(SiemAgenteFonte).values(
                empresa_id=empresa_id, agente_id=agente_id, tipo=tipo, ultimo_evento_em=ultimo_em, total_eventos=total
            )
            await self.sessao.execute(
                novo.on_conflict_do_update(
                    index_elements=["agente_id", "tipo"],
                    set_={
                        "ultimo_evento_em": func.greatest(SiemAgenteFonte.ultimo_evento_em, novo.excluded.ultimo_evento_em),
                        "total_eventos": SiemAgenteFonte.total_eventos + novo.excluded.total_eventos,
                    },
                )
            )


class CorrelacaoRepositorio(RepositorioBase):
    """Persistência do motor de correlação (siem/correlacao_siem.py) e leitura das correlações."""

    async def sigma_ativas(self, empresa_id) -> list[dict]:
        stmt = select(SigmaRegra.id, SigmaRegra.nome, SigmaRegra.nivel, SigmaRegra.logsource, SigmaRegra.detection).where(
            SigmaRegra.empresa_id == empresa_id, SigmaRegra.ativo.is_(True)
        )
        return _linhas(await self.sessao.execute(stmt))

    async def playbooks_ativos(self, empresa_id) -> list[dict]:
        stmt = select(SoarPlaybook.id, SoarPlaybook.nome, SoarPlaybook.gatilho, SoarPlaybook.acoes).where(
            SoarPlaybook.empresa_id == empresa_id, SoarPlaybook.ativo.is_(True)
        )
        return _linhas(await self.sessao.execute(stmt))

    async def indicadores_por_valor(self, empresa_id, valores: list[str]) -> list[dict]:
        """Indicadores CTI vigentes cujo valor (em minúsculas) está em `valores`."""
        stmt = select(CtiIndicador.id, CtiIndicador.indicator_type, CtiIndicador.valor, CtiIndicador.confidence).where(
            CtiIndicador.empresa_id == empresa_id,
            func.lower(CtiIndicador.valor).in_(valores),
            (CtiIndicador.valid_until.is_(None)) | (CtiIndicador.valid_until > func.now()),
        )
        return _linhas(await self.sessao.execute(stmt))

    async def inserir_sigma_alertas(self, linhas: list[dict]) -> None:
        stmt = pg_insert(SigmaAlerta).on_conflict_do_nothing(index_elements=["regra_id", "evento_id"])
        await self.sessao.execute(stmt, linhas)

    async def inserir_correlacoes(self, linhas: list[dict]) -> None:
        await self.sessao.execute(pg_insert(SiemCorrelacao), linhas)

    async def inserir_execucoes(self, linhas: list[dict]) -> None:
        await self.sessao.execute(pg_insert(SoarExecucao), linhas)

    async def contar_ultimas_24h(self, modelo, empresa_id) -> int:
        stmt = select(func.count()).select_from(modelo).where(
            modelo.empresa_id == empresa_id, modelo.criado_em >= _janela(24)
        )
        return (await self.sessao.execute(stmt)).scalar_one()

    async def recentes(self, empresa_id, limite: int) -> list[dict]:
        """Correlações mais recentes com o resumo do evento de origem (primeiro de `evento_ids`)."""
        c, e = SiemCorrelacao, EventoSiem
        stmt = (
            select(
                c.id, c.regra, c.severidade, c.score, c.cti_match, c.playbook_id, c.criado_em,
                c.detalhes["regras"].label("regras"), c.detalhes["sigma"].label("sigma"),
                e.source_type, e.hostname, e.username, func.host(e.source_ip).label("source_ip"),
                func.host(e.destination_ip).label("destination_ip"), e.event_type,
                func.left(e.message, 240).label("message"),
            )
            .outerjoin(e, (e.id == c.evento_ids[1]) & (e.empresa_id == c.empresa_id))
            .where(c.empresa_id == empresa_id)
            .order_by(c.criado_em.desc(), c.id.desc()).limit(limite)
        )
        return _linhas(await self.sessao.execute(stmt))


class SigmaRepositorio(RepositorioBase):
    async def salvar_regra(self, empresa_id, nome, titulo, nivel, logsource, detection, tags, ativo) -> SigmaRegra:
        novo = pg_insert(SigmaRegra).values(
            empresa_id=empresa_id, nome=nome, titulo=titulo, nivel=nivel, logsource=logsource,
            detection=detection, tags=tags, ativo=ativo,
        )
        stmt = novo.on_conflict_do_update(
            index_elements=["empresa_id", "nome"],
            set_={
                "titulo": novo.excluded.titulo, "nivel": novo.excluded.nivel, "logsource": novo.excluded.logsource,
                "detection": novo.excluded.detection, "tags": novo.excluded.tags, "ativo": novo.excluded.ativo,
                "atualizado_em": func.now(),
            },
        ).returning(SigmaRegra)
        return (await self.sessao.execute(stmt)).scalar_one()

    async def listar_regras(self, empresa_id, apenas_ativas: bool = False) -> list[SigmaRegra]:
        stmt = select(SigmaRegra).where(SigmaRegra.empresa_id == empresa_id)
        if apenas_ativas:
            stmt = stmt.where(SigmaRegra.ativo.is_(True))
        return list((await self.sessao.execute(stmt.order_by(SigmaRegra.id.desc()))).scalars())

    async def listar_alertas(self, empresa_id, limite: int) -> list[dict]:
        a = SigmaAlerta
        stmt = (
            select(a.id, a.regra_id, SigmaRegra.nome.label("regra"), a.evento_id, a.severidade, a.evidencias, a.criado_em)
            .join(SigmaRegra, SigmaRegra.id == a.regra_id)
            .where(a.empresa_id == empresa_id).order_by(a.criado_em.desc()).limit(limite)
        )
        return _linhas(await self.sessao.execute(stmt))

    async def registrar_alerta(self, empresa_id, regra_id: int, evento_id: int, severidade: str, evidencias: dict) -> int:
        novo = pg_insert(SigmaAlerta).values(
            empresa_id=empresa_id, regra_id=regra_id, evento_id=evento_id, severidade=severidade, evidencias=evidencias
        )
        stmt = novo.on_conflict_do_update(
            index_elements=["regra_id", "evento_id"], set_={"severidade": novo.excluded.severidade}
        ).returning(SigmaAlerta.id)
        return (await self.sessao.execute(stmt)).scalar_one()


class SoarRepositorio(RepositorioBase):
    async def criar_playbook(self, empresa_id, nome, gatilho, acoes, ativo) -> SoarPlaybook:
        playbook = SoarPlaybook(empresa_id=empresa_id, nome=nome, gatilho=gatilho, acoes=acoes, ativo=ativo)
        self.sessao.add(playbook)
        await self.sessao.flush()
        await self.sessao.refresh(playbook)
        return playbook

    async def listar_playbooks(self, empresa_id) -> list[SoarPlaybook]:
        stmt = select(SoarPlaybook).where(SoarPlaybook.empresa_id == empresa_id).order_by(SoarPlaybook.id.desc())
        return list((await self.sessao.execute(stmt)).scalars())

    async def atualizar_playbook(self, empresa_id, playbook_id: int, campos: dict) -> SoarPlaybook | None:
        stmt = (
            update(SoarPlaybook).where(SoarPlaybook.id == playbook_id, SoarPlaybook.empresa_id == empresa_id)
            .values(**campos).returning(SoarPlaybook).execution_options(synchronize_session=False)
        )
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    async def obter_ativo(self, empresa_id, playbook_id: int) -> SoarPlaybook | None:
        stmt = select(SoarPlaybook).where(
            SoarPlaybook.id == playbook_id, SoarPlaybook.empresa_id == empresa_id, SoarPlaybook.ativo.is_(True)
        )
        return (await self.sessao.execute(stmt)).scalar_one_or_none()

    async def listar_execucoes(self, empresa_id, limite: int) -> list[dict]:
        e = SoarExecucao
        stmt = (
            select(
                e.id, e.playbook_id, SoarPlaybook.nome.label("playbook"), e.incidente_id, e.status, e.executado_em,
                e.resultado["regra"].astext.label("regra"), e.resultado["evento_id"].label("evento_id"),
            )
            .join(SoarPlaybook, SoarPlaybook.id == e.playbook_id)
            .where(e.empresa_id == empresa_id).order_by(e.executado_em.desc(), e.id.desc()).limit(limite)
        )
        return _linhas(await self.sessao.execute(stmt))

    async def registrar_execucao(self, empresa_id, playbook_id, incidente_id, status: str, resultado: dict):
        execucao = SoarExecucao(
            empresa_id=empresa_id, playbook_id=playbook_id, incidente_id=incidente_id, status=status, resultado=resultado
        )
        self.sessao.add(execucao)
        await self.sessao.flush()
        await self.sessao.refresh(execucao)
        return execucao


class CtiRepositorio(RepositorioBase):
    async def upsert_lote(self, empresa_id, indicadores: list[dict]) -> None:
        linhas = [
            {
                "empresa_id": empresa_id, "stix_id": i["stix_id"], "tipo": i["tipo"],
                "indicator_type": i["indicator_type"], "valor": i["valor"], "pattern": i["pattern"],
                "confidence": i["confidence"], "valid_until": i["valid_until"], "labels": i["labels"], "raw": i["raw"],
            }
            for i in indicadores
        ]
        novo = pg_insert(CtiIndicador)
        stmt = novo.on_conflict_do_update(
            index_elements=["empresa_id", "stix_id"],
            set_={c: getattr(novo.excluded, c) for c in
                  ("indicator_type", "valor", "pattern", "confidence", "valid_until", "labels", "raw")},
        )
        await self.sessao.execute(stmt, linhas)

    async def listar_recentes(self, empresa_id, limite: int) -> list[dict]:
        c = CtiIndicador
        stmt = (
            select(c.id, c.stix_id, c.indicator_type, c.valor, c.confidence, c.valid_until, c.labels, c.criado_em)
            .where(c.empresa_id == empresa_id).order_by(c.criado_em.desc()).limit(limite)
        )
        return _linhas(await self.sessao.execute(stmt))

    async def listar_para_feed(self, empresa_id, depois_do_id: int, limite: int) -> list[dict]:
        c = CtiIndicador
        stmt = (
            select(c.id, c.stix_id, c.indicator_type, c.valor, c.pattern, c.confidence, c.valid_until, c.labels, c.criado_em)
            .where(c.empresa_id == empresa_id, c.id > depois_do_id).order_by(c.id).limit(limite)
        )
        return _linhas(await self.sessao.execute(stmt))


class UebaRepositorio(RepositorioBase):
    async def listar_anomalias(self, empresa_id, limite: int) -> list[dict]:
        a = UebaAnomalia
        stmt = (
            select(a.id, a.evento_id, a.chave, a.tipo, a.score, a.motivo, a.evidencias, a.janela_hora, a.criado_em)
            .where(a.empresa_id == empresa_id).order_by(a.criado_em.desc()).limit(limite)
        )
        return _linhas(await self.sessao.execute(stmt))

    async def registrar_anomalia(self, empresa_id, evento_id, chave, tipo, score, motivo, evidencias) -> dict:
        """No máximo UMA anomalia por entidade por hora; `nova` = (xmax = 0) distingue insert de update."""
        janela = func.date_trunc("hour", func.timezone("UTC", func.now()))
        novo = pg_insert(UebaAnomalia).values(
            empresa_id=empresa_id, evento_id=evento_id, chave=chave, tipo=tipo, score=score, motivo=motivo,
            evidencias=evidencias, janela_hora=func.timezone("UTC", janela),
        )
        stmt = novo.on_conflict_do_update(
            index_elements=["empresa_id", "chave", "janela_hora"],
            set_={"score": func.greatest(UebaAnomalia.score, novo.excluded.score), "evidencias": novo.excluded.evidencias},
        ).returning(
            UebaAnomalia.id, UebaAnomalia.score, UebaAnomalia.motivo, literal_column("(xmax = 0)").label("nova")
        )
        return dict((await self.sessao.execute(stmt)).one()._mapping)


class EdrRepositorio(RepositorioBase):
    async def inserir(self, empresa_id, **campos) -> dict:
        stmt = pg_insert(EdrTelemetria).values(empresa_id=empresa_id, **campos).returning(
            EdrTelemetria.id, EdrTelemetria.criado_em
        )
        return dict((await self.sessao.execute(stmt)).one()._mapping)

    async def inserir_processo_suspeito_deduplicado(
        self, empresa_id, agente_id, hostname, processo, pid, usuario, detalhes: dict
    ) -> None:
        """Grava um processo suspeito, a menos que (agente, pid, processo) já tenha sido gravado na última hora."""
        t = EdrTelemetria
        ja_existe = exists().where(
            t.empresa_id == empresa_id, t.agente_id == agente_id, t.pid.is_not_distinct_from(pid),
            t.processo.is_not_distinct_from(processo), t.criado_em > func.now() - timedelta(hours=1),
        )
        origem = select(
            literal(empresa_id, t.empresa_id.type), literal(agente_id, t.agente_id.type),
            literal("processo_suspeito"), literal(hostname, t.hostname.type), literal(processo, t.processo.type),
            literal(pid, t.pid.type), literal(usuario, t.usuario.type), literal(detalhes, t.detalhes.type),
            literal("HIGH"),
        ).where(~ja_existe)
        await self.sessao.execute(
            pg_insert(t).from_select(
                ["empresa_id", "agente_id", "tipo", "hostname", "processo", "pid", "usuario", "detalhes", "severidade"],
                origem,
            )
        )

    async def listar(self, empresa_id, limite: int) -> list[dict]:
        t = EdrTelemetria
        stmt = (
            select(
                t.id, t.agente_id, t.tipo, t.hostname, t.processo, t.pid, t.usuario, t.caminho, t.hash_sha256,
                t.parent_pid, func.host(t.destino_ip).label("destino_ip"), t.destino_porta, t.protocolo,
                t.severidade, t.detalhes, t.criado_em,
            )
            .where(t.empresa_id == empresa_id).order_by(t.criado_em.desc()).limit(limite)
        )
        return _linhas(await self.sessao.execute(stmt))

    async def resumo_24h(self, empresa_id) -> list[dict]:
        t = EdrTelemetria
        stmt = (
            select(t.tipo, func.count().label("total"))
            .where(t.empresa_id == empresa_id, t.criado_em >= _janela(24))
            .group_by(t.tipo).order_by(desc("total"))
        )
        return _linhas(await self.sessao.execute(stmt))


class RetencaoSiemRepositorio(RepositorioBase):
    """Retenção quente -> fria -> descarte. Requer sessão superadmin (enxerga todos os tenants)."""

    async def mover_fatia_para_frio(self, hot_days: int, cold_days: int, tamanho_fatia: int) -> tuple[int, int]:
        """
        Remove até `tamanho_fatia` eventos mais velhos que `hot_days` do armazenamento quente e copia para o frio
        os que ainda estão dentro de `cold_days` (os mais velhos que isso são apenas descartados).
        Devolve (removidos, arquivados) -- uma única instrução, atômica.
        """
        alvo = (
            select(EventoSiem.id).where(EventoSiem.timestamp < func.now() - timedelta(days=hot_days))
            .order_by(EventoSiem.timestamp).limit(tamanho_fatia).cte("alvo")
        )
        movidos = (
            delete(EventoSiem).where(EventoSiem.id.in_(select(alvo.c.id)))
            .returning(*EventoSiem.__table__.c).cte("movidos")
        )
        colunas = [c.key for c in EventoSiemCold.__table__.c if c.key != "arquivado_em"]
        arquivados = (
            pg_insert(EventoSiemCold)
            .from_select(
                [*colunas, "arquivado_em"],
                select(*[movidos.c[c] for c in colunas], func.now()).where(
                    movidos.c.timestamp >= func.now() - timedelta(days=cold_days)
                ),
            )
            .on_conflict_do_nothing(index_elements=["id"])
            .returning(literal(1).label("um")).cte("arquivados")
        )
        stmt = select(
            select(func.count()).select_from(movidos).scalar_subquery().label("removidos"),
            select(func.count()).select_from(arquivados).scalar_subquery().label("arquivados"),
        )
        linha = (await self.sessao.execute(stmt)).one()
        return int(linha.removidos), int(linha.arquivados)

    async def expirar_fatia_do_frio(self, cold_days: int, tamanho_fatia: int) -> int:
        alvo = (
            select(EventoSiemCold.id).where(EventoSiemCold.timestamp < func.now() - timedelta(days=cold_days))
            .limit(tamanho_fatia)
        )
        return (await self.sessao.execute(delete(EventoSiemCold).where(EventoSiemCold.id.in_(alvo)))).rowcount
