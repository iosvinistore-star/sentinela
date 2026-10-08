# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Casos de uso do SIEM (consulta de eventos, painéis, fontes e UEBA) sobre os repositórios."""
from sentinela.models import EdrTelemetria, SigmaAlerta, SiemCorrelacao, UebaAnomalia
from sentinela.repositories.siem import (
    CorrelacaoRepositorio,
    EdrRepositorio,
    EventoSiemRepositorio,
    SiemAgenteFonteRepositorio,
    SiemFonteRepositorio,
    UebaRepositorio,
)
from sentinela.siem.correlacao_siem import correlacionar_lote
from sentinela.siem.servico import persistir_eventos_com_ids
from sentinela.siem.ueba import avaliar_lote


class FonteSiemDuplicadaError(ValueError):
    """Já existe uma fonte com este nome (sem distinguir maiúsculas) nesta empresa."""


def _fonte_publica(fonte) -> dict:
    return {
        "id": fonte.id, "nome": fonte.nome, "tipo": fonte.tipo, "configuracao": fonte.configuracao,
        "ativo": fonte.ativo, "criado_em": fonte.criado_em,
    }


# --- eventos --------------------------------------------------------------------
async def consultar_eventos(sessao, empresa_id, limite: int, severidade: str | None, source_type: str | None) -> list[dict]:
    return await EventoSiemRepositorio(sessao).consultar(
        empresa_id, limite, severidade.upper() if severidade else None, source_type,
    )


# --- painéis ----------------------------------------------------------------------
async def resumo(sessao, empresa_id, horas: int) -> dict:
    repo = EventoSiemRepositorio(sessao)
    total = await repo.contar(empresa_id, horas)
    criticos = await repo.contar(empresa_id, horas, ("CRITICAL", "EMERGENCY", "ALERT"))
    return {
        "janela_horas": horas,
        "total_eventos": int(total or 0),
        "criticos": int(criticos or 0),
        "eps_medio": round((float(total or 0) / (horas * 3600)), 3),
        "fontes": await repo.por_tipo_de_fonte(empresa_id, horas),
        "severidades": await repo.por_severidade(empresa_id, horas),
        "por_minuto": await repo.por_minuto(empresa_id, horas),
    }


async def fontes_ativas(sessao, empresa_id) -> list[dict]:
    return await EventoSiemRepositorio(sessao).fontes_ativas(empresa_id)


async def soc_executivo(sessao, empresa_id) -> dict:
    eventos = EventoSiemRepositorio(sessao)
    correlacoes = CorrelacaoRepositorio(sessao)
    return {
        "janela": "24h",
        "eventos": int(await eventos.contar(empresa_id, 24)),
        "alto_risco": int(await eventos.contar(empresa_id, 24, ("HIGH", "CRITICAL", "EMERGENCY", "ALERT"))),
        "correlacoes": int(await correlacoes.contar_ultimas_24h(SiemCorrelacao, empresa_id)),
        "ueba_anomalias": int(await correlacoes.contar_ultimas_24h(UebaAnomalia, empresa_id)),
        "sigma_alertas": int(await correlacoes.contar_ultimas_24h(SigmaAlerta, empresa_id)),
        "edr_telemetria": int(await correlacoes.contar_ultimas_24h(EdrTelemetria, empresa_id)),
    }


async def correlacoes_recentes(sessao, empresa_id, limite: int) -> list[dict]:
    return await CorrelacaoRepositorio(sessao).recentes(empresa_id, limite)


# --- fontes ------------------------------------------------------------------------
async def listar_fontes(sessao, empresa_id) -> list[dict]:
    return [_fonte_publica(f) for f in await SiemFonteRepositorio(sessao).listar(empresa_id)]


async def criar_fonte(sessao, empresa_id, nome: str, tipo: str, configuracao: dict, ativo: bool) -> dict:
    from sqlalchemy.exc import IntegrityError

    try:
        # SAVEPOINT: a violação de unicidade não pode abortar a transação inteira do chamador.
        async with sessao.begin_nested():
            fonte = await SiemFonteRepositorio(sessao).criar(empresa_id, nome, tipo.lower(), configuracao, ativo)
    except IntegrityError as exc:
        raise FonteSiemDuplicadaError(nome) from exc
    return _fonte_publica(fonte)


async def atualizar_fonte(sessao, empresa_id, fonte_id: int, nome: str, tipo: str, configuracao: dict, ativo: bool) -> dict | None:
    fonte = await SiemFonteRepositorio(sessao).atualizar(empresa_id, fonte_id, nome, tipo.lower(), configuracao, ativo)
    return _fonte_publica(fonte) if fonte else None


async def excluir_fonte(sessao, empresa_id, fonte_id: int) -> bool:
    return await SiemFonteRepositorio(sessao).excluir(empresa_id, fonte_id)


# --- UEBA ----------------------------------------------------------------------------
async def listar_anomalias(sessao, empresa_id, limite: int) -> list[dict]:
    return await UebaRepositorio(sessao).listar_anomalias(empresa_id, limite)


async def reavaliar_ueba(sessao, empresa_id, limite: int) -> dict:
    eventos = await EventoSiemRepositorio(sessao).recentes_para_ueba(empresa_id, limite)
    resultado = await avaliar_lote(sessao, str(empresa_id), [(e["id"], e) for e in eventos])
    return {
        "avaliados": len(eventos),
        "entidades_anomalas": len(resultado),
        "anomalias_criadas": sum(1 for a in resultado.values() if a["nova"]),
    }


# --- ingestão ----------------------------------------------------------------------------
async def ingerir_eventos_do_agente(sessao, empresa_id: str, agente_id: str, normalizados: list[dict]) -> dict:
    """Persiste o lote, correlaciona e contabiliza por tipo de fonte do agente."""
    ids = await persistir_eventos_com_ids(sessao, empresa_id, normalizados, agente_id)
    resultado = await correlacionar_lote(sessao, empresa_id, list(zip(ids, normalizados)))
    por_tipo: dict[str, tuple] = {}
    for ev in normalizados:
        tipo = str(ev["source_type"])
        ts, n = por_tipo.get(tipo, (ev["timestamp"], 0))
        por_tipo[tipo] = (max(ts, ev["timestamp"]), n + 1)
    await SiemAgenteFonteRepositorio(sessao).somar_lote(empresa_id, agente_id, por_tipo)
    return resultado


async def registrar_processos_suspeitos_edr(sessao, empresa_id, agente_id, hostname: str, processos: list[dict]) -> None:
    """Preserva a telemetria de processos suspeitos do heartbeat, deduplicada por (agente, pid, processo) na última hora."""
    repo = EdrRepositorio(sessao)
    for proc in processos:
        await repo.inserir_processo_suspeito_deduplicado(
            empresa_id, agente_id, hostname, proc["nome"], proc["pid"], proc["usuario"],
            {"linha_de_comando": proc["linha_de_comando"], "origem": "heartbeat"},
        )
