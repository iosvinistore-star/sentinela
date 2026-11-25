# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Regras Sigma por tenant e avaliação manual de eventos."""
from sentinela.repositories.siem import EventoSiemRepositorio, SigmaRepositorio
from sentinela.siem.sigma import SigmaErro, compilar_regra


class EventoNaoEncontradoError(LookupError):
    pass


def _regra_publica(regra) -> dict:
    return regra.para_dict()


async def salvar_regra(sessao, empresa_id, dados: dict) -> dict:
    regra = await SigmaRepositorio(sessao).salvar_regra(
        empresa_id, dados["nome"], dados["titulo"], dados["nivel"], dados["logsource"],
        dados["detection"], dados["tags"], dados["ativo"],
    )
    return _regra_publica(regra)


async def listar_regras(sessao, empresa_id) -> list[dict]:
    return [_regra_publica(r) for r in await SigmaRepositorio(sessao).listar_regras(empresa_id)]


async def listar_alertas(sessao, empresa_id, limite: int) -> list[dict]:
    return await SigmaRepositorio(sessao).listar_alertas(empresa_id, limite)


async def avaliar_evento(sessao, empresa_id, evento_id: int) -> list[dict]:
    """Roda as regras ativas contra um evento e registra um alerta por regra que casar."""
    evento = await EventoSiemRepositorio(sessao).obter_para_sigma(empresa_id, evento_id)
    if evento is None:
        raise EventoNaoEncontradoError(evento_id)
    repo = SigmaRepositorio(sessao)
    hits = []
    for regra in await repo.listar_regras(empresa_id, apenas_ativas=True):
        r = _regra_publica(regra)
        try:
            casa = compilar_regra(r).casa(evento)
        except SigmaErro:
            continue
        if casa:
            alerta_id = await repo.registrar_alerta(
                empresa_id, r["id"], evento_id, str(r["nivel"]).upper(), {"regra": r["nome"], "automatico": False},
            )
            hits.append({"alerta_id": alerta_id, "regra": r["nome"]})
    return hits
