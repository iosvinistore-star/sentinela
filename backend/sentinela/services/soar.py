# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Playbooks SOAR: cadastro, edição, execuções registradas e acionamento manual."""
from sentinela.repositories.siem import SoarRepositorio


class PlaybookNaoEncontradoError(LookupError):
    pass


async def criar_playbook(sessao, empresa_id, nome, gatilho, acoes, ativo) -> dict:
    return (await SoarRepositorio(sessao).criar_playbook(empresa_id, nome, gatilho, acoes, ativo)).para_dict()


async def listar_playbooks(sessao, empresa_id) -> list[dict]:
    return [p.para_dict() for p in await SoarRepositorio(sessao).listar_playbooks(empresa_id)]


async def atualizar_playbook(sessao, empresa_id, playbook_id: int, campos: dict) -> dict:
    playbook = await SoarRepositorio(sessao).atualizar_playbook(empresa_id, playbook_id, campos)
    if playbook is None:
        raise PlaybookNaoEncontradoError(playbook_id)
    return playbook.para_dict()


async def listar_execucoes(sessao, empresa_id, limite: int) -> list[dict]:
    return await SoarRepositorio(sessao).listar_execucoes(empresa_id, limite)


async def acionar_manual(sessao, empresa_id, playbook_id: int, incidente_id, acionado_por) -> dict:
    """Registra o acionamento manual (auditoria). Nenhuma ação é executada pela plataforma."""
    repo = SoarRepositorio(sessao)
    playbook = await repo.obter_ativo(empresa_id, playbook_id)
    if playbook is None:
        raise PlaybookNaoEncontradoError(playbook_id)
    execucao = await repo.registrar_execucao(
        empresa_id, playbook_id, incidente_id, "ACIONADO_MANUAL",
        {"acoes_planejadas": playbook.acoes, "acionado_por": str(acionado_por), "execucao_destrutiva": False},
    )
    return {"playbook": playbook.nome, "id": execucao.id, "status": execucao.status, "executado_em": execucao.executado_em}
