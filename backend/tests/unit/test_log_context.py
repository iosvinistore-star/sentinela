# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testes de core/log_context.py -- Fase E / E2, ver
ARQUITETURA_OBSERVABILIDADE.md §1.3.
"""
import asyncio

from sentinela.core.log_context import adicionar_contexto, iniciar_contexto, obter_contexto


def test_iniciar_contexto_sem_argumentos_zera_tudo():
    # Não assume que o contexto começa vazio no processo (evitaria
    # depender da ORDEM de execução em relação a outros testes que também
    # tocam este ContextVar) -- em vez disso, testa que `iniciar_contexto()`
    # sem argumentos é a forma correta de zerar.
    iniciar_contexto(request_id="algo-que-deveria-sumir")
    iniciar_contexto()
    assert obter_contexto() == {}


def test_iniciar_contexto_substitui_tudo():
    iniciar_contexto(request_id="abc", metodo="GET")
    assert obter_contexto() == {"request_id": "abc", "metodo": "GET"}
    iniciar_contexto(request_id="xyz")
    # iniciar_contexto de novo APAGA o que tinha antes -- só o middleware
    # deveria chamar isto, uma vez por requisição.
    assert obter_contexto() == {"request_id": "xyz"}


def test_adicionar_contexto_mescla_sem_apagar_o_que_ja_existia():
    iniciar_contexto(request_id="abc")
    adicionar_contexto(empresa_id="empresa-1")
    assert obter_contexto() == {"request_id": "abc", "empresa_id": "empresa-1"}
    adicionar_contexto(usuario_id="user-1")
    assert obter_contexto() == {"request_id": "abc", "empresa_id": "empresa-1", "usuario_id": "user-1"}


def test_adicionar_contexto_ignora_valores_none():
    iniciar_contexto(request_id="abc")
    adicionar_contexto(empresa_id=None)
    assert "empresa_id" not in obter_contexto()


def test_adicionar_contexto_sobrescreve_campo_existente():
    iniciar_contexto(papel="admin")
    adicionar_contexto(papel="analista")
    assert obter_contexto()["papel"] == "analista"


def test_obter_contexto_devolve_copia_nao_a_referencia_interna():
    iniciar_contexto(request_id="abc")
    copia = obter_contexto()
    copia["request_id"] = "adulterado"
    assert obter_contexto()["request_id"] == "abc"


async def test_contexto_isolado_entre_tasks_concorrentes():
    """
    O motivo de usar contextvars em vez de uma variável de módulo comum:
    duas "requisições" concorrentes (aqui, duas asyncio.Task) nunca devem
    vazar contexto uma para a outra, mesmo intercalando await na mesma
    thread do event loop -- ver ARQUITETURA_OBSERVABILIDADE.md §1.3.
    """
    resultados = {}

    async def _requisicao_simulada(nome: str, atraso: float):
        iniciar_contexto(request_id=nome)
        await asyncio.sleep(atraso)
        adicionar_contexto(empresa_id=f"empresa-{nome}")
        await asyncio.sleep(atraso)
        resultados[nome] = obter_contexto()

    await asyncio.gather(
        _requisicao_simulada("req-a", 0.01),
        _requisicao_simulada("req-b", 0.02),
    )

    assert resultados["req-a"] == {"request_id": "req-a", "empresa_id": "empresa-req-a"}
    assert resultados["req-b"] == {"request_id": "req-b", "empresa_id": "empresa-req-b"}
