# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Testes do limitador de tentativas (auth/rate_limit.py) -- usa um relógio
falso injetável em vez de time.sleep() de verdade, pra rodar instantâneo e
determinístico."""
from sentinela.auth.rate_limit import LimitadorTentativas


class _RelogioFalso:
    def __init__(self):
        self.agora = 0.0

    def __call__(self):
        return self.agora

    def avancar(self, segundos):
        self.agora += segundos


async def test_bloqueia_apos_max_tentativas():
    relogio = _RelogioFalso()
    limitador = LimitadorTentativas(max_tentativas=3, janela_segundos=60, bloqueio_segundos=30, agora=relogio)

    assert await limitador.registrar_falha("chave") == 0
    assert await limitador.registrar_falha("chave") == 0
    restante = await limitador.registrar_falha("chave")
    assert restante > 0
    assert await limitador.tempo_restante_bloqueio("chave") > 0


async def test_bloqueio_expira_apos_o_tempo_configurado():
    relogio = _RelogioFalso()
    limitador = LimitadorTentativas(max_tentativas=2, janela_segundos=60, bloqueio_segundos=10, agora=relogio)
    await limitador.registrar_falha("chave")
    await limitador.registrar_falha("chave")
    assert await limitador.tempo_restante_bloqueio("chave") > 0

    relogio.avancar(11)
    assert await limitador.tempo_restante_bloqueio("chave") == 0


async def test_falhas_fora_da_janela_de_tempo_nao_se_acumulam():
    relogio = _RelogioFalso()
    limitador = LimitadorTentativas(max_tentativas=3, janela_segundos=10, bloqueio_segundos=30, agora=relogio)
    await limitador.registrar_falha("chave")
    relogio.avancar(11)  # fora da janela -- essa falha "expira"
    await limitador.registrar_falha("chave")
    restante = await limitador.registrar_falha("chave")
    assert restante == 0  # só 2 falhas dentro da janela atual, limite é 3


async def test_registrar_sucesso_limpa_o_historico_de_falhas():
    relogio = _RelogioFalso()
    limitador = LimitadorTentativas(max_tentativas=3, janela_segundos=60, bloqueio_segundos=30, agora=relogio)
    await limitador.registrar_falha("chave")
    await limitador.registrar_falha("chave")
    await limitador.registrar_sucesso("chave")

    await limitador.registrar_falha("chave")
    restante = await limitador.registrar_falha("chave")
    assert restante == 0  # contador zerado pelo sucesso -- só 2 falhas "novas"


async def test_chaves_diferentes_sao_independentes():
    relogio = _RelogioFalso()
    limitador = LimitadorTentativas(max_tentativas=2, janela_segundos=60, bloqueio_segundos=30, agora=relogio)
    await limitador.registrar_falha("ip-a")
    await limitador.registrar_falha("ip-a")
    assert await limitador.tempo_restante_bloqueio("ip-a") > 0
    assert await limitador.tempo_restante_bloqueio("ip-b") == 0
