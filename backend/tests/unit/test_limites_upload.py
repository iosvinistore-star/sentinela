# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Testes do limitador de upload de log (core/limites_upload.py) -- mesmo
padrão de relógio falso injetável de tests/unit/test_rate_limit.py, pra
rodar instantâneo e determinístico (sem esperar janelas de verdade)."""
import asyncio

import pytest

from sentinela.core.limites_upload import LimitadorUploads, LimiteUploadExcedidoError, mensagem_amigavel


class _RelogioFalso:
    def __init__(self):
        self.agora = 0.0

    def __call__(self):
        return self.agora

    def avancar(self, segundos):
        self.agora += segundos


async def test_reservar_volume_dentro_do_teto_nao_levanta():
    limitador = LimitadorUploads(teto_bytes_por_usuario=1000, teto_bytes_por_empresa=10_000)
    await limitador.reservar_volume("usuario-1", "empresa-1", 500)
    await limitador.reservar_volume("usuario-1", "empresa-1", 400)  # 900 <= 1000, ok


async def test_reservar_volume_estoura_teto_por_usuario():
    limitador = LimitadorUploads(teto_bytes_por_usuario=1000, teto_bytes_por_empresa=1_000_000)
    await limitador.reservar_volume("usuario-1", "empresa-1", 900)
    with pytest.raises(LimiteUploadExcedidoError) as exc_info:
        await limitador.reservar_volume("usuario-1", "empresa-1", 200)  # 900+200 > 1000
    assert exc_info.value.motivo == "volume_usuario"


async def test_reservar_volume_estoura_teto_por_empresa_mesmo_com_usuarios_diferentes():
    """O teto por empresa soma TODOS os usuários da mesma empresa -- um
    ataque coordenado (ou só vários usuários legítimos) não escapa do
    limite trocando de usuário."""
    limitador = LimitadorUploads(teto_bytes_por_usuario=1_000_000, teto_bytes_por_empresa=1000)
    await limitador.reservar_volume("usuario-1", "empresa-1", 600)
    await limitador.reservar_volume("usuario-2", "empresa-1", 300)  # 900 <= 1000, ok
    with pytest.raises(LimiteUploadExcedidoError) as exc_info:
        await limitador.reservar_volume("usuario-3", "empresa-1", 200)  # 900+200 > 1000
    assert exc_info.value.motivo == "volume_empresa"


async def test_chamada_que_estoura_teto_nao_registra_consumo_parcial():
    """Uma reserva rejeitada não deve "gastar" nada da cota -- só o que
    passou é contado."""
    limitador = LimitadorUploads(teto_bytes_por_usuario=1000, teto_bytes_por_empresa=1_000_000)
    with pytest.raises(LimiteUploadExcedidoError):
        await limitador.reservar_volume("usuario-1", "empresa-1", 5000)
    # Ainda dá pra reservar até o teto inteiro -- a tentativa recusada não deixou resíduo.
    await limitador.reservar_volume("usuario-1", "empresa-1", 1000)


async def test_volume_fora_da_janela_de_tempo_nao_se_acumula():
    relogio = _RelogioFalso()
    limitador = LimitadorUploads(
        teto_bytes_por_usuario=1000, janela_usuario_segundos=3600,
        teto_bytes_por_empresa=1_000_000, agora=relogio,
    )
    await limitador.reservar_volume("usuario-1", "empresa-1", 900)
    relogio.avancar(3601)  # fora da janela -- os 900 bytes "expiram"
    await limitador.reservar_volume("usuario-1", "empresa-1", 900)  # não estoura de novo


async def test_usuarios_e_empresas_diferentes_sao_independentes():
    limitador = LimitadorUploads(teto_bytes_por_usuario=1000, teto_bytes_por_empresa=1000)
    await limitador.reservar_volume("usuario-1", "empresa-1", 900)
    # outra empresa inteira, sem relação -- não deveria ser afetada.
    await limitador.reservar_volume("usuario-2", "empresa-2", 900)


async def test_concorrencia_falha_rapido_ao_atingir_o_teto():
    limitador = LimitadorUploads(max_concorrentes=2)
    entrou = []

    async def _tarefa_lenta():
        async with limitador.processamento():
            entrou.append(1)
            await asyncio.sleep(0.05)

    t1 = asyncio.create_task(_tarefa_lenta())
    t2 = asyncio.create_task(_tarefa_lenta())
    await asyncio.sleep(0.01)  # garante que t1/t2 já entraram no bloco

    with pytest.raises(LimiteUploadExcedidoError) as exc_info:
        async with limitador.processamento():
            pass  # nunca deveria chegar aqui -- já há 2 em andamento
    assert exc_info.value.motivo == "concorrencia"

    await t1
    await t2
    assert len(entrou) == 2


async def test_concorrencia_libera_o_slot_apos_terminar():
    limitador = LimitadorUploads(max_concorrentes=1)
    async with limitador.processamento():
        pass
    # o slot foi liberado ao sair do `async with` -- uma segunda chamada
    # sequencial não deveria ser recusada.
    async with limitador.processamento():
        pass


async def test_concorrencia_libera_o_slot_mesmo_se_a_tarefa_levantar():
    limitador = LimitadorUploads(max_concorrentes=1)
    with pytest.raises(ValueError):
        async with limitador.processamento():
            raise ValueError("falha simulada dentro do processamento")
    # o `finally` do context manager deveria ter liberado o slot mesmo assim.
    async with limitador.processamento():
        pass


def test_mensagem_amigavel_cobre_os_tres_motivos():
    for motivo in ("volume_usuario", "volume_empresa", "concorrencia"):
        assert mensagem_amigavel(LimiteUploadExcedidoError(motivo))


def test_mensagem_amigavel_tem_fallback_para_motivo_desconhecido():
    assert mensagem_amigavel(LimiteUploadExcedidoError("motivo_nunca_visto"))
