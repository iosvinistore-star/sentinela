# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testes de integração para db/limitadores_compartilhados.py -- a versão dos
limitadores de abuso (login/troca de senha, volume de upload) que
compartilha o contador entre réplicas via Postgres (ver
migrations/0015_rate_limiting_compartilhado.sql e o item 4 das "Limitações
conhecidas" do README, que esta dupla de classes resolve).

O cenário central que estes testes provam -- e que a suíte antiga
(tests/unit/test_rate_limit.py, tests/unit/test_limites_upload.py) não
conseguia provar, por rodar contra um dict em memória de UM objeto Python
só -- é que DUAS instâncias distintas das classes, ambas apontando para o
MESMO pool, enxergam o MESMO contador. É exatamente essa propriedade que
faltava na versão em memória (cada réplica/worker tinha seu próprio dict).
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from sentinela.core.limites_upload import LimiteUploadExcedidoError
from sentinela.db.limitadores_compartilhados import (
    LimitadorTentativasCompartilhado,
    LimitadorUploadsCompartilhado,
)

pytestmark = pytest.mark.integration


def _chave_unica(prefixo="teste"):
    # uuid4 por teste -- evita qualquer colisão com linhas deixadas por
    # outros testes na mesma tabela compartilhada (não há fixture de
    # limpeza por-teste aqui, ao contrário de `empresa_factory`).
    return f"{prefixo}:{uuid.uuid4()}"


# ---------------------------------------------------------------------------
# LimitadorTentativasCompartilhado (login / troca de senha)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_registrar_falha_bloqueia_apos_max_tentativas(pool):
    chave = _chave_unica("login")
    limitador = LimitadorTentativasCompartilhado(pool, max_tentativas=3, janela_segundos=300, bloqueio_segundos=60)

    for _ in range(2):
        assert await limitador.registrar_falha(chave) == 0.0

    assert await limitador.registrar_falha(chave) == 60.0
    assert await limitador.tempo_restante_bloqueio(chave) > 0


@pytest.mark.asyncio
async def test_registrar_sucesso_limpa_bloqueio(pool):
    chave = _chave_unica("login")
    limitador = LimitadorTentativasCompartilhado(pool, max_tentativas=1, janela_segundos=300, bloqueio_segundos=60)

    await limitador.registrar_falha(chave)
    assert await limitador.tempo_restante_bloqueio(chave) > 0

    await limitador.registrar_sucesso(chave)
    assert await limitador.tempo_restante_bloqueio(chave) == 0.0


@pytest.mark.asyncio
async def test_contador_compartilhado_entre_duas_instancias(pool):
    """O cenário que motivou a migração: duas réplicas do processo (aqui,
    dois objetos Python distintos, nunca o mesmo) compartilhando o MESMO
    contador via Postgres -- ao contrário do LimitadorTentativas original,
    onde cada instância tinha seu próprio dict em memória e nunca veria as
    falhas registradas pela outra."""
    chave = _chave_unica("login")
    replica_1 = LimitadorTentativasCompartilhado(pool, max_tentativas=3, janela_segundos=300, bloqueio_segundos=60)
    replica_2 = LimitadorTentativasCompartilhado(pool, max_tentativas=3, janela_segundos=300, bloqueio_segundos=60)

    await replica_1.registrar_falha(chave)
    await replica_2.registrar_falha(chave)
    # A 3a falha, registrada pela réplica_1, já precisa enxergar as 2
    # falhas anteriores -- uma vinda de si mesma, outra da réplica_2.
    restante = await replica_1.registrar_falha(chave)

    assert restante == 60.0
    assert await replica_2.tempo_restante_bloqueio(chave) > 0  # réplica_2 também vê o bloqueio


@pytest.mark.asyncio
async def test_janela_expirada_reseta_contador_em_vez_de_acumular(pool):
    chave = _chave_unica("login")
    estado = {"agora": datetime(2026, 1, 1, tzinfo=timezone.utc)}
    limitador = LimitadorTentativasCompartilhado(
        pool, max_tentativas=2, janela_segundos=60, bloqueio_segundos=30, agora=lambda: estado["agora"],
    )

    await limitador.registrar_falha(chave)
    estado["agora"] += timedelta(seconds=61)  # janela de 60s expirou
    restante = await limitador.registrar_falha(chave)

    assert restante == 0.0  # reiniciou a janela -- não acumulou com a falha antiga (senão bloquearia aqui)


# ---------------------------------------------------------------------------
# reservar_tentativa -- correção da revisão crítica de 2026-09 (achado 1):
# TOCTOU entre tempo_restante_bloqueio (leitura) e registrar_falha (escrita,
# só depois de bcrypt) permitia que N requisições concorrentes para a MESMA
# chave todas lessem "não bloqueado" antes de qualquer uma commitar a falha.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reservar_tentativa_preserva_comportamento_sequencial_do_par_antigo(pool):
    """Mesmo comportamento observável de tempo_restante_bloqueio+registrar_falha
    em uso sequencial: a tentativa que ATINGE max_tentativas ainda é permitida
    (0.0) -- só a tentativa SEGUINTE vê o bloqueio. Isto é o que
    test_heartbeat_com_token_invalido_repetido_e_rate_limitado_com_429 (em
    tests/api ou tests/unit, ver auth/dependencies.py) já depende."""
    chave = _chave_unica("reserva")
    limitador = LimitadorTentativasCompartilhado(pool, max_tentativas=3, janela_segundos=300, bloqueio_segundos=60)

    assert await limitador.reservar_tentativa(chave) == 0.0
    assert await limitador.reservar_tentativa(chave) == 0.0
    # 3a chamada cruza max_tentativas=3 -- ainda permitida (0.0), mas já
    # grava o bloqueio para a PRÓXIMA chamada ver.
    assert await limitador.reservar_tentativa(chave) == 0.0

    restante = await limitador.reservar_tentativa(chave)
    # Ao contrário de registrar_falha (que devolve a constante
    # self._bloqueio_segundos), reservar_tentativa computa o restante real a
    # partir de bloqueado_ate - agora (mesma conta de tempo_restante_bloqueio)
    # -- por isso é ligeiramente menor que 60.0, nunca maior.
    assert 59.0 < restante <= 60.0
    assert await limitador.tempo_restante_bloqueio(chave) > 0


@pytest.mark.asyncio
async def test_reservar_tentativa_ja_bloqueado_rejeita_sem_incrementar(pool):
    chave = _chave_unica("reserva")
    limitador = LimitadorTentativasCompartilhado(pool, max_tentativas=1, janela_segundos=300, bloqueio_segundos=60)

    assert await limitador.reservar_tentativa(chave) == 0.0  # cruza max_tentativas=1
    restante_1 = await limitador.reservar_tentativa(chave)
    restante_2 = await limitador.reservar_tentativa(chave)
    assert restante_1 > 0
    assert restante_2 > 0


@pytest.mark.asyncio
async def test_reservar_tentativa_fecha_a_corrida_de_concorrencia(pool):
    """Repro direto do achado 1 da revisão crítica: 30 'tentativas de login'
    concorrentes para a MESMA chave, cada uma simulando uma tentativa de auth
    lenta (bcrypt) entre a reserva e o resultado. Com o par antigo
    (tempo_restante_bloqueio + registrar_falha só no fim), TODAS as 30
    passavam pela checagem antes de qualquer uma commitar uma falha --
    nenhuma era bloqueada, apesar de max_tentativas=5. Com reservar_tentativa,
    a reserva em si é o UPSERT atômico: no máximo `max_tentativas` reservas
    conseguem passar (restante == 0.0) antes do bloqueio ficar visível para
    as demais."""
    chave = _chave_unica("concorrencia")
    max_tentativas = 5
    limitador = LimitadorTentativasCompartilhado(
        pool, max_tentativas=max_tentativas, janela_segundos=300, bloqueio_segundos=60,
    )

    async def tentativa_de_login():
        restante = await limitador.reservar_tentativa(chave)
        if restante > 0:
            return "bloqueado"
        # Simula o tempo de um bcrypt.checkpw() real -- é exatamente esta
        # janela, entre a reserva/checagem e o resultado da auth, que
        # permitia a corrida com o par tempo_restante_bloqueio+registrar_falha.
        await asyncio.sleep(0.05)
        return "tentou"

    resultados = await asyncio.gather(*[tentativa_de_login() for _ in range(30)])

    tentou = resultados.count("tentou")
    bloqueado = resultados.count("bloqueado")
    assert tentou + bloqueado == 30
    # Nunca mais do que max_tentativas passam -- é exatamente esta invariante
    # que o bug quebrava (todas as 30 passavam).
    assert tentou <= max_tentativas
    assert bloqueado >= 30 - max_tentativas
    # A chave precisa terminar bloqueada (senão o teste não provaria nada).
    assert await limitador.tempo_restante_bloqueio(chave) > 0


# ---------------------------------------------------------------------------
# LimitadorUploadsCompartilhado (volume por usuário/empresa)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reservar_volume_bloqueia_acima_do_teto_por_usuario(pool):
    usuario_id, empresa_id = str(uuid.uuid4()), str(uuid.uuid4())
    limitador = LimitadorUploadsCompartilhado(pool, teto_bytes_por_usuario=100, teto_bytes_por_empresa=10_000)

    await limitador.reservar_volume(usuario_id, empresa_id, 60)
    with pytest.raises(LimiteUploadExcedidoError) as exc:
        await limitador.reservar_volume(usuario_id, empresa_id, 60)
    assert exc.value.motivo == "volume_usuario"


@pytest.mark.asyncio
async def test_reservar_volume_bloqueia_acima_do_teto_por_empresa_mesmo_com_usuarios_diferentes(pool):
    empresa_id = str(uuid.uuid4())
    limitador = LimitadorUploadsCompartilhado(pool, teto_bytes_por_usuario=10_000, teto_bytes_por_empresa=100)

    await limitador.reservar_volume(str(uuid.uuid4()), empresa_id, 60)
    with pytest.raises(LimiteUploadExcedidoError) as exc:
        await limitador.reservar_volume(str(uuid.uuid4()), empresa_id, 60)
    assert exc.value.motivo == "volume_empresa"


@pytest.mark.asyncio
async def test_reservar_volume_nao_afeta_outro_usuario_ou_empresa(pool):
    limitador = LimitadorUploadsCompartilhado(pool, teto_bytes_por_usuario=100, teto_bytes_por_empresa=100)
    usuario_a, empresa_a = str(uuid.uuid4()), str(uuid.uuid4())
    usuario_b, empresa_b = str(uuid.uuid4()), str(uuid.uuid4())

    await limitador.reservar_volume(usuario_a, empresa_a, 90)
    # usuário/empresa completamente diferentes -- não deve herdar o consumo de A.
    await limitador.reservar_volume(usuario_b, empresa_b, 90)


@pytest.mark.asyncio
async def test_reservar_volume_compartilhado_entre_duas_instancias(pool):
    """Mesma propriedade central do limitador de tentativas: duas réplicas
    apontando para o mesmo pool compartilham a mesma cota."""
    usuario_id, empresa_id = str(uuid.uuid4()), str(uuid.uuid4())
    replica_1 = LimitadorUploadsCompartilhado(pool, teto_bytes_por_usuario=100, teto_bytes_por_empresa=10_000)
    replica_2 = LimitadorUploadsCompartilhado(pool, teto_bytes_por_usuario=100, teto_bytes_por_empresa=10_000)

    await replica_1.reservar_volume(usuario_id, empresa_id, 60)
    with pytest.raises(LimiteUploadExcedidoError):
        await replica_2.reservar_volume(usuario_id, empresa_id, 60)


@pytest.mark.asyncio
async def test_reservar_volume_janela_expirada_libera_cota_novamente(pool):
    usuario_id, empresa_id = str(uuid.uuid4()), str(uuid.uuid4())
    estado = {"agora": datetime(2026, 1, 1, tzinfo=timezone.utc)}
    limitador = LimitadorUploadsCompartilhado(
        pool, teto_bytes_por_usuario=100, teto_bytes_por_empresa=10_000,
        janela_usuario_segundos=3600, agora=lambda: estado["agora"],
    )

    await limitador.reservar_volume(usuario_id, empresa_id, 90)
    estado["agora"] += timedelta(seconds=3601)  # janela de 1h expirou
    await limitador.reservar_volume(usuario_id, empresa_id, 90)  # não deveria mais contar o consumo antigo


@pytest.mark.asyncio
async def test_processamento_e_concorrencia_continuam_em_memoria_por_replica(pool):
    """`processamento()` (concorrência) é a única parte que continua
    deliberadamente em memória/por-processo -- ver docstring da classe.
    Duas instâncias distintas (réplicas diferentes) NÃO compartilham este
    semáforo, ao contrário das cotas de volume acima."""
    replica_1 = LimitadorUploadsCompartilhado(pool, max_concorrentes=1)
    replica_2 = LimitadorUploadsCompartilhado(pool, max_concorrentes=1)

    async with replica_1.processamento():
        # Mesma réplica, semáforo já ocupado -- deveria recusar.
        with pytest.raises(LimiteUploadExcedidoError):
            async with replica_1.processamento():
                pass
        # Réplica DIFERENTE, semáforo próprio -- não sabe do outro processo.
        async with replica_2.processamento():
            pass
