# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Versões dos limitadores de abuso (auth/rate_limit.py, core/limites_upload.py)
que compartilham o contador entre TODAS as réplicas/workers via Postgres, em
vez de guardá-lo em memória do processo.

Contexto (ver README, "Limitações conhecidas", item 4): com uma única
réplica (`uvicorn` sem `--workers`, um container só -- o deploy atual deste
projeto), os limitadores em memória funcionam perfeitamente. O gatilho para
esta migração é o dia em que o backend passa a rodar em mais de uma réplica
atrás de um load balancer: cada réplica passaria a ter seu PRÓPRIO contador,
e um atacante distribuindo tentativas entre réplicas (ou só tendo azar de
bater em réplicas diferentes) ganharia, na prática, um limite multiplicado
pelo número de réplicas -- para login (força bruta de senha) e troca de
senha isso é um problema de segurança real, não só de "cota injusta".

Same interface das classes antigas (`tempo_restante_bloqueio`/
`registrar_falha`/`registrar_sucesso` para tentativas; `reservar_volume`/
`processamento` para upload) -- main.py troca só QUEM é instanciado em
`app.state.limitador_login`/`app.state.limitador_uploads`, nenhuma rota
precisou mudar uma linha.

As classes antigas (`auth.rate_limit.LimitadorTentativas`,
`core.limites_upload.LimitadorUploads`) continuam no repo: têm sua própria
suíte de testes unitários (tests/unit/test_rate_limit.py,
tests/unit/test_limites_upload.py) com relógio falso injetável, e
`LimitadorUploads` continua sendo usada aqui embaixo para a ÚNICA parte que
deliberadamente NÃO virou compartilhada (ver `LimitadorUploadsCompartilhado`
abaixo).
"""
import random
from datetime import datetime, timedelta, timezone

from sentinela.core.limites_upload import LimiteUploadExcedidoError, LimitadorUploads, mensagem_amigavel  # noqa: F401
from sentinela.repositories.limites import LimiteTentativaRepositorio, LimiteUploadRepositorio

_PROBABILIDADE_LIMPEZA = 0.01  # 1 em 100 chamadas -- barato o bastante para nunca precisar de um cron dedicado.


def _agora_utc() -> datetime:
    return datetime.now(timezone.utc)


class LimitadorTentativasCompartilhado:
    """
    Substitui `auth.rate_limit.LimitadorTentativas` para login/troca de
    senha -- ver migrations/0015_rate_limiting_compartilhado.sql para a
    tabela (`limite_tentativas`, janela FIXA por chave -- ver comentário lá
    para o porquê de fixa em vez de deslizante).
    """

    def __init__(self, db, max_tentativas: int = 5, janela_segundos: float = 300,
                 bloqueio_segundos: float = 300, agora=_agora_utc):
        self._pool = db
        self._max_tentativas = max_tentativas
        self._janela_segundos = janela_segundos
        self._bloqueio_segundos = bloqueio_segundos
        self._agora = agora

    async def tempo_restante_bloqueio(self, chave: str) -> float:
        async with self._pool.superadmin_session() as sessao:
            bloqueado_ate = await LimiteTentativaRepositorio(sessao).bloqueado_ate(chave)
        if bloqueado_ate is None:
            return 0.0
        restante = (bloqueado_ate - self._agora()).total_seconds()
        return max(restante, 0.0)

    async def registrar_falha(self, chave: str) -> float:
        """
        Um único UPSERT atômico decide, na hora, se a janela atual do lado
        de fora do banco já expirou (reseta pra 1) ou incrementa -- o lock
        de linha que o `INSERT ... ON CONFLICT` já toma sozinho (mantido
        até o fim da transação, que `Database.superadmin_session` abre)
        serializa duas chamadas concorrentes para a MESMA chave sem
        precisar de um lock explícito (`SELECT ... FOR UPDATE` não serviria
        aqui -- a linha pode nem existir ainda na primeira falha desta
        chave).
        """
        agora = self._agora()
        inicio_janela_valida = agora - timedelta(seconds=self._janela_segundos)

        async with self._pool.superadmin_session() as sessao:
            repo = LimiteTentativaRepositorio(sessao)
            contador, _ = await repo.contar_tentativa(chave, agora, inicio_janela_valida)
            bloqueado_ate = None
            if contador >= self._max_tentativas:
                bloqueado_ate = agora + timedelta(seconds=self._bloqueio_segundos)
                await repo.bloquear(chave, bloqueado_ate)
            if random.random() < _PROBABILIDADE_LIMPEZA:
                await self._limpar_antigas_sem_conexao_nova(sessao, agora)

        return self._bloqueio_segundos if bloqueado_ate is not None else 0.0

    async def reservar_tentativa(self, chave: str) -> float:
        """
        Correção de bug encontrado em revisão crítica (2026-09, "revisa as
        outras partes do sistema", achado 1): `tempo_restante_bloqueio` +
        `registrar_falha` (chamado só DEPOIS de uma tentativa de auth
        completa, incluindo bcrypt) forma um TOCTOU -- N requisições
        concorrentes para a MESMA chave todas leem "não bloqueado" antes de
        qualquer uma commitar a falha que bloquearia as demais. Repro
        confirmado: 30 tentativas de login concorrentes com senha errada,
        nenhuma bloqueada, apesar de max_tentativas=5.

        Este método FECHA a reserva da tentativa (conta o uso) ANTES da
        auth rodar, reusando o mesmo UPSERT atômico de `registrar_falha` --
        o lock de linha que o `INSERT ... ON CONFLICT` toma (mantido até o
        fim da transação) agora serializa de verdade duas chamadas
        concorrentes para a mesma chave, porque a contagem acontece num
        único round-trip atômico em vez de dois (leitura + escrita)
        separados por um bcrypt lento no meio.

        Retorna os segundos restantes de bloqueio (0.0 se esta tentativa
        pode prosseguir). Comportamento sequencial preservado byte-a-byte
        com o par tempo_restante_bloqueio+registrar_falha antigo: a
        tentativa que atinge exatamente `max_tentativas` ainda é permitida
        (retorna 0.0) -- só a bloqueia PARA FUTURAS chamadas, setando
        `bloqueado_ate` já nesta transação -- e só a tentativa seguinte
        (N+1) vê o bloqueio e é rejeitada. Isto é o que
        `test_heartbeat_com_token_invalido_repetido_e_rate_limitado_com_429`
        já cobre (5 falhas sequenciais retornam 401, só a 6ª retorna 429).

        Chamadores devem substituir `tempo_restante_bloqueio` por este
        método e REMOVER a chamada a `registrar_falha` que faziam depois de
        uma tentativa mal sucedida (já contada aqui). `registrar_sucesso`
        continua igual, chamado só quando a tentativa é válida.
        """
        agora = self._agora()
        inicio_janela_valida = agora - timedelta(seconds=self._janela_segundos)

        async with self._pool.superadmin_session() as sessao:
            repo = LimiteTentativaRepositorio(sessao)
            contador, bloqueado_ate_existente = await repo.contar_tentativa(chave, agora, inicio_janela_valida)

            if bloqueado_ate_existente is not None and bloqueado_ate_existente > agora:
                # Já bloqueado por uma reserva anterior (ou pré-existente) --
                # rejeita esta tentativa antes de qualquer auth rodar, sem
                # incrementar/contar mais nada (o INSERT acima já rodou o
                # CASE de reset de janela, mas isso é inofensivo: uma chave
                # já bloqueada só é liberada quando `bloqueado_ate` expira,
                # e o próximo INSERT depois disso reseta a janela do zero
                # normalmente).
                if random.random() < _PROBABILIDADE_LIMPEZA:
                    await self._limpar_antigas_sem_conexao_nova(sessao, agora)
                return max((bloqueado_ate_existente - agora).total_seconds(), 0.0)

            if contador >= self._max_tentativas:
                # Esta reserva é a que CRUZA o limite -- ainda deixa passar
                # (retorna 0.0), mas já grava o bloqueio para que a PRÓXIMA
                # chamada (concorrente ou sequencial) veja bloqueado_ate no
                # futuro e seja rejeitada acima.
                novo_bloqueado_ate = agora + timedelta(seconds=self._bloqueio_segundos)
                await repo.bloquear(chave, novo_bloqueado_ate)

            if random.random() < _PROBABILIDADE_LIMPEZA:
                await self._limpar_antigas_sem_conexao_nova(sessao, agora)

        return 0.0

    async def devolver_tentativa(self, chave: str) -> None:
        """Desfaz UMA reserva feita por `reservar_tentativa` (tentativa legítima).

        V8.2: o backstop por IP dos agentes (`limitador_agente_ip`) reservava
        uma tentativa a cada requisição autenticada e nunca a devolvia -- ou
        seja, contava TODO tráfego, não só falhas. Com a ingestão SIEM (um lote
        a cada 250 ms por Agent), qualquer Agent coletando eventos era barrado
        com 429 em segundos, assim como qualquer frota de mais de ~20 agentes
        atrás da mesma NAT. Devolver só a PRÓPRIA reserva (em vez de apagar a
        chave, como `registrar_sucesso`) mantém a propriedade documentada em
        auth/dependencies.py: um sucesso ocasional não apaga as falhas
        acumuladas por um flood atrás do mesmo IP. Um bloqueio já ativo
        (`bloqueado_ate`) não é desfeito.
        """
        async with self._pool.superadmin_session() as sessao:
            await LimiteTentativaRepositorio(sessao).devolver(chave, self._agora())

    async def registrar_sucesso(self, chave: str) -> None:
        async with self._pool.superadmin_session() as sessao:
            await LimiteTentativaRepositorio(sessao).remover(chave)

    async def _limpar_antigas_sem_conexao_nova(self, sessao, agora):
        """
        Chamada com baixa probabilidade de dentro de `registrar_falha` --
        mesmo raciocínio do teto de memória do `LimitadorTentativas`
        original: sem isto, um processo de longa duração exposto à
        internet (scanners, IPs únicos que nunca voltam) acumularia uma
        linha por IP distinto para sempre. Só remove quem NÃO está
        bloqueado agora e cuja janela já expirou -- nunca uma linha ainda
        relevante.
        """
        limite = agora - timedelta(seconds=self._janela_segundos)
        await LimiteTentativaRepositorio(sessao).limpar_expiradas(limite)

    async def limpar_tudo_para_teste(self) -> None:
        """Só para a suíte de testes (ver tests/api/conftest_api.py) -- zera
        o estado compartilhado entre testes que reusam a mesma app/pool."""
        async with self._pool.superadmin_session() as sessao:
            await LimiteTentativaRepositorio(sessao).limpar_tudo()


class LimitadorUploadsCompartilhado:
    """
    Substitui `core.limites_upload.LimitadorUploads` para as DUAS cotas de
    volume (por usuário/hora, por empresa/dia) -- ver
    migrations/0015_rate_limiting_compartilhado.sql (`limite_upload_eventos`,
    um evento por upload aceito, somado dentro da janela a cada checagem --
    aqui SIM faz sentido janela deslizante de verdade, ao contrário do
    limitador de tentativas: a janela é muito maior (1h/24h) e a soma exata
    já está barata o bastante).

    A CONCORRÊNCIA (`processamento()`, quantas análises de log rodam ao
    mesmo tempo) continua deliberadamente em memória, delegada para um
    `LimitadorUploads` interno usado só para ISSO -- ela protege a
    threadpool deste PROCESSO especificamente (ver o docstring de
    core/limites_upload.py), então "compartilhar entre réplicas" nem faz
    sentido: cada réplica tem sua própria threadpool para proteger.
    """

    def __init__(
        self,
        db,
        teto_bytes_por_usuario: int = 50 * 1024 * 1024,
        janela_usuario_segundos: float = 3600,
        teto_bytes_por_empresa: int = 300 * 1024 * 1024,
        janela_empresa_segundos: float = 86400,
        max_concorrentes: int = 4,
        agora=_agora_utc,
    ):
        self._pool = db
        self._teto_usuario = teto_bytes_por_usuario
        self._janela_usuario = janela_usuario_segundos
        self._teto_empresa = teto_bytes_por_empresa
        self._janela_empresa = janela_empresa_segundos
        self._agora = agora
        # Só para a concorrência local -- ver docstring da classe.
        self._concorrencia = LimitadorUploads(max_concorrentes=max_concorrentes)

    def processamento(self):
        return self._concorrencia.processamento()

    async def reservar_volume(self, usuario_id: str, empresa_id: str, tamanho_bytes: int) -> None:
        chave_usuario = f"usuario:{usuario_id}"
        chave_empresa = f"empresa:{empresa_id}"
        agora = self._agora()

        async with self._pool.superadmin_session() as sessao:
            # pg_advisory_xact_lock: sem isto, duas requisições concorrentes
            # do MESMO usuário (ou da mesma empresa) fariam cada uma sua
            # própria SELECT SUM ANTES de qualquer uma commitar o INSERT --
            # sob READ COMMITTED nenhuma vê o INSERT da outra ainda não
            # commitado, e as duas passariam mesmo que a SOMA das duas
            # estourasse o teto (o mesmo problema clássico de "check then
            # act" que o `asyncio.Lock()` único do LimitadorUploads original
            # evitava, só que aquele serializava TODO upload do processo
            # inteiro, de qualquer usuário/empresa -- este lock é só para a
            # MESMA chave, liberado automaticamente no fim da transação).
            repo = LimiteUploadRepositorio(sessao)
            await repo.travar(chave_usuario)
            usados_usuario = await self._somar_janela(repo, chave_usuario, agora, self._janela_usuario)
            if usados_usuario + tamanho_bytes > self._teto_usuario:
                raise LimiteUploadExcedidoError("volume_usuario", self._janela_usuario)

            await repo.travar(chave_empresa)
            usados_empresa = await self._somar_janela(repo, chave_empresa, agora, self._janela_empresa)
            if usados_empresa + tamanho_bytes > self._teto_empresa:
                raise LimiteUploadExcedidoError("volume_empresa", self._janela_empresa)

            await repo.registrar([chave_usuario, chave_empresa], agora, tamanho_bytes)

            if random.random() < _PROBABILIDADE_LIMPEZA:
                limite_geral = agora - timedelta(seconds=max(self._janela_usuario, self._janela_empresa))
                await repo.limpar_antigos(limite_geral)

    async def _somar_janela(self, repo, chave, agora, janela_segundos) -> int:
        return await repo.somar_janela(chave, agora - timedelta(seconds=janela_segundos))

    async def limpar_tudo_para_teste(self) -> None:
        """Só para testes -- ver `LimitadorTentativasCompartilhado.limpar_tudo_para_teste`."""
        async with self._pool.superadmin_session() as sessao:
            await LimiteUploadRepositorio(sessao).limpar_tudo()
