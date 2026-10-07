# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Limites de abuso para upload/análise de log (POST /logs/upload,
POST /api/v1/logs/analisar), em memória -- mesma limitação conhecida de
auth/rate_limit.py:LimitadorTentativas (por estar em memória do processo,
múltiplas réplicas atrás de um load balancer teriam contadores
independentes).

NÃO é mais o que a aplicação usa para as DUAS cotas de VOLUME (por
usuário/hora, por empresa/dia) em produção: `app.state.limitador_uploads`
(ver main.py) é hoje um `db.limitadores_compartilhados.
LimitadorUploadsCompartilhado`, que guarda esses dois contadores no
Postgres (ver migrations/0015_rate_limiting_compartilhado.sql) em vez de em
memória. A classe abaixo continua sendo usada para a terceira trava
(`processamento()`, CONCORRÊNCIA) -- essa, sim, correta e propositalmente
em memória por processo, ver o item 3 do docstring original abaixo -- e
continua tendo sua própria suíte de testes unitários com relógio falso
injetável (tests/unit/test_limites_upload.py).

`MAX_LOG_UPLOAD_BYTES` (10 MB, em api/v1/logs.py e web/routes_logs.py) já
limita o tamanho de UMA requisição, mas não limita quantas vezes alguém
pode repetir isso. Este módulo fecha três lacunas que um teto por
requisição sozinho não cobre:

  1. VOLUME POR USUÁRIO numa janela de tempo -- sem isto, um único usuário
     autenticado podia enviar dezenas de arquivos de 9,9 MB em sequência
     (cada um individualmente dentro do limite) e consumir CPU/IO do
     processo inteiro sem custo algum.
  2. VOLUME POR EMPRESA (tenant) numa janela maior (diária) -- soma de
     TODOS os usuários da mesma empresa; protege contra abuso coordenado
     (vários usuários da mesma empresa, ou uma única conta comprometida
     usada em rajada) e funciona como uma cota "justa" entre clientes que
     compartilham o mesmo host.
  3. CONCORRÊNCIA -- `processar_arquivo_logs` é CPU-bound e síncrono (roda
     em `asyncio.to_thread`, ver comentário em api/v1/logs.py). A
     threadpool padrão do asyncio é compartilhada com QUALQUER outro
     `to_thread`/`run_in_executor` do processo; sem um teto de quantas
     análises de log rodam ao mesmo tempo, N uploads grandes simultâneos
     esgotam essa threadpool e famintam o resto da aplicação. Ao contrário
     dos dois limites acima (que rejeitam com 429 e o cliente tenta de
     novo mais tarde), este é sobre PROTEGER O PROCESSO, não sobre cota
     por cliente -- por isso o teto é global (compartilhado por todos os
     tenants), não por usuário/empresa.
"""
import asyncio
import contextlib
import time
from collections import OrderedDict

MAX_CHAVES_RASTREADAS_PADRAO = 5_000


class LimiteUploadExcedidoError(Exception):
    """`motivo` é uma das strings "volume_usuario" / "volume_empresa" /
    "concorrencia" -- quem chama decide a mensagem exposta ao cliente a
    partir disso (ver api/v1/logs.py e web/routes_logs.py)."""
    def __init__(self, motivo: str, janela_segundos: float = 0):
        self.motivo = motivo
        self.janela_segundos = janela_segundos


_MENSAGENS_AMIGAVEIS = {
    "volume_usuario": "Você excedeu o volume de upload de logs permitido para o seu usuário nesta janela de tempo. Tente novamente mais tarde.",
    "volume_empresa": "Sua empresa excedeu o volume diário de upload de logs permitido. Tente novamente mais tarde ou entre em contato com o suporte.",
    "concorrencia": "Muitas análises de log em andamento no momento. Tente novamente em alguns instantes.",
}


def mensagem_amigavel(exc: LimiteUploadExcedidoError) -> str:
    """Mensagem de erro em português, reutilizada pelas duas rotas de
    upload (api/v1/logs.py e web/routes_logs.py) -- mantém a mensagem
    consistente nos dois lugares sem duplicar o texto."""
    return _MENSAGENS_AMIGAVEIS.get(exc.motivo, "Limite de upload excedido. Tente novamente mais tarde.")


class LimitadorUploads:
    def __init__(
        self,
        teto_bytes_por_usuario: int = 50 * 1024 * 1024,     # 50 MB / hora / usuário
        janela_usuario_segundos: float = 3600,
        teto_bytes_por_empresa: int = 300 * 1024 * 1024,    # 300 MB / dia / empresa
        janela_empresa_segundos: float = 86400,
        max_concorrentes: int = 4,
        agora=time.monotonic,
        max_chaves: int = MAX_CHAVES_RASTREADAS_PADRAO,
    ):
        self._teto_usuario = teto_bytes_por_usuario
        self._janela_usuario = janela_usuario_segundos
        self._teto_empresa = teto_bytes_por_empresa
        self._janela_empresa = janela_empresa_segundos
        self._max_concorrentes = max_concorrentes
        self._agora = agora
        self._max_chaves = max_chaves
        # chave -> [(timestamp, bytes), ...], em ordem de última atividade
        # (mesmo truque de poda O(1) amortizado de auth/rate_limit.py).
        self._eventos_usuario: "OrderedDict[str, list[tuple[float, int]]]" = OrderedDict()
        self._eventos_empresa: "OrderedDict[str, list[tuple[float, int]]]" = OrderedDict()
        self._em_andamento = 0
        self._lock = asyncio.Lock()

    def _somar_e_podar_sem_lock(self, mapa, chave, agora, janela):
        eventos = [(t, n) for t, n in mapa.get(chave, []) if agora - t < janela]
        if eventos:
            mapa[chave] = eventos
            mapa.move_to_end(chave)
        else:
            mapa.pop(chave, None)
        return sum(n for _, n in eventos)

    def _podar_chaves_antigas_sem_lock(self):
        while len(self._eventos_usuario) > self._max_chaves:
            self._eventos_usuario.popitem(last=False)
        while len(self._eventos_empresa) > self._max_chaves:
            self._eventos_empresa.popitem(last=False)

    async def reservar_volume(self, usuario_id: str, empresa_id: str, tamanho_bytes: int) -> None:
        """
        Levanta `LimiteUploadExcedidoError` SEM registrar nada se qualquer
        um dos dois tetos (usuário/empresa) seria estourado; caso
        contrário, registra o consumo e retorna.

        Chamar DEPOIS de ler o arquivo por completo (quando `tamanho_bytes`
        já é conhecido -- ver o loop de leitura em chunks que já existe em
        api/v1/logs.py/web/routes_logs.py para o teto de 10 MB por
        requisição), mas ANTES de mandar o conteúdo para
        `processar_arquivo_logs`. Não há "devolução" de cota se o
        processamento falhar depois por outro motivo (ex.: arquivo
        corrompido) -- o custo de I/O de ler os bytes já foi pago de
        qualquer forma, então contar contra a cota está correto mesmo
        nesse caso.
        """
        async with self._lock:
            agora = self._agora()
            usados_usuario = self._somar_e_podar_sem_lock(self._eventos_usuario, usuario_id, agora, self._janela_usuario)
            if usados_usuario + tamanho_bytes > self._teto_usuario:
                raise LimiteUploadExcedidoError("volume_usuario", self._janela_usuario)
            usados_empresa = self._somar_e_podar_sem_lock(self._eventos_empresa, empresa_id, agora, self._janela_empresa)
            if usados_empresa + tamanho_bytes > self._teto_empresa:
                raise LimiteUploadExcedidoError("volume_empresa", self._janela_empresa)

            self._eventos_usuario.setdefault(usuario_id, []).append((agora, tamanho_bytes))
            self._eventos_usuario.move_to_end(usuario_id)
            self._eventos_empresa.setdefault(empresa_id, []).append((agora, tamanho_bytes))
            self._eventos_empresa.move_to_end(empresa_id)
            self._podar_chaves_antigas_sem_lock()

    @contextlib.asynccontextmanager
    async def processamento(self):
        """
        Uso: `async with limitador.processamento(): <chamada CPU-bound>`.

        Falha RÁPIDO (levanta na hora, nunca fica esperando um slot
        liberar) quando já há `max_concorrentes` análises em andamento --
        um 429 imediato é melhor do que enfileirar silenciosamente e
        arriscar o cliente (ou um proxy na frente) dar timeout esperando
        uma resposta que pode demorar minutos.
        """
        async with self._lock:
            if self._em_andamento >= self._max_concorrentes:
                raise LimiteUploadExcedidoError("concorrencia")
            self._em_andamento += 1
        try:
            yield
        finally:
            async with self._lock:
                self._em_andamento -= 1
