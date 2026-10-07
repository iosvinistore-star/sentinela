# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Limitador de tentativas em memória -- mitiga força bruta de senha (no
login) e abuso do fluxo de "esqueci minha senha" (spam de email), sem
depender de um serviço externo (Redis etc.).

NÃO é mais o que a aplicação usa em produção: `app.state.limitador_login`
(ver main.py) é hoje um `db.limitadores_compartilhados.
LimitadorTentativasCompartilhado`, que resolve a limitação abaixo guardando
o contador no Postgres em vez de em memória do processo (ver
migrations/0015_rate_limiting_compartilhado.sql). Esta classe continua no
repo por ter sua própria suíte de testes unitários com relógio falso
injetável (tests/unit/test_rate_limit.py, rápida e sem precisar de um
Postgres de teste rodando) e por documentar, de forma isolada e legível, a
lógica original de janela deslizante -- mas nenhuma rota HTTP a instancia
mais diretamente.

Limitação conhecida e documentada (da versão em memória, agora resolvida na
versão compartilhada): por estar em memória do processo, numa implantação
com múltiplas réplicas atrás de um load balancer cada réplica teria seu
próprio contador -- o limite efetivo multiplicaria pelo número de réplicas.

Chave sugerida: o IP do chamador (`request.client.host`), não o email --
limitar por email abriria uma porta pra um atacante "trancar" a conta de
outra pessoa só errando a senha dela várias vezes de propósito (negação de
serviço). Limitar por IP é a mitigação padrão pra força bruta sem esse
efeito colateral.

Teto de memória: `_falhas`/`_bloqueado_ate` são `OrderedDict`s em ordem de
atividade -- um IP que erra 1-4 vezes (abaixo do limite de bloqueio) e
nunca mais volta é podado depois que sua última tentativa sai da janela,
em vez de ficar parado no dict pra sempre (um processo de longa duração
exposto à internet vê diversidade enorme de IPs -- scanners, por exemplo
-- então isso vazava memória lentamente antes desta correção). Há também
um teto duro (`max_chaves`) como segurança adicional.
"""
import asyncio
import time
from collections import OrderedDict

_MAX_CHAVES_RASTREADAS_PADRAO = 20_000


class LimitadorTentativas:
    def __init__(self, max_tentativas: int = 5, janela_segundos: float = 300,
                 bloqueio_segundos: float = 300, agora=time.monotonic,
                 max_chaves: int = _MAX_CHAVES_RASTREADAS_PADRAO):
        self._max_tentativas = max_tentativas
        self._janela_segundos = janela_segundos
        self._bloqueio_segundos = bloqueio_segundos
        self._agora = agora
        self._max_chaves = max_chaves
        # Ambos em ordem de "última atividade" -- permite podar as entradas
        # mais antigas em O(1) amortizado (olhando só o início do dict) em
        # vez de varrer a estrutura inteira a cada chamada.
        self._falhas: "OrderedDict[str, list[float]]" = OrderedDict()
        self._bloqueado_ate: "OrderedDict[str, float]" = OrderedDict()
        self._lock = asyncio.Lock()

    def _podar_sem_lock(self) -> None:
        agora = self._agora()

        # bloqueado_ate: sempre inserido/atualizado com `agora +
        # bloqueio_segundos` (constante), então a ordem de inserção já é a
        # ordem de expiração -- basta olhar o início e parar na primeira
        # entrada ainda válida.
        while self._bloqueado_ate:
            chave, ate = next(iter(self._bloqueado_ate.items()))
            if ate > agora:
                break
            del self._bloqueado_ate[chave]

        # falhas: remove quem não tem nenhuma tentativa dentro da janela E
        # não está bloqueado no momento.
        while self._falhas:
            chave, tentativas = next(iter(self._falhas.items()))
            ainda_valida = any(agora - t < self._janela_segundos for t in tentativas)
            if ainda_valida or chave in self._bloqueado_ate:
                break
            del self._falhas[chave]

        # Teto duro: se o número de chaves distintas ainda assim continuar
        # crescendo (muitos IPs únicos, todos dentro da janela ao mesmo
        # tempo), descarta as mais antigas em vez de deixar o processo
        # crescer sem limite -- prioriza as chaves mais recentes, mais
        # prováveis de ainda estarem em uso.
        while len(self._falhas) > self._max_chaves:
            self._falhas.popitem(last=False)
        while len(self._bloqueado_ate) > self._max_chaves:
            self._bloqueado_ate.popitem(last=False)

    async def tempo_restante_bloqueio(self, chave: str) -> float:
        """Quantos segundos faltam pro bloqueio acabar (0 se não está bloqueado)."""
        async with self._lock:
            return self._tempo_restante_sem_lock(chave)

    def _tempo_restante_sem_lock(self, chave: str) -> float:
        ate = self._bloqueado_ate.get(chave)
        if ate is None:
            return 0.0
        restante = ate - self._agora()
        if restante <= 0:
            del self._bloqueado_ate[chave]
            return 0.0
        return restante

    async def registrar_falha(self, chave: str) -> float:
        """Registra uma tentativa que falhou; devolve o tempo de bloqueio
        restante depois de registrar (0 se ainda não atingiu o limite)."""
        async with self._lock:
            agora = self._agora()
            tentativas = [t for t in self._falhas.get(chave, []) if agora - t < self._janela_segundos]
            tentativas.append(agora)
            if len(tentativas) >= self._max_tentativas:
                self._bloqueado_ate[chave] = agora + self._bloqueio_segundos
                self._bloqueado_ate.move_to_end(chave)
                self._falhas[chave] = []
            else:
                self._falhas[chave] = tentativas
            self._falhas.move_to_end(chave)
            resultado = self._tempo_restante_sem_lock(chave)
            self._podar_sem_lock()
            return resultado

    async def registrar_sucesso(self, chave: str) -> None:
        """Limpa o histórico de falhas -- um login bem-sucedido não deveria
        deixar o contador "quase estourando" pra próxima pessoa que usar o
        mesmo IP (rede corporativa/NAT compartilhado, por exemplo)."""
        async with self._lock:
            self._falhas.pop(chave, None)
            self._bloqueado_ate.pop(chave, None)
