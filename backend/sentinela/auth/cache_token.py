# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Cache de verificações de token bem-sucedidas (agente e licença).

Problema: o heartbeat de TODO agente verifica o token com bcrypt (~0,3 s de CPU de propósito). Com o intervalo
padrão de 30 s isso limita um servidor de 4 CPUs a poucas centenas de agentes -- e, passando disso, a fila de
verificações estoura o backstop por IP e a frota inteira atrás do mesmo NAT leva 429.

Solução: lembrar que "este token já foi verificado contra ESTE hash". Quem consulta continua indo ao banco a cada
requisição (lookup por prefixo, barato e indexado) e compara o `token_hash` que está lá agora com o que foi
verificado antes:

* token REVOGADO: a linha não é mais encontrada (o lookup filtra `status = 'ativo'`) -> recusado na hora, sem esperar
  nenhum TTL;
* token REEMITIDO/trocado: o hash no banco mudou -> o cache não vale e o bcrypt roda de novo;
* token ERRADO ou inexistente: nunca é cacheado (só sucesso entra) e segue pelo caminho completo, com o bcrypt contra
  o hash real ou o dummy, preservando o tempo uniforme e os limitadores.

A chave do cache é o SHA-256 do token (o token em si nunca fica em memória) e o valor é o hash bcrypt já verificado.
O cache é por processo, limitado (LRU) e com validade máxima; `SENTINELA_TOKEN_CACHE_ENTRADAS=0` o desliga.
"""
import asyncio
import hashlib
import time
from collections import OrderedDict

from sentinela.auth.security import hash_token_e_rapido, verificar_hash_token, verificar_senha
from sentinela.core.segredos import obter_segredo


class CacheVerificacaoToken:
    def __init__(self, max_entradas: int = 20_000, ttl_segundos: float = 3600, relogio=time.monotonic):
        self._max = max_entradas
        self._ttl = ttl_segundos
        self._relogio = relogio
        self._entradas: OrderedDict[str, tuple[str, float]] = OrderedDict()
        self.acertos = 0
        self.erros = 0

    @staticmethod
    def _chave(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    async def verificar(self, token: str, token_hash: str) -> bool:
        """
        True se `token` confere com `token_hash` (do banco, AGORA).

        Hashes `sha256$` (tokens novos) são verificados direto, em microssegundos. O cache só importa para
        os hashes bcrypt LEGADOS (tokens emitidos antes), e só sucessos são lembrados.
        """
        if hash_token_e_rapido(token_hash):
            return verificar_hash_token(token, token_hash)
        if self._max <= 0:
            return await asyncio.to_thread(verificar_senha, token, token_hash)
        chave = self._chave(token)
        agora = self._relogio()
        entrada = self._entradas.get(chave)
        if entrada is not None:
            hash_verificado, expira_em = entrada
            if hash_verificado == token_hash and expira_em > agora:
                self._entradas.move_to_end(chave)
                self.acertos += 1
                return True
            del self._entradas[chave]
        self.erros += 1
        ok = await asyncio.to_thread(verificar_senha, token, token_hash)
        if ok:
            self._entradas[chave] = (token_hash, agora + self._ttl)
            while len(self._entradas) > self._max:
                self._entradas.popitem(last=False)
        return ok

    def limpar(self) -> None:
        self._entradas.clear()


def _inteiro_do_ambiente(nome: str, padrao: int) -> int:
    try:
        return int(obter_segredo(nome, str(padrao)))
    except (TypeError, ValueError):
        return padrao


# Instância única do processo, compartilhada por agente e licença (a chave é o hash do token inteiro).
cache_tokens = CacheVerificacaoToken(
    max_entradas=_inteiro_do_ambiente("SENTINELA_TOKEN_CACHE_ENTRADAS", 20_000),
    ttl_segundos=_inteiro_do_ambiente("SENTINELA_TOKEN_CACHE_TTL_SEGUNDOS", 3600),
)
