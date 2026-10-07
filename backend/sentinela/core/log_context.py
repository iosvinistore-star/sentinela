# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Contexto de correlação para logging estruturado (Fase E / E2) -- ver
ARQUITETURA_OBSERVABILIDADE.md §1.3 para o raciocínio completo.

Usa `contextvars` (não `threading.local`) porque a aplicação é assíncrona
(asyncio/FastAPI): múltiplas requisições concorrentes podem intercalar
`await`s na MESMA thread do event loop, e `threading.local` não isola
contexto por `asyncio.Task`, só por thread. `contextvars` propaga
corretamente através de `await`s DENTRO da mesma requisição (mesma Task) e
nunca vaza para outra requisição concorrente.

`web/logging_middleware.py` chama `iniciar_contexto` uma vez por
requisição, no início. Qualquer dependência de autenticação que resolva
uma identidade (`auth/dependencies.py`) chama `adicionar_contexto` para
enriquecer o contexto já existente -- nunca `iniciar_contexto` de novo no
meio de uma requisição, o que apagaria os campos já definidos pelo
middleware (`request_id`, `metodo`, `path`).
"""
from contextvars import ContextVar

_contexto: ContextVar[dict | None] = ContextVar("sentinela_log_context", default=None)


def iniciar_contexto(**campos) -> None:
    """Substitui o contexto INTEIRO da requisição atual -- só o middleware
    deve chamar isto, uma vez, no começo do `dispatch`."""
    _contexto.set(dict(campos))


def adicionar_contexto(**campos) -> None:
    """Mescla campos novos no contexto já existente da requisição atual --
    chamado pelas dependências de autenticação assim que resolvem uma
    identidade, sem apagar o que o middleware já tinha definido. Valores
    `None` são ignorados (evita sobrescrever um campo já preenchido com
    `None` só porque uma dependência não encontrou aquele dado)."""
    atual = dict(_contexto.get() or {})
    atual.update({chave: valor for chave, valor in campos.items() if valor is not None})
    _contexto.set(atual)


def obter_contexto() -> dict:
    """Devolve uma CÓPIA do contexto atual -- o chamador (o formatter de
    log) nunca deve mutar o dict devolvido diretamente."""
    return dict(_contexto.get() or {})
