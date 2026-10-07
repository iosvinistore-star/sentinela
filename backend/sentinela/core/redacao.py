# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Mascaramento de segredos -- item 16 do plano de endurecimento
pós-auditoria: "Authorization, Cookie, JWT, senha, token, refresh_token,
reset_token, chaves de API e credenciais SMTP nunca aparecem em logs,
auditoria ou saída de exceção".

Quatro pontos de uso (ver cada um para o porquê especificamente daquele
lugar):
  - services/auditoria.py:registrar_evento -- `detalhes` é um dict de uso
    livre, escrito por várias funções de services/*.py; mascarar aqui, no
    único ponto de entrada da tabela `auditoria`, protege contra qualquer
    chamador futuro que acidentalmente inclua um campo sensível, sem
    precisar confiar que cada chamador individual lembre de fazer isso.
  - core/firewall.py:_registrar/_registrar_auditoria -- mesma lógica, para
    os arquivos de log/auditoria em texto do módulo de firewall.
  - main.py -- dois exception handlers: `RequestValidationError` (o
    handler PADRÃO do FastAPI ecoa o valor bruto enviado em cada erro de
    validação -- ver o comentário longo no handler) e o handler genérico
    de `ValueError` (defesa em profundidade, caso uma mensagem de erro
    futura acabe interpolando algo sensível).
  - core/logging_config.py:FormatadorJSON/FormatadorTexto (Fase E / E2,
    ver ARQUITETURA_OBSERVABILIDADE.md §1.6) -- toda linha de log da
    aplicação passa por aqui antes de virar JSON/texto: a `message` por
    `mascarar_texto`, o contexto de correlação e qualquer `extra={...}`
    de uma chamada de log por `mascarar_dados`.
"""
import re

# Nomes de campo (comparados em minúsculas, "-" normalizado para "_") cujo
# VALOR nunca deve ir para log/auditoria/resposta de erro, não importa de
# onde vieram (corpo de requisição, header, dict de auditoria).
CAMPOS_SENSIVEIS = {
    "authorization", "cookie", "set_cookie", "x_sentinela_csrf",
    "senha", "senha_atual", "senha_nova", "password", "nova_senha",
    "token", "jwt", "refresh_token", "reset_token", "token_hash",
    "api_key", "apikey", "abuseipdb_api_key", "vt_api_key",
    "smtp_password", "smtp_user", "senha_hash", "dashboard_senha",
}

MASCARA = "***REDACTED***"

# Bearer tokens / JWTs soltos dentro de texto livre (ex.: uma mensagem de
# erro ou log que por acidente interpola um header inteiro em vez de só o
# valor de um campo já coberto por CAMPOS_SENSIVEIS acima).
_PADRAO_BEARER = re.compile(r"Bearer\s+[A-Za-z0-9\-_.=]+", re.IGNORECASE)
_PADRAO_JWT = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


def campo_sensivel(nome) -> bool:
    """Público -- reusado fora deste módulo por main.py (handler de
    RequestValidationError, ver comentário lá) para decidir se o "input"
    ecoado de um erro de validação deve ser mascarado."""
    return isinstance(nome, str) and nome.strip().lower().replace("-", "_") in CAMPOS_SENSIVEIS


def mascarar_texto(texto: str) -> str:
    """Substitui qualquer Bearer token / JWT reconhecível dentro de uma
    string livre -- não sabe "de quem" é o texto, só reconhece o FORMATO."""
    if not texto:
        return texto
    texto = _PADRAO_BEARER.sub(f"Bearer {MASCARA}", texto)
    texto = _PADRAO_JWT.sub(MASCARA, texto)
    return texto


def mascarar_dados(dados):
    """
    Percorre recursivamente dicts/listas: o VALOR de qualquer chave em
    CAMPOS_SENSIVEIS (comparação case-insensitive) vira `MASCARA`
    incondicionalmente (mesmo que o valor original não fosse string --
    ex.: um número, ou um dict aninhado inteiro); toda outra string
    restante ainda passa por `mascarar_texto` (cobre um token solto dentro
    do valor de uma chave "genérica", ex.: "detalhe": "Bearer eyJ...").
    Tipos que não são dict/list/str (int, bool, None, etc.) atravessam
    sem modificação.
    """
    if isinstance(dados, dict):
        return {
            chave: MASCARA if campo_sensivel(chave) else mascarar_dados(valor)
            for chave, valor in dados.items()
        }
    if isinstance(dados, list):
        return [mascarar_dados(item) for item in dados]
    if isinstance(dados, str):
        return mascarar_texto(dados)
    return dados
