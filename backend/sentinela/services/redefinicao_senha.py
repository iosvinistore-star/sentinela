# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Fluxo de "esqueci minha senha" -- só para usuários de empresa (o mesmo
universo de auth/login.py e de TrocarSenhaRequest em api/v1/usuarios.py);
superadmin não tem essa opção nesta versão.

Token de reset: alta entropia (secrets.token_urlsafe(32) = 256 bits), só o
HASH (sha256) fica gravado no banco -- ver migrations/0009. Expira em 1h,
uso único (usado_em marcado na confirmação, uma segunda tentativa com o
mesmo token falha).

`solicitar_redefinicao` sempre se comporta do mesmo jeito (mesmo retorno)
tenha o email existido ou não -- não dá pra um chamador descobrir se um
email está cadastrado só pelo VALOR de retorno (evita enumeração de
contas). Ver o comentário dentro da função para o que isso significa (e
não significa) em termos de tempo de resposta.
"""
import asyncio
import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone

from sentinela.auth.security import hash_senha, validar_politica_senha
from sentinela.core.email import enviar_email
from sentinela.repositories.redefinicao_senha import RedefinicaoSenhaRepositorio
from sentinela.repositories.usuarios import UsuarioRepositorio

VALIDADE_HORAS = 1

logger = logging.getLogger("sentinela.redefinicao_senha")

# Referências fortes às tasks de envio de email "dispare e esqueça" (ver
# _disparar_email_em_segundo_plano) -- sem isto, o event loop só guarda uma
# referência FRACA a uma task criada com asyncio.create_task(); nada mais
# no código guarda uma referência forte a ela (o chamador não faz
# `await` nela, de propósito), então o coletor de lixo pode encerrar a
# task NO MEIO da execução, antes do SMTP terminar. Cada task se remove
# sozinha do set quando termina (add_done_callback), então isto não
# vaza memória.
_tarefas_email_em_segundo_plano: set[asyncio.Task] = set()


def _disparar_email_em_segundo_plano(coro) -> asyncio.Task:
    tarefa = asyncio.create_task(coro)
    _tarefas_email_em_segundo_plano.add(tarefa)
    tarefa.add_done_callback(_tarefas_email_em_segundo_plano.discard)
    return tarefa


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def solicitar_redefinicao(pool, email: str, url_base: str) -> asyncio.Task | None:
    """
    Devolve a `asyncio.Task` do envio de email em segundo plano (só para
    quem quiser aguardá-la explicitamente -- ver tests/integration/
    test_redefinicao_senha.py) quando o email existe, ou `None` quando não
    existe. As rotas (api/v1/auth.py, web/routes_auth.py) IGNORAM esse
    retorno de propósito -- não fazem `await` na task, só na função em si.

    Duas correções nesta função, ambas sobre o mesmo tema ("não vazar se
    um email está cadastrado"):

    1. Envio de email é SÍNCRONO (smtplib, ver core/email.py) e, antes
       desta correção, rodava com `await` direto dentro do caminho de
       requisição -- bloqueava a única thread do event loop (ver o mesmo
       problema, já corrigido, em api/v1/logs.py sobre o parsing de log)
       E, mais grave aqui, criava um canal lateral de TIMING: uma resposta
       pra um email cadastrado (SELECT + INSERT + handshake SMTP inteiro,
       às vezes segundos) demorava visivelmente mais que uma resposta pra
       um email não cadastrado (um único SELECT). Um atacante não
       precisava nem do CONTEÚDO da resposta (que já era idêntico) --
       bastava cronometrar. `asyncio.to_thread` tira o SMTP síncrono do
       event loop; disparar via `_disparar_email_em_segundo_plano` (em vez
       de `await`) tira ele do caminho de resposta -- a função devolve
       assim que o INSERT termina, o SMTP roda depois, sem afetar quando o
       chamador recebe a resposta HTTP.

    2. Mesmo com o SMTP fora do caminho de resposta, o caminho "email não
       existe" ainda fazia MENOS trabalho no Postgres (1 SELECT) que o
       caminho "email existe" (1 SELECT + 1 INSERT) -- uma diferença bem
       menor que o SMTP, mas ainda um sinal de timing mensurável em teoria.
       O SELECT extra abaixo no ramo "não existe" equaliza o número de
       round-trips ao Postgres entre os dois caminhos. Isto não é uma
       garantia de tempo constante de verdade (jitter de rede/SO, cache do
       Postgres etc. sempre vão introduzir alguma variação) -- é uma
       mitigação de defesa em profundidade, na mesma linha do resto deste
       projeto, não uma prova formal.
    """
    async with pool.superadmin_session() as sessao:
        usuario_id = await UsuarioRepositorio(sessao).obter_id_ativo_por_email(email)
        if usuario_id is None:
            logger.info("Pedido de redefinição de senha para email não cadastrado (ou inativo): %s", email)
            await sessao.fetchval("SELECT 1")
            return None

        token = secrets.token_urlsafe(32)
        expira_em = datetime.now(timezone.utc) + timedelta(hours=VALIDADE_HORAS)
        await RedefinicaoSenhaRepositorio(sessao).criar(usuario_id, _hash_token(token), expira_em)

    link = f"{url_base.rstrip('/')}/redefinir-senha?token={token}"
    return _disparar_email_em_segundo_plano(
        asyncio.to_thread(
            enviar_email,
            email,
            "Redefinição de senha -- Sentinela SOC",
            "Recebemos um pedido para redefinir sua senha no Sentinela SOC.\n\n"
            f"Clique no link abaixo para escolher uma senha nova (válido por {VALIDADE_HORAS} hora(s)):\n{link}\n\n"
            "Se você não pediu isso, ignore este email -- sua senha não será alterada.",
        )
    )


async def confirmar_redefinicao(pool, token: str, senha_nova: str) -> bool:
    """True se o token era válido (existe, não expirou, não foi usado
    ainda) e a senha foi trocada; False caso contrário.

    Levanta `ValueError` (capturado pelo handler global em main.py -> 422)
    se `senha_nova` não atender à política mínima -- checagem redundante
    com o `Field(min_length=..., max_length=...)` do schema Pydantic da
    API, mas este serviço é chamado também pela rota HTML
    (web/routes_auth.py), então validar aqui garante a regra
    independentemente de quem chama."""
    validar_politica_senha(senha_nova)
    token_hash = _hash_token(token)
    async with pool.superadmin_session() as sessao:
        repo = RedefinicaoSenhaRepositorio(sessao)
        # Atômico de propósito -- a versão antiga fazia um SELECT (checava
        # usado_em/expira_em em Python) e só DEPOIS um UPDATE separado
        # marcando usado_em: uma janela TOCTOU clássica. Duas requisições
        # concorrentes com o MESMO token válido (ex.: um atacante que
        # interceptou o link de reset correndo contra o clique real da
        # vítima) podiam ambas passar pelo SELECT antes de qualquer UPDATE
        # confirmar -- as duas prosseguiam pra trocar a senha (uma
        # sobrescrevendo a outra silenciosamente) e AMBAS recebiam `True`,
        # efetivamente permitindo usar um token de uso único mais de uma
        # vez numa corrida. Fazer a "reivindicação" do token num único
        # UPDATE ... WHERE usado_em IS NULL ... RETURNING fecha a janela:
        # o Postgres serializa updates concorrentes na mesma linha, então
        # só UMA das requisições concorrentes recebe uma linha de volta --
        # a outra recebe zero linhas (usado_em já não é mais NULL) e falha
        # aqui, antes mesmo de tocar em usuarios.senha_hash.
        usuario_id = await repo.consumir(token_hash)
        if usuario_id is None:
            return False
        # token_version + 1 -- ver migrations/0011_token_version.sql: uma
        # senha trocada via "esqueci minha senha" (o cenário mais comum é
        # justamente "perdi controle da conta") também precisa derrubar
        # qualquer sessão já aberta com a senha antiga, não só atualizar o
        # hash. Mesmo raciocínio de services/usuarios.py:trocar_propria_senha
        # -- aqui não há sessão HTTP ativa para reemitir cookie (o
        # chamador nem está autenticado), então não há nada além do UPDATE
        # a fazer.
        #
        # asyncio.to_thread: mesmo motivo do SMTP acima -- bcrypt é caro
        # em CPU de propósito, rodar direto aqui bloquearia o event loop
        # do processo pela duração do hash.
        senha_hash_nova = await asyncio.to_thread(hash_senha, senha_nova)
        await repo.trocar_senha_do_usuario(usuario_id, senha_hash_nova)
        return True
