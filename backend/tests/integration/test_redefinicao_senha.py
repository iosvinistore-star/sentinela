# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testes do fluxo "esqueci minha senha" (services/redefinicao_senha.py) --
o envio de email em si é mockado (nenhum teste deve depender de um SMTP de
verdade), mas geração/validação de token e troca de senha rodam contra
Postgres real.
"""
import asyncio
import re
import uuid
from unittest.mock import patch

import pytest

from sentinela.auth.login import autenticar
from sentinela.auth.security import hash_senha
from sentinela.db.pool import superadmin_scoped_connection
from sentinela.services import redefinicao_senha as servico

pytestmark = pytest.mark.integration


async def _criar_usuario(pool, empresa_id, email, senha):
    usuario_id = uuid.uuid4()
    async with superadmin_scoped_connection(pool) as conn:
        await conn.execute(
            "INSERT INTO usuarios (id, empresa_id, email, papel, senha_hash) VALUES ($1, $2, $3, 'analista', $4)",
            usuario_id, empresa_id, email, hash_senha(senha),
        )
    return usuario_id


def _extrair_token(corpo_texto: str) -> str:
    m = re.search(r"token=([\w\-]+)", corpo_texto)
    assert m, f"token não encontrado no corpo do email: {corpo_texto!r}"
    return m.group(1)


@pytest.mark.asyncio
async def test_fluxo_completo_de_redefinicao_de_senha(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Redefinicao Senha")
    email = f"usuario-redefinicao-{uuid.uuid4()}@example.com"
    await _criar_usuario(pool, empresa_id, email, "senha-antiga-123")

    with patch("sentinela.services.redefinicao_senha.enviar_email") as email_mock:
        email_mock.return_value = True
        # O envio agora roda em segundo plano (ver
        # services/redefinicao_senha.py -- não bloqueia mais o caminho de
        # resposta HTTP, de propósito), então o teste precisa aguardar a
        # task devolvida explicitamente antes de checar o mock -- sem
        # isso, a asserção abaixo rodaria antes da task ter sido agendada.
        tarefa = await servico.solicitar_redefinicao(pool, email, "http://localhost:8000")
        await tarefa

    assert email_mock.call_count == 1
    destinatario, _assunto, corpo = email_mock.call_args[0]
    assert destinatario == email
    token = _extrair_token(corpo)

    ok = await servico.confirmar_redefinicao(pool, token, "senha-nova-456")
    assert ok is True

    assert await autenticar(pool, email, "senha-antiga-123") is None
    credenciais = await autenticar(pool, email, "senha-nova-456")
    assert credenciais is not None
    assert credenciais["email"] == email


@pytest.mark.asyncio
async def test_token_usado_duas_vezes_falha_na_segunda(pool, empresa_factory):
    empresa_id = await empresa_factory("Empresa Redefinicao Senha 2")
    email = f"usuario-redefinicao-2-{uuid.uuid4()}@example.com"
    await _criar_usuario(pool, empresa_id, email, "senha-antiga-123")

    with patch("sentinela.services.redefinicao_senha.enviar_email") as email_mock:
        email_mock.return_value = True
        tarefa = await servico.solicitar_redefinicao(pool, email, "http://localhost:8000")
        await tarefa
    token = _extrair_token(email_mock.call_args[0][2])

    assert await servico.confirmar_redefinicao(pool, token, "senha-nova-456") is True
    assert await servico.confirmar_redefinicao(pool, token, "outra-senha-789") is False


@pytest.mark.asyncio
async def test_token_invalido_e_recusado(pool):
    ok = await servico.confirmar_redefinicao(pool, "token-que-nunca-existiu", "senha-nova-456")
    assert ok is False


@pytest.mark.asyncio
async def test_confirmar_redefinicao_concorrente_so_uma_ganha_a_corrida(pool, empresa_factory):
    """Regressão do TOCTOU corrigido em confirmar_redefinicao: duas
    chamadas CONCORRENTES com o MESMO token só podem ter uma vencedora --
    a versão antiga (SELECT depois UPDATE, em statements separados)
    deixava as duas passarem e ambas devolverem True. Dispara as duas ao
    mesmo tempo com asyncio.gather para maximizar a chance de cair na
    janela de corrida, e confirma que só uma delas venceu."""
    empresa_id = await empresa_factory("Empresa Redefinicao Senha Corrida")
    email = f"usuario-redefinicao-corrida-{uuid.uuid4()}@example.com"
    await _criar_usuario(pool, empresa_id, email, "senha-original-123")

    with patch("sentinela.services.redefinicao_senha.enviar_email") as email_mock:
        email_mock.return_value = True
        tarefa = await servico.solicitar_redefinicao(pool, email, "http://localhost:8000")
        await tarefa
    token = _extrair_token(email_mock.call_args[0][2])

    resultados = await asyncio.gather(
        servico.confirmar_redefinicao(pool, token, "senha-nova-corrida-1"),
        servico.confirmar_redefinicao(pool, token, "senha-nova-corrida-2"),
    )
    assert sorted(resultados) == [False, True]

    # uma terceira tentativa com o mesmo token, depois que a corrida já
    # terminou, também precisa falhar -- o token continua de uso único.
    assert await servico.confirmar_redefinicao(pool, token, "senha-nova-corrida-3") is False


@pytest.mark.asyncio
async def test_email_inexistente_nao_gera_erro_nem_envia_email(pool):
    with patch("sentinela.services.redefinicao_senha.enviar_email") as email_mock:
        resultado = await servico.solicitar_redefinicao(
            pool, f"nao-existe-{uuid.uuid4()}@example.com", "http://localhost:8000",
        )
    email_mock.assert_not_called()
    # None (não uma Task) -- o chamador não tem como, só olhando o valor
    # de retorno, distinguir "email não existe" de "email existe mas o
    # envio ainda não terminou" -- ver o docstring da função.
    assert resultado is None


@pytest.mark.asyncio
async def test_solicitar_redefinicao_nao_bloqueia_no_envio_do_email(pool, empresa_factory):
    """O ponto inteiro da correção: `solicitar_redefinicao` devolve o
    controle assim que o INSERT termina, SEM esperar `enviar_email`
    rodar -- então, no instante em que a função retorna, o mock ainda não
    foi chamado (só depois que a task em segundo plano tiver a chance de
    rodar)."""
    empresa_id = await empresa_factory("Empresa Redefinicao Senha Nao Bloqueia")
    email = f"usuario-redefinicao-nb-{uuid.uuid4()}@example.com"
    await _criar_usuario(pool, empresa_id, email, "senha-antiga-123")

    with patch("sentinela.services.redefinicao_senha.enviar_email") as email_mock:
        email_mock.return_value = True
        tarefa = await servico.solicitar_redefinicao(pool, email, "http://localhost:8000")
        assert isinstance(tarefa, asyncio.Task)
        # Ainda não rodou -- a função voltou antes de o event loop ter
        # chance de agendar a task.
        assert email_mock.call_count == 0
        await tarefa
        assert email_mock.call_count == 1
