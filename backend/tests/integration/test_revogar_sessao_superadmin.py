# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""scripts.revogar_sessao_superadmin -- ferramenta operacional para encerrar
imediatamente toda sessão já aberta de um superadmin (ver docstring do
script para o porquê disso não existir como fluxo de "trocar senha")."""
import pytest

from scripts.criar_superadmin import criar_superadmin
from scripts.revogar_sessao_superadmin import revogar_sessao_superadmin
from sentinela.auth.login import autenticar
from tests.sql_cru import executar

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_revogar_incrementa_token_version(db):
    from tests.integration.conftest_db import TEST_DATABASE_URL_ADMIN

    email = "revogar-teste@example.com"
    try:
        await criar_superadmin(TEST_DATABASE_URL_ADMIN, email, "senha-forte-revogar-1")
        credenciais_antes = await autenticar(db, email, "senha-forte-revogar-1")
        assert credenciais_antes["token_version"] == 1

        novo_tv = await revogar_sessao_superadmin(TEST_DATABASE_URL_ADMIN, email)
        assert novo_tv == 2

        # a senha continua a mesma -- só o token_version mudou (login
        # ainda funciona, só que agora emite um "tv" novo, que invalida
        # qualquer JWT emitido ANTES da revogação).
        credenciais_depois = await autenticar(db, email, "senha-forte-revogar-1")
        assert credenciais_depois["token_version"] == 2
    finally:
        async with db.superadmin_session() as conn:
            await executar(conn, "DELETE FROM superadmins WHERE email = $1", email)


@pytest.mark.asyncio
async def test_revogar_email_inexistente_devolve_none(db):
    from tests.integration.conftest_db import TEST_DATABASE_URL_ADMIN

    resultado = await revogar_sessao_superadmin(TEST_DATABASE_URL_ADMIN, "nao-existe-nunca@example.com")
    assert resultado is None


@pytest.mark.asyncio
async def test_revogacoes_sucessivas_incrementam_a_cada_chamada(db):
    from tests.integration.conftest_db import TEST_DATABASE_URL_ADMIN

    email = "revogar-sucessivo@example.com"
    try:
        await criar_superadmin(TEST_DATABASE_URL_ADMIN, email, "senha-forte-revogar-2")
        tv1 = await revogar_sessao_superadmin(TEST_DATABASE_URL_ADMIN, email)
        tv2 = await revogar_sessao_superadmin(TEST_DATABASE_URL_ADMIN, email)
        assert tv2 == tv1 + 1
    finally:
        async with db.superadmin_session() as conn:
            await executar(conn, "DELETE FROM superadmins WHERE email = $1", email)
