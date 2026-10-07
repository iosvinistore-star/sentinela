# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""scripts.criar_superadmin -- bootstrap do primeiro superadmin (ovo e galinha
de uma instalação nova, sem dados legados: ver docstring do script)."""
import pytest

from scripts.criar_superadmin import criar_superadmin
from sentinela.auth.login import autenticar
from sentinela.db.pool import superadmin_scoped_connection

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_criar_superadmin_permite_login_de_verdade(pool):
    from tests.integration.conftest_db import TEST_DATABASE_URL_ADMIN

    email = "bootstrap-teste@example.com"
    try:
        criado = await criar_superadmin(TEST_DATABASE_URL_ADMIN, email, "senha-forte-bootstrap-1")
        assert criado is True

        credenciais = await autenticar(pool, email, "senha-forte-bootstrap-1")
        assert credenciais is not None
        assert credenciais["tipo"] == "superadmin"
        assert credenciais["papel"] == "superadmin"
    finally:
        async with superadmin_scoped_connection(pool) as conn:
            await conn.execute("DELETE FROM superadmins WHERE email = $1", email)


@pytest.mark.asyncio
async def test_criar_superadmin_e_idempotente_nao_duplica_nem_sobrescreve(pool):
    from tests.integration.conftest_db import TEST_DATABASE_URL_ADMIN

    email = "bootstrap-idempotente@example.com"
    try:
        primeira = await criar_superadmin(TEST_DATABASE_URL_ADMIN, email, "senha-original-123")
        segunda = await criar_superadmin(TEST_DATABASE_URL_ADMIN, email, "senha-diferente-456")
        assert primeira is True
        assert segunda is False

        # a senha da primeira chamada continua valendo -- a segunda não sobrescreveu
        credenciais = await autenticar(pool, email, "senha-original-123")
        assert credenciais is not None
        credenciais_senha_nova = await autenticar(pool, email, "senha-diferente-456")
        assert credenciais_senha_nova is None
    finally:
        async with superadmin_scoped_connection(pool) as conn:
            await conn.execute("DELETE FROM superadmins WHERE email = $1", email)
