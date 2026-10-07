# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Fixtures para os testes de API: cliente httpx.AsyncClient + ASGITransport
contra a app FastAPI completa, com o lifespan (criação do pool) disparado
manualmente (`app.router.lifespan_context`), já que ASGITransport não roda
eventos de lifespan sozinho.

Reusa o mesmo Postgres de teste de tests/integration/conftest_db.py — os
dois tipos de teste (integration e api) rodam contra o mesmo banco.
"""
import os
import uuid

import httpx
import pytest_asyncio

from tests.integration.conftest_db import (
    TEST_DATABASE_URL,
    TEST_DATABASE_URL_ADMIN,
)


@pytest_asyncio.fixture(scope="session")
async def app_instance(_schema_aplicado):
    """
    Importa `sentinela.main` só depois que as variáveis de ambiente que
    `config.Settings` lê já estão setadas -- se importássemos no topo do
    arquivo, `criar_app()` já teria rodado com env vars possivelmente
    ausentes.
    """
    os.environ.setdefault("DATABASE_URL", TEST_DATABASE_URL)
    os.environ.setdefault("DATABASE_URL_ADMIN", TEST_DATABASE_URL_ADMIN)
    os.environ.setdefault("JWT_SECRET", "segredo-de-teste-nao-use-em-producao")
    # Fase C (MFA/TOTP) -- chave Fernet válida fixa para toda a suíte de
    # testes (ver Settings.validar() em config.py e auth/mfa.py). Fixa (não
    # gerada por teste) para reprodutibilidade -- nenhum teste depende do
    # VALOR desta chave, só de que ela exista e seja válida.
    os.environ.setdefault("SENTINELA_MFA_ENCRYPTION_KEY", "FubcIZSMWTNTDq6fxHGe66Wooatc2PzAdSjz14ZmcQM=")
    os.environ.setdefault("ENV", "test")

    from sentinela.main import app as fastapi_app

    async with fastapi_app.router.lifespan_context(fastapi_app):
        yield fastapi_app


@pytest_asyncio.fixture
async def client(app_instance):
    transport = httpx.ASGITransport(app=app_instance)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture(autouse=True)
async def _resetar_rate_limiter_de_login(app_instance):
    """
    `app_instance` é session-scoped (recriar o pool de conexões a cada
    teste seria caro) e o `LimitadorTentativasCompartilhado` global mora em
    `app.state.limitador_login` (Postgres, ver
    db/limitadores_compartilhados.py) -- então, sem isso, ele persiste igual
    entre TODOS os testes da sessão inteira. Isso não seria problema se
    cada teste "chegasse" com um IP diferente, como aconteceria de verdade
    em produção -- mas sob `httpx.ASGITransport`, `request.client` vem
    `None`, e tanto `web/routes_auth.py` quanto `api/v1/auth.py` caem no
    fallback `"desconhecido"` como chave (ver `_ip_do_cliente`). Ou seja:
    toda a suíte de testes de API/web, rodando na mesma sessão, se vê como
    um único IP compartilhado.

    Sem este reset, um teste que erra a senha de propósito várias vezes
    (ex.: tests/api/test_rate_limit_login.py, ou os vários testes de
    "senha atual errada" espalhados pela suíte) esgota o limite de
    tentativas e bloqueia esse IP fictício por `bloqueio_segundos` (padrão:
    300s) -- tempo suficiente pra derrubar, em cascata, TODOS os testes
    seguintes da sessão que dependem de conseguir logar (a maioria).
    Foi exatamente esse o sintoma observado: a suíte passava 100% quando
    cada arquivo de teste rodava isolado, mas tinha dezenas de falhas em
    cascata (redirecionamentos 303 inesperados = "não autenticado") quando
    rodada por inteiro -- não é um bug do produto, é puramente um efeito
    colateral de testes compartilharem uma única app/IP.
    """
    await app_instance.state.limitador_login.limpar_tudo_para_teste()
    # Fase C (MFA) -- mesmo raciocínio: `limitador_mfa` também é
    # session-scoped via `app_instance`, então sem reset ele também
    # acumula falhas entre testes que testam código TOTP/recovery errado
    # de propósito (ver tests/api/test_mfa.py).
    await app_instance.state.limitador_mfa.limpar_tudo_para_teste()
    yield


@pytest_asyncio.fixture
async def usuario_de_teste(pool, empresa_factory):
    """Cria uma empresa + um usuário admin com senha conhecida, pronto para logar via /api/v1/auth/login."""
    from sentinela.auth.security import hash_senha
    from sentinela.db.pool import superadmin_scoped_connection

    empresa_id = await empresa_factory("Empresa API Teste")
    email = f"admin-{uuid.uuid4()}@example.com"
    senha = "senha-forte-123"
    usuario_id = uuid.uuid4()

    async with superadmin_scoped_connection(pool) as conn:
        await conn.execute(
            "INSERT INTO usuarios (id, empresa_id, email, papel, senha_hash) VALUES ($1, $2, $3, 'admin', $4)",
            usuario_id, empresa_id, email, hash_senha(senha),
        )

    return {"id": usuario_id, "empresa_id": empresa_id, "email": email, "senha": senha, "papel": "admin"}


@pytest_asyncio.fixture
async def analista_de_teste(pool, empresa_factory):
    from sentinela.auth.security import hash_senha
    from sentinela.db.pool import superadmin_scoped_connection

    empresa_id = await empresa_factory("Empresa API Teste Analista")
    email = f"analista-{uuid.uuid4()}@example.com"
    senha = "senha-forte-123"
    usuario_id = uuid.uuid4()

    async with superadmin_scoped_connection(pool) as conn:
        await conn.execute(
            "INSERT INTO usuarios (id, empresa_id, email, papel, senha_hash) VALUES ($1, $2, $3, 'analista', $4)",
            usuario_id, empresa_id, email, hash_senha(senha),
        )

    return {"id": usuario_id, "empresa_id": empresa_id, "email": email, "senha": senha, "papel": "analista"}


@pytest_asyncio.fixture
async def superadmin_de_teste(pool):
    from sentinela.auth.security import hash_senha
    from sentinela.db.pool import superadmin_scoped_connection

    email = f"superadmin-{uuid.uuid4()}@example.com"
    senha = "senha-forte-123"
    superadmin_id = uuid.uuid4()

    async with superadmin_scoped_connection(pool) as conn:
        await conn.execute(
            "INSERT INTO superadmins (id, email, senha_hash) VALUES ($1, $2, $3)",
            superadmin_id, email, hash_senha(senha),
        )

    yield {"id": superadmin_id, "email": email, "senha": senha}

    async with superadmin_scoped_connection(pool) as conn:
        # Fase C -- login (e outras ações administrativas) agora grava
        # eventos de auditoria referenciando este superadmin
        # (`auditoria.ator_superadmin_id`, FK sem ON DELETE CASCADE de
        # propósito -- produção nunca APAGA um superadmin de verdade, só
        # desativa, então o histórico de auditoria nunca precisa sobreviver
        # a uma exclusão real). Só este fixture de teste faz DELETE de
        # verdade (para não acumular lixo entre testes) -- sem apagar as
        # linhas de auditoria referenciando este id efêmero primeiro, o
        # DELETE abaixo violaria a FK sempre que o teste tiver feito login
        # (LOGIN_SUCCESS/LOGIN_FAILURE, ver api/v1/auth.py) ou qualquer
        # outra ação auditada com este superadmin como ator.
        await conn.execute("DELETE FROM auditoria WHERE ator_superadmin_id = $1", superadmin_id)
    async with superadmin_scoped_connection(pool) as conn:
        await conn.execute("DELETE FROM superadmins WHERE id = $1", superadmin_id)


async def logar(client: httpx.AsyncClient, email: str, senha: str) -> httpx.Response:
    return await client.post("/api/v1/auth/login", json={"email": email, "senha": senha})
