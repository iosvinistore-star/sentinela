# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Testes de rota para /api/v1/auth/esqueci-senha e /redefinir-senha -- o
fluxo completo com token real já é coberto em
tests/integration/test_redefinicao_senha.py; aqui só o contrato HTTP."""
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_esqueci_senha_sempre_200_email_existindo_ou_nao(client, usuario_de_teste):
    with patch("sentinela.services.redefinicao_senha.enviar_email", return_value=True):
        resp_existe = await client.post(
            "/api/v1/auth/esqueci-senha", json={"email": usuario_de_teste["email"]},
            headers={"X-Sentinela-CSRF": "1"},
        )
        resp_nao_existe = await client.post(
            "/api/v1/auth/esqueci-senha", json={"email": "ninguem-tem-esse-email@example.com"},
            headers={"X-Sentinela-CSRF": "1"},
        )
    assert resp_existe.status_code == 200
    assert resp_nao_existe.status_code == 200


@pytest.mark.asyncio
async def test_redefinir_com_token_invalido_e_400(client):
    resp = await client.post(
        "/api/v1/auth/redefinir-senha", json={"token": "invalido", "senha_nova": "nova-senha-123"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_redefinir_com_senha_curta_e_422_sem_ecoar_senha_ou_token(client):
    """Item 16 do plano de endurecimento -- mesma checagem de
    tests/api/test_usuarios_api.py:test_trocar_senha_curta_demais_e_422_sem_ecoar_a_senha_na_resposta,
    para o outro endpoint que recebe uma senha nova (ver
    main.py:_erro_de_validacao)."""
    resp = await client.post(
        "/api/v1/auth/redefinir-senha",
        json={"token": "token-de-teste-qualquer", "senha_nova": "curta"},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 422
    assert "token-de-teste-qualquer" not in resp.text

    detalhe = resp.json()["detail"]
    erro_senha = next(e for e in detalhe if e["loc"][-1] == "senha_nova")
    assert erro_senha["input"] == "***REDACTED***"


@pytest.mark.asyncio
async def test_esqueci_senha_sem_csrf_e_recusado(client, usuario_de_teste):
    """O cliente React sempre manda este header em toda mutação (ver
    frontend-react/src/api/client.ts) -- alguém batendo direto na API sem
    ele deve ser recusado, igual qualquer outra rota mutável."""
    resp = await client.post("/api/v1/auth/esqueci-senha", json={"email": usuario_de_teste["email"]})
    assert resp.status_code == 403
