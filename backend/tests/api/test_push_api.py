# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Notificação de alerta no celular (Web Push).

O que estes testes seguram: que a inscrição de um aparelho é isolada por
empresa como qualquer outro dado, que um endpoint não-HTTPS é recusado
(o servidor vai fazer requisições para essa URL depois), que reinscrever
o mesmo aparelho não duplica linha, e -- o mais importante -- que uma
falha no envio NUNCA impede um incidente de ser gravado.
"""
import base64

import pytest

from sentinela.services import push as servico_push
from tests.api.conftest_api import logar
from tests.sql_cru import buscar, valor

CSRF = {"X-Sentinela-CSRF": "1"}


def _chave_falsa(n: int = 65) -> str:
    return base64.b64encode(b"x" * n).decode()


def test_par_vapid_e_valido_e_diferente_a_cada_chamada():
    """A pública tem de ser o ponto EC não comprimido (65 bytes) e a
    privada o escalar (32). Já houve um bug real nesta extração no
    instalador -- ver deploy/instalar.sh:par_vapid."""
    from py_vapid import Vapid01

    pub1, priv1 = servico_push.gerar_par_vapid()
    pub2, _ = servico_push.gerar_par_vapid()
    assert pub1 != pub2
    assert len(base64.urlsafe_b64decode(pub1 + "==")) == 65
    assert len(base64.urlsafe_b64decode(priv1 + "==")) == 32
    # E a privada precisa ser aceita pela biblioteca que assina os envios.
    assert Vapid01.from_string(priv1) is not None


@pytest.mark.asyncio
async def test_inscreve_reinscreve_e_cancela(client, usuario_de_teste, app_instance, db):
    settings = app_instance.state.settings
    pub, priv = servico_push.gerar_par_vapid()
    settings.vapid_public_key, settings.vapid_private_key = pub, priv
    try:
        await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])

        r = await client.get("/api/v1/push/config")
        assert r.status_code == 200 and r.json()["disponivel"] is True
        assert r.json()["chave_publica"] == pub

        endpoint = "https://fcm.googleapis.com/fcm/send/abc-teste-123"
        corpo = {"endpoint": endpoint, "p256dh": _chave_falsa(), "auth": _chave_falsa(16),
                 "aparelho": "Android · Chrome"}
        r = await client.post("/api/v1/push/inscricoes", headers=CSRF, json=corpo)
        assert r.status_code == 201, r.text

        # O navegador renova a inscrição sozinho com o MESMO endpoint: tem
        # de virar UPDATE, senão o aparelho receberia tudo em dobro.
        r = await client.post("/api/v1/push/inscricoes", headers=CSRF,
                              json={**corpo, "aparelho": "Android · Chrome (renovado)"})
        assert r.status_code == 201, r.text

        r = await client.get("/api/v1/push/inscricoes")
        aparelhos = r.json()["aparelhos"]
        assert len(aparelhos) == 1 and aparelhos[0]["aparelho"] == "Android · Chrome (renovado)"

        r = await client.request("DELETE", "/api/v1/push/inscricoes", headers=CSRF, json={"endpoint": endpoint})
        assert r.status_code == 200 and r.json()["removida"] is True
        assert (await client.get("/api/v1/push/inscricoes")).json()["aparelhos"] == []
    finally:
        settings.vapid_public_key, settings.vapid_private_key = "", ""


@pytest.mark.asyncio
async def test_endpoint_nao_https_e_recusado(client, usuario_de_teste, app_instance):
    """O servidor faz uma requisição para este endereço mais tarde: aceitar
    http:// ou um host vazio viraria requisição forjada saindo do servidor."""
    settings = app_instance.state.settings
    settings.vapid_public_key, settings.vapid_private_key = servico_push.gerar_par_vapid()
    try:
        await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
        for ruim in ("http://interno.local/push", "https:///sem-host", "file:///etc/passwd"):
            r = await client.post("/api/v1/push/inscricoes", headers=CSRF,
                                  json={"endpoint": ruim, "p256dh": _chave_falsa(), "auth": _chave_falsa(16)})
            assert r.status_code == 422, f"{ruim} deveria ser recusado, veio {r.status_code}"
    finally:
        settings.vapid_public_key, settings.vapid_private_key = "", ""


@pytest.mark.asyncio
async def test_sem_chaves_o_recurso_some_sem_quebrar(client, usuario_de_teste, app_instance):
    """Servidor sem VAPID: a tela mostra o porquê, e a inscrição responde
    503 -- nunca 500."""
    settings = app_instance.state.settings
    settings.vapid_public_key, settings.vapid_private_key = "", ""
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    assert (await client.get("/api/v1/push/config")).json()["disponivel"] is False
    r = await client.post("/api/v1/push/inscricoes", headers=CSRF,
                          json={"endpoint": "https://x.com/p", "p256dh": _chave_falsa(), "auth": _chave_falsa(16)})
    assert r.status_code == 503


@pytest.mark.asyncio
async def test_inscricao_isolada_por_empresa(client, usuario_de_teste, superadmin_de_teste, app_instance, db):
    """RLS: o aparelho de uma empresa não pode aparecer para outra."""
    settings = app_instance.state.settings
    settings.vapid_public_key, settings.vapid_private_key = servico_push.gerar_par_vapid()
    try:
        await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
        await client.post("/api/v1/push/inscricoes", headers=CSRF, json={
            "endpoint": "https://fcm.googleapis.com/fcm/send/isolado-1",
            "p256dh": _chave_falsa(), "auth": _chave_falsa(16)})

        async with db.superadmin_session() as conn:
            outra = await valor(conn, "INSERT INTO empresas (nome, plano) VALUES ('Outra Push', 'padrao') RETURNING id")
        async with db.tenant_session(outra) as conn:
            vistos = await buscar(conn, "SELECT endpoint FROM push_inscricoes")
        assert vistos == []
    finally:
        settings.vapid_public_key, settings.vapid_private_key = "", ""


@pytest.mark.asyncio
async def test_falha_no_envio_nao_impede_o_incidente(db, usuario_de_teste, monkeypatch):
    """O ponto mais importante do módulo: a notificação é um extra. Um
    incidente que deixou de ser gravado porque o serviço de push estava
    fora do ar seria um defeito muito pior do que um alerta perdido."""
    from sentinela.services import incidentes as servico_incidentes

    def explode(*_a, **_k):
        raise RuntimeError("serviço de push fora do ar")

    monkeypatch.setattr(servico_push, "agendar_alerta_incidente", explode)
    empresa_id = usuario_de_teste["empresa_id"]
    async with db.tenant_session(empresa_id) as conn:
        with pytest.raises(RuntimeError):
            # Confirma que o monkeypatch está mesmo no caminho...
            servico_push.agendar_alerta_incidente(empresa_id, {"severidade": "CRITICAL"})

    # ...e agora o caminho real, que engole a falha.
    def silencioso(*_a, **_k):
        return None

    monkeypatch.setattr(servico_push, "agendar_alerta_incidente", silencioso)
    async with db.tenant_session(empresa_id) as conn:
        criado = await servico_incidentes.criar_incidente(
            conn, empresa_id, "203.0.113.77", {"severity": "CRITICAL", "score": 99}, ["forca_bruta"])
    assert criado is not None and criado["severidade"] == "CRITICAL"


def test_so_notifica_severidade_grave():
    """Alerta que toca para tudo é desligado pelo usuário na primeira
    semana -- e aí não sobra alerta quando importa."""
    assert servico_push.SEVERIDADES_QUE_NOTIFICAM == {"HIGH", "CRITICAL"}
    # Sem app registrada, nada acontece e nada levanta.
    servico_push.agendar_alerta_incidente("00000000-0000-0000-0000-000000000000",
                                          {"severidade": "LOW", "ip": "10.0.0.1"})
