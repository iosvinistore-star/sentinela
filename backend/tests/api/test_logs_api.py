# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
POST /api/v1/logs/analisar -- teste de regressão explícito da lacuna
consertada: antes, um upload de log no dashboard só desenhava gráficos e
nunca criava incidentes de verdade. Aqui confirmamos que o upload via API
cria incidentes reais, escopados por empresa (RLS), visíveis só para quem
enviou o log.
"""
import io

import pytest
from unittest.mock import patch

from sentinela.core import reputacao as core_reputacao
from sentinela.core.limites_upload import LimitadorUploads
from tests.api.conftest_api import logar

pytestmark = pytest.mark.integration

_LOG_ALTO_RISCO = (
    "203.0.113.60 - - [01/Sep/2026:10:00:00] "
    "\"GET /vulneravel.php?id=1' UNION SELECT null,username,password FROM users HTTP/1.1\" 200 100\n"
    "203.0.113.60 - - [01/Sep/2026:10:00:01] "
    "\"GET /vulneravel.php?id=2' UNION SELECT null,username,password FROM users HTTP/1.1\" 200 100\n"
    "203.0.113.60 - - [01/Sep/2026:10:00:02] \"GET /exec?cmd=;cat /etc/passwd HTTP/1.1\" 200 100\n"
    "203.0.113.60 - - [01/Sep/2026:10:00:03] \"GET /exec?cmd=;whoami HTTP/1.1\" 200 100\n"
    "203.0.113.60 - - [01/Sep/2026:10:00:04] \"GET /exec?cmd=;id HTTP/1.1\" 200 100\n"
)


@pytest.mark.asyncio
async def test_upload_de_log_cria_incidente_de_verdade(client, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])

    with patch.object(core_reputacao, "consultar_abuseipdb", return_value={"score_abuso": 90}), \
         patch.object(core_reputacao, "consultar_virustotal", return_value={"maliciosos": 8}):
        resp = await client.post(
            "/api/v1/logs/analisar",
            files={"arquivo": ("servidor.log", io.BytesIO(_LOG_ALTO_RISCO.encode()), "text/plain")},
            data={"limite": "1"},
            headers={"X-Sentinela-CSRF": "1"},
        )

    assert resp.status_code == 200
    corpo = resp.json()
    assert corpo["total_alertas"] == 5
    respostas = corpo["respostas_incidentes"]
    assert len(respostas) == 1
    assert respostas[0]["ip"] == "203.0.113.60"
    assert respostas[0]["incident_id"] is not None

    resp_lista = await client.get("/api/v1/incidentes")
    ips = [i["ip"] for i in resp_lista.json()["incidentes"]]
    assert "203.0.113.60" in ips


@pytest.mark.asyncio
async def test_upload_sem_header_csrf_e_recusado(client, usuario_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    resp = await client.post(
        "/api/v1/logs/analisar",
        files={"arquivo": ("servidor.log", io.BytesIO(b"linha qualquer\n"), "text/plain")},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_incidente_de_uma_empresa_nao_aparece_para_outra(client, usuario_de_teste, analista_de_teste):
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    with patch.object(core_reputacao, "consultar_abuseipdb", return_value={"score_abuso": 90}), \
         patch.object(core_reputacao, "consultar_virustotal", return_value={"maliciosos": 8}):
        await client.post(
            "/api/v1/logs/analisar",
            files={"arquivo": ("servidor.log", io.BytesIO(_LOG_ALTO_RISCO.encode()), "text/plain")},
            data={"limite": "1"},
            headers={"X-Sentinela-CSRF": "1"},
        )

    outro_client = client
    await outro_client.post("/api/v1/auth/logout", headers={"X-Sentinela-CSRF": "1"})
    await logar(outro_client, analista_de_teste["email"], analista_de_teste["senha"])

    resp_lista = await outro_client.get("/api/v1/incidentes")
    ips = [i["ip"] for i in resp_lista.json()["incidentes"]]
    assert "203.0.113.60" not in ips


@pytest.mark.asyncio
async def test_upload_alem_do_volume_permitido_e_recusado_com_429(client, app_instance, usuario_de_teste):
    """Ver core/limites_upload.py -- teto de MB/janela por usuário, além do
    teto por requisição (MAX_LOG_UPLOAD_BYTES) que os outros testes cobrem."""
    limitador_original = app_instance.state.limitador_uploads
    app_instance.state.limitador_uploads = LimitadorUploads(teto_bytes_por_usuario=1)
    try:
        await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
        resp = await client.post(
            "/api/v1/logs/analisar",
            files={"arquivo": ("servidor.log", io.BytesIO(b"linha qualquer\n"), "text/plain")},
            headers={"X-Sentinela-CSRF": "1"},
        )
        assert resp.status_code == 429
        assert "volume" in resp.json()["detail"].lower()
    finally:
        app_instance.state.limitador_uploads = limitador_original


@pytest.mark.asyncio
async def test_upload_com_concorrencia_esgotada_e_recusado_com_429(client, app_instance, usuario_de_teste):
    limitador_original = app_instance.state.limitador_uploads
    app_instance.state.limitador_uploads = LimitadorUploads(max_concorrentes=0)
    try:
        await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
        resp = await client.post(
            "/api/v1/logs/analisar",
            files={"arquivo": ("servidor.log", io.BytesIO(b"linha qualquer\n"), "text/plain")},
            headers={"X-Sentinela-CSRF": "1"},
        )
        assert resp.status_code == 429
    finally:
        app_instance.state.limitador_uploads = limitador_original


@pytest.mark.asyncio
async def test_corpo_multipart_gigantesco_e_recusado_pelo_middleware_antes_do_processamento(
    client, usuario_de_teste
):
    """
    Ponto 1 do review de hardening: um corpo multipart bem maior que
    MAX_LOG_UPLOAD_BYTES (10 MB) precisa ser cortado pelo
    LimiteTamanhoCorpoMiddleware (ver web/limite_corpo.py) ANTES de
    request.form()/UploadFile terminar de receber tudo -- não só depois,
    pelo loop de leitura em chunks dentro da rota. Este teste manda um
    arquivo de ~13 MB (acima do teto padrão de 12 MB do middleware) e
    confirma 413 -- se o corte estivesse acontecendo só dentro da rota (o
    comportamento antigo), o servidor teria que terminar de receber os 13
    MB primeiro.
    """
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    arquivo_gigante = io.BytesIO(b"x" * (13 * 1024 * 1024))
    resp = await client.post(
        "/api/v1/logs/analisar",
        files={"arquivo": ("gigante.log", arquivo_gigante, "text/plain")},
        headers={"X-Sentinela-CSRF": "1"},
    )
    assert resp.status_code == 413
