# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
POST /logs/upload (HTMX) -- a metade HTMX da correção da lacuna do
dashboard antigo (ver tests/api/test_logs_api.py para a metade React da
mesma correção).
"""
import io
from unittest.mock import patch

import pytest

from sentinela.core import reputacao as core_reputacao
from sentinela.core.limites_upload import LimitadorUploads

pytestmark = pytest.mark.integration

_LOG_ALTO_RISCO = (
    "203.0.113.120 - - [01/Sep/2026:10:00:00] "
    "\"GET /vulneravel.php?id=1' UNION SELECT null,username,password FROM users HTTP/1.1\" 200 100\n"
    "203.0.113.120 - - [01/Sep/2026:10:00:01] "
    "\"GET /vulneravel.php?id=2' UNION SELECT null,username,password FROM users HTTP/1.1\" 200 100\n"
    "203.0.113.120 - - [01/Sep/2026:10:00:02] \"GET /exec?cmd=;cat /etc/passwd HTTP/1.1\" 200 100\n"
    "203.0.113.120 - - [01/Sep/2026:10:00:03] \"GET /exec?cmd=;whoami HTTP/1.1\" 200 100\n"
    "203.0.113.120 - - [01/Sep/2026:10:00:04] \"GET /exec?cmd=;id HTTP/1.1\" 200 100\n"
)


@pytest.mark.asyncio
async def test_upload_via_htmx_cria_incidente_visivel_na_lista(client, usuario_de_teste):
    await client.post("/login", data={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})

    with patch.object(core_reputacao, "consultar_abuseipdb", return_value={"score_abuso": 90}), \
         patch.object(core_reputacao, "consultar_virustotal", return_value={"maliciosos": 8}):
        resp = await client.post(
            "/logs/upload",
            files={"arquivo": ("servidor.log", io.BytesIO(_LOG_ALTO_RISCO.encode()), "text/plain")},
            data={"limite": "1", "verificar_reputacao": "true"},
            headers={"X-Sentinela-CSRF": "1"},
        )

    assert resp.status_code == 200
    assert "203.0.113.120" in resp.text
    assert "Incidentes criados" in resp.text

    resp_lista = await client.get("/incidentes")
    assert "203.0.113.120" in resp_lista.text


@pytest.mark.asyncio
async def test_upload_sem_csrf_e_recusado(client, usuario_de_teste):
    await client.post("/login", data={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})
    resp = await client.post(
        "/logs/upload", files={"arquivo": ("servidor.log", io.BytesIO(b"linha\n"), "text/plain")},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_upload_alem_do_volume_permitido_e_recusado_com_429(client, app_instance, usuario_de_teste):
    """Ver core/limites_upload.py -- mesma checagem da metade React
    (tests/api/test_logs_api.py), aqui exercitada pela rota HTMX."""
    limitador_original = app_instance.state.limitador_uploads
    app_instance.state.limitador_uploads = LimitadorUploads(teto_bytes_por_usuario=1)
    try:
        await client.post("/login", data={"email": usuario_de_teste["email"], "senha": usuario_de_teste["senha"]})
        resp = await client.post(
            "/logs/upload",
            files={"arquivo": ("servidor.log", io.BytesIO(b"linha qualquer\n"), "text/plain")},
            headers={"X-Sentinela-CSRF": "1"},
        )
        assert resp.status_code == 429
    finally:
        app_instance.state.limitador_uploads = limitador_original
