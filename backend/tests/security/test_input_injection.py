# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
import pytest
from unittest.mock import patch

from sentinela.core import reputacao


def test_reputacao_rejeita_entrada_nao_ip_antes_de_qualquer_rede():
    with patch.object(reputacao.requests, "get") as get:
        resultado = reputacao.consultar_reputacao_ip("127.0.0.1@evil.example")
    assert resultado["erro"] == "IP inválido"
    get.assert_not_called()


def test_reputacao_usa_destinos_fixos_para_ip_valido():
    class Resp:
        def raise_for_status(self):
            pass
        def json(self):
            return {"data": {"abuseConfidenceScore": 0, "last_analysis_stats": {}}}
    with patch.object(reputacao.requests, "get", return_value=Resp()) as get:
        reputacao.consultar_reputacao_ip("203.0.113.77", usar_cache=False, abuseipdb_key="x", vt_key="y")
    urls=[c.args[0] for c in get.call_args_list]
    assert urls == ["https://api.abuseipdb.com/api/v2/check", "https://www.virustotal.com/api/v3/ip_addresses/203.0.113.77"]
    assert all("evil" not in u for u in urls)

@pytest.mark.asyncio
async def test_login_sql_injection_payload_nao_bypassa_autenticacao(client):
    resp = await client.post('/api/v1/auth/login', json={'email': "' OR '1'='1", 'senha': "' OR '1'='1"})
    assert resp.status_code in (401, 429)
