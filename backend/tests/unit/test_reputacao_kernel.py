# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testes do módulo de reputação (reputacao.py).

Nenhuma chamada HTTP real acontece aqui: requests.get é sempre mockado, e as
chaves de API são controladas via monkeypatch em vez de variáveis de
ambiente reais.
"""
from unittest.mock import MagicMock, patch

import requests

from sentinela.core import reputacao


def _resposta_mock(json_data, status_ok=True):
    resp = MagicMock()
    resp.json.return_value = json_data
    if status_ok:
        resp.raise_for_status.return_value = None
    else:
        resp.raise_for_status.side_effect = requests.HTTPError("erro http")
    return resp


# ---------------------------------------------------------------------------
# Sem chave configurada -> falha graciosa, não derruba a aplicação
# ---------------------------------------------------------------------------

def test_abuseipdb_sem_chave_retorna_erro(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    resultado = reputacao.consultar_abuseipdb("203.0.113.5")
    assert "erro" in resultado


def test_virustotal_sem_chave_retorna_erro(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    resultado = reputacao.consultar_virustotal("203.0.113.5")
    assert "erro" in resultado


# ---------------------------------------------------------------------------
# Chamadas com chave configurada (requests mockado)
# ---------------------------------------------------------------------------

def test_abuseipdb_com_chave_retorna_dados_parseados():
    resposta = _resposta_mock({
        "data": {
            "abuseConfidenceScore": 87,
            "totalReports": 42,
            "countryCode": "RU",
            "isp": "Exemplo ISP",
            "usageType": "Data Center",
            "domain": "exemplo.com",
        }
    })
    with patch.object(reputacao.requests, "get", return_value=resposta) as get_mock:
        resultado = reputacao.consultar_abuseipdb("203.0.113.5", api_key="chave-teste")

    assert resultado["score_abuso"] == 87
    assert resultado["total_denuncias"] == 42
    assert resultado["pais"] == "RU"
    get_mock.assert_called_once()
    assert get_mock.call_args.kwargs["headers"]["Key"] == "chave-teste"


def test_abuseipdb_com_erro_de_rede_retorna_erro_sem_lancar_excecao():
    with patch.object(reputacao.requests, "get", side_effect=requests.ConnectionError("timeout")):
        resultado = reputacao.consultar_abuseipdb("203.0.113.5", api_key="chave-teste")
    assert "erro" in resultado


def test_virustotal_com_chave_retorna_dados_parseados():
    resposta = _resposta_mock({
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 6, "suspicious": 2, "harmless": 70},
                "reputation": -15,
                "country": "CN",
                "as_owner": "Exemplo AS",
            }
        }
    })
    with patch.object(reputacao.requests, "get", return_value=resposta):
        resultado = reputacao.consultar_virustotal("203.0.113.5", api_key="chave-teste")

    assert resultado["maliciosos"] == 6
    assert resultado["reputacao"] == -15


# ---------------------------------------------------------------------------
# consultar_reputacao_ip: classificação combinada + cache
# ---------------------------------------------------------------------------

def test_classificacao_alto_risco_por_score_abuseipdb():
    with patch.object(reputacao, "consultar_abuseipdb", return_value={"score_abuso": 90}), \
         patch.object(reputacao, "consultar_virustotal", return_value={"maliciosos": 0}):
        resultado = reputacao.consultar_reputacao_ip("203.0.113.5", usar_cache=False)
    assert resultado["classificacao"] == "ALTO RISCO"


def test_classificacao_alto_risco_por_maliciosos_virustotal():
    with patch.object(reputacao, "consultar_abuseipdb", return_value={"score_abuso": 0}), \
         patch.object(reputacao, "consultar_virustotal", return_value={"maliciosos": 8}):
        resultado = reputacao.consultar_reputacao_ip("203.0.113.5", usar_cache=False)
    assert resultado["classificacao"] == "ALTO RISCO"


def test_classificacao_risco_moderado():
    with patch.object(reputacao, "consultar_abuseipdb", return_value={"score_abuso": 30}), \
         patch.object(reputacao, "consultar_virustotal", return_value={"maliciosos": 0}):
        resultado = reputacao.consultar_reputacao_ip("203.0.113.5", usar_cache=False)
    assert resultado["classificacao"] == "RISCO MODERADO"


def test_classificacao_baixo_risco_quando_sem_sinal():
    with patch.object(reputacao, "consultar_abuseipdb", return_value={"erro": "sem chave"}), \
         patch.object(reputacao, "consultar_virustotal", return_value={"erro": "sem chave"}):
        resultado = reputacao.consultar_reputacao_ip("203.0.113.5", usar_cache=False)
    assert resultado["classificacao"] == "BAIXO RISCO / DESCONHECIDO"


def test_cache_evita_segunda_consulta_ao_mesmo_ip():
    with patch.object(reputacao, "consultar_abuseipdb", return_value={"score_abuso": 10}) as abuse_mock, \
         patch.object(reputacao, "consultar_virustotal", return_value={"maliciosos": 0}):
        reputacao.consultar_reputacao_ip("203.0.113.5", usar_cache=True)
        reputacao.consultar_reputacao_ip("203.0.113.5", usar_cache=True)

    abuse_mock.assert_called_once()
