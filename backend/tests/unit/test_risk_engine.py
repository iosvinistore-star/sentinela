# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testes do motor de risco (risk_engine.py).

Cobrem principalmente o fator "threat_intelligence": ele precisa reagir aos
dicts de reputação exatamente como consultar_reputacao_ip() (reputacao.py) os
produz de verdade -- com as chaves "score_abuso" (abuseipdb) e "maliciosos"
(virustotal) -- e não a nomes de campo da API crua (ex.: "abuseConfidenceScore",
"malicious"), que nunca aparecem no dict retornado por reputacao.py.
"""
from sentinela.core import risk_engine


def test_sem_reputacao_nao_soma_intel():
    risco = risk_engine.calcular_risco(3, ["SQL Injection (SQLi)"], reputacao=None)
    assert risco["fatores"]["threat_intelligence"] == 0


def test_reputacao_no_formato_real_do_projeto_eleva_o_score():
    """
    Formato exatamente como reputacao.consultar_reputacao_ip() devolve:
    reputacao["abuseipdb"]["score_abuso"] e reputacao["virustotal"]["maliciosos"].
    """
    reputacao_alto_risco = {
        "ip": "203.0.113.5",
        "abuseipdb": {"score_abuso": 100, "total_denuncias": 50, "pais": "RU"},
        "virustotal": {"maliciosos": 10, "suspeitos": 2, "inofensivos": 60},
        "classificacao": "ALTO RISCO",
    }

    com_intel = risk_engine.calcular_risco(2, ["Scanner de Vulnerabilidades"], reputacao=reputacao_alto_risco)
    sem_intel = risk_engine.calcular_risco(2, ["Scanner de Vulnerabilidades"], reputacao=None)

    # score_abuso=100 -> min(100*0.15, 15) = 15; maliciosos=10 -> min(10*2, 12) = 12
    assert com_intel["fatores"]["threat_intelligence"] == 27.0
    assert com_intel["score"] > sem_intel["score"]


def test_reputacao_desconhecida_ou_sem_sinal_nao_eleva_score():
    reputacao_neutra = {
        "ip": "203.0.113.5",
        "abuseipdb": {"erro": "sem chave"},
        "virustotal": {"erro": "sem chave"},
        "classificacao": "BAIXO RISCO / DESCONHECIDO",
    }
    risco = risk_engine.calcular_risco(2, ["Scanner de Vulnerabilidades"], reputacao=reputacao_neutra)
    assert risco["fatores"]["threat_intelligence"] == 0


def test_intel_e_limitada_ao_teto_mesmo_com_score_maximo():
    reputacao_maxima = {
        "abuseipdb": {"score_abuso": 100},
        "virustotal": {"maliciosos": 999},
    }
    risco = risk_engine.calcular_risco(1, ["Command Injection"], reputacao=reputacao_maxima)
    # 15 (teto abuseipdb) + 12 (teto virustotal) = 27
    assert risco["fatores"]["threat_intelligence"] == 27.0


def test_aceita_payload_cru_da_api_como_fallback():
    """Compatibilidade: se algum chamador passar o payload cru da API (em vez
    do dict traduzido por reputacao.py), os nomes de campo originais da API
    ainda funcionam como fallback."""
    reputacao_payload_cru = {
        "abuseipdb": {"abuseConfidenceScore": 80},
        "virustotal": {"malicious": 6},
    }
    risco = risk_engine.calcular_risco(1, ["Path Traversal"], reputacao=reputacao_payload_cru)
    assert risco["fatores"]["threat_intelligence"] > 0


def test_severidade_sobe_de_faixa_gracas_a_reputacao_ruim():
    """Caso de ponta a ponta: um IP com poucos ataques mas reputação péssima
    deve conseguir cruzar a faixa MEDIUM -> HIGH graças ao fator de intel --
    é exatamente o cenário que ficava mascarado pelo bug de nomes de chave."""
    tipos = ["SQL Injection (SQLi)", "Command Injection"]
    reputacao_pessima = {
        "abuseipdb": {"score_abuso": 95},
        "virustotal": {"maliciosos": 15},
    }
    risco = risk_engine.calcular_risco(3, tipos, reputacao=reputacao_pessima)
    assert risco["fatores"]["threat_intelligence"] > 20
    assert risco["severity"] in ("HIGH", "CRITICAL")


def test_reputacao_com_tipo_inesperado_nao_quebra():
    """reputacao != dict, ou sub-chaves != dict -> tratado com segurança, sem
    lançar exceção (mantém o comportamento defensivo já existente)."""
    risco = risk_engine.calcular_risco(1, ["Path Traversal"], reputacao="nao é um dict")
    assert risco["fatores"]["threat_intelligence"] == 0

    risco2 = risk_engine.calcular_risco(1, ["Path Traversal"], reputacao={"abuseipdb": "x", "virustotal": "y"})
    assert risco2["fatores"]["threat_intelligence"] == 0


def test_correlacao_elevar_risco():
    risco = risk_engine.calcular_risco(2, ["SQL Injection (SQLi)"], correlacao_score=70)
    assert risco["fatores"]["correlacao"] == 14.0
    assert risco["score"] > 0


# Capacidade 3 do modo autônomo -- ver
# core/risk_engine.aplicar_amortecimento_falso_positivo e
# services/automacao.obter_contagem_falsos_positivos.

def test_amortecimento_abaixo_do_minimo_nao_altera_o_risco():
    risco = risk_engine.calcular_risco(5, ["SQL Injection (SQLi)"])
    amortecido = risk_engine.aplicar_amortecimento_falso_positivo(risco, 1)
    assert amortecido == risco
    assert amortecido is risco  # nem cópia é feita -- devolve o mesmo objeto


def test_amortecimento_no_minimo_desconta_do_score():
    risco = risk_engine.calcular_risco(10, ["Command Injection", "SQL Injection (SQLi)"])
    amortecido = risk_engine.aplicar_amortecimento_falso_positivo(risco, 2)
    assert amortecido["score"] == max(0, risco["score"] - 24)  # 2 * 12
    assert amortecido["fatores"]["amortecimento_falso_positivo"] == -24
    # não modifica o dict original in-place
    assert "amortecimento_falso_positivo" not in risco["fatores"]


def test_amortecimento_e_limitado_a_um_teto():
    risco = {"score": 100, "severity": "CRITICAL", "fatores": {}}
    amortecido = risk_engine.aplicar_amortecimento_falso_positivo(risco, 50)
    assert amortecido["fatores"]["amortecimento_falso_positivo"] == -40  # teto
    assert amortecido["score"] == 60


def test_amortecimento_nunca_deixa_o_score_negativo():
    risco = {"score": 10, "severity": "LOW", "fatores": {}}
    amortecido = risk_engine.aplicar_amortecimento_falso_positivo(risco, 10)
    assert amortecido["score"] == 0
    assert amortecido["severity"] == "LOW"


def test_amortecimento_pode_derrubar_a_severidade_de_faixa():
    risco = {"score": 65, "severity": "HIGH", "fatores": {}}
    amortecido = risk_engine.aplicar_amortecimento_falso_positivo(risco, 3)  # desconto 36
    assert amortecido["score"] == 29
    assert amortecido["severity"] == "LOW"
