# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testes de core/correlacao.py -- especificamente da correção de bug
encontrado em revisão crítica (2026-09, "revisa as outras partes do
sistema", achado 3): `_parse_data` podia devolver um datetime AWARE (quando
o timestamp do log tem offset, ex.: "-0300") para um evento e um datetime
NAIVE (fallback sem offset, ou `datetime.min` quando o parsing falha) para
OUTRO evento do MESMO IP -- e comparar/subtrair um aware com um naive
lança `TypeError: can't compare offset-naive and offset-aware datetimes`,
sem nenhum catch, DENTRO de `correlacionar_por_ip`.

Isso importa de verdade porque `correlacionar_por_ip` é chamada em
`services/resposta_incidentes.py:responder_a_incidentes` ANTES do loop
por-candidato que isola falhas com try/except (ver o comentário lá) -- um
timestamp malformado de UM IP derrubava a criação de incidente do LOTE
INTEIRO, para todos os outros IPs do mesmo upload de log, inclusive
ataques óbvios e reais.
"""
from datetime import timezone

from sentinela.core.correlacao import _parse_data, correlacionar_por_ip


# ---------------------------------------------------------------------------
# _parse_data -- normalização de timezone-awareness
# ---------------------------------------------------------------------------

def test_parse_data_com_offset_retorna_aware_em_utc():
    dt = _parse_data("26/Aug/2026:16:14:00 -0300")
    assert dt is not None
    assert dt.tzinfo is not None
    # -0300 -> 19:14:00 em UTC
    assert dt.astimezone(timezone.utc).hour == 19


def test_parse_data_sem_offset_retorna_aware_tambem():
    """O fallback (formato truncado/sem offset) precisa devolver um
    datetime com a MESMA propriedade de awareness que o caminho com "%z" --
    senão dois eventos do mesmo IP, um em cada caminho, voltam a ser
    incomparáveis (o próprio bug desta correção)."""
    dt = _parse_data("26/Aug/2026:16:14:00")
    assert dt is not None
    assert dt.tzinfo is not None


def test_parse_data_invalido_retorna_none():
    assert _parse_data("isso nao e uma data") is None
    assert _parse_data("") is None
    assert _parse_data(None) is None


def test_parse_data_aware_e_naive_do_mesmo_horario_sao_comparaveis_e_iguais_em_utc():
    """Prova direta de que os dois caminhos de sucesso de _parse_data agora
    produzem valores do mesmo "tipo" (aware) e comparáveis entre si -- sem
    isto, esta comparação por si só já lançaria TypeError antes da correção."""
    com_offset = _parse_data("26/Aug/2026:16:14:00 +0000")
    sem_offset = _parse_data("26/Aug/2026:16:14:00")
    assert com_offset is not None and sem_offset is not None
    assert com_offset == sem_offset  # não lança, e são iguais (mesmo instante em UTC)


# ---------------------------------------------------------------------------
# correlacionar_por_ip -- repro do crash de batch inteiro
# ---------------------------------------------------------------------------

def test_correlacionar_por_ip_nao_lanca_com_timestamps_aware_e_naive_misturados_no_mesmo_ip():
    """
    Repro direto do achado 3: um IP com 3 eventos, onde um timestamp tem
    offset (parseia aware), outro não tem offset (parseia naive antes da
    correção) e um terceiro é irreconhecível (cai em `None` ->
    `datetime.min`, também naive antes da correção). Antes da correção,
    isto lançava TypeError na hora de `sorted()` (linha 34) ou na subtração
    de tempos (linha 41) -- interrompendo TODO o processamento do lote,
    não só deste IP.
    """
    relatorio = {"detalhes_alertas": [
        {"ip": "203.0.113.50", "data": "03/Sep/2026:10:00:01 -0300", "tipo_ataque": "Scanner de Vulnerabilidades"},
        {"ip": "203.0.113.50", "data": "03/Sep/2026:10:00:05", "tipo_ataque": "Path Traversal"},  # sem offset
        {"ip": "203.0.113.50", "data": "isso-nao-e-uma-data-valida", "tipo_ataque": "SQL Injection (SQLi)"},  # irreconhecível
        # Um segundo IP no mesmo lote, sem nenhum problema -- prova que o
        # lote inteiro continua sendo processado (não só que não lança).
        {"ip": "203.0.113.51", "data": "03/Sep/2026:11:00:00 -0300", "tipo_ataque": "Command Injection"},
    ]}

    resultado = correlacionar_por_ip(relatorio)  # não deve lançar

    assert "203.0.113.50" in resultado
    assert "203.0.113.51" in resultado
    assert resultado["203.0.113.50"]["total_eventos"] == 3
    assert resultado["203.0.113.51"]["total_eventos"] == 1


def test_correlacionar_por_ip_com_todos_os_timestamps_irreconheciveis_nao_lanca():
    """Caso extremo: NENHUM timestamp do IP parseia -- todos caem no
    fallback `_DATA_MINIMA` (todos iguais entre si, então nunca comparados
    contra um valor aware de verdade neste caso específico, mas o teste
    documenta que o caminho `default=0` do Counter/max também não lança)."""
    relatorio = {"detalhes_alertas": [
        {"ip": "203.0.113.60", "data": "lixo-1", "tipo_ataque": "XSS"},
        {"ip": "203.0.113.60", "data": "lixo-2", "tipo_ataque": "XSS"},
    ]}
    resultado = correlacionar_por_ip(relatorio)
    assert resultado["203.0.113.60"]["total_eventos"] == 2


def test_correlacao_detecta_cadeia_scanner_e_exploracao():
    """Mesmo teste já existente em test_analisador_logs.py -- duplicado
    aqui, no arquivo dedicado a core/correlacao.py, para que a suíte de
    correlação fique auto-contida (o original em test_analisador_logs.py
    continua valendo, sem remoção)."""
    relatorio = {"detalhes_alertas": [
        {"ip": "203.0.113.10", "data": "03/Sep/2026:10:00:01", "tipo_ataque": "Scanner de Vulnerabilidades"},
        {"ip": "203.0.113.10", "data": "03/Sep/2026:10:00:05", "tipo_ataque": "Path Traversal"},
        {"ip": "203.0.113.10", "data": "03/Sep/2026:10:00:09", "tipo_ataque": "SQL Injection (SQLi)"},
    ]}
    corr = correlacionar_por_ip(relatorio)["203.0.113.10"]
    assert corr["correlacionado"] is True
    assert "reconhecimento_e_exploracao" in corr["sinais"]
