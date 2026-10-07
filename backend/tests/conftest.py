# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Fixtures compartilhadas por toda a suíte de testes (unit/integration/api).

O objetivo central destas fixtures é isolar os testes do mundo real: nenhum
teste deve tocar o iptables de verdade, escrever em /etc, ou fazer chamadas
HTTP reais. Tudo isso é redirecionado para arquivos temporários ou mockado.

Pós-rearquitetura: a antiga fixture `isolar_arquivos_de_estado` também
redirecionava `incidents.DB_PADRAO` (SQLite) — isso não existe mais, pois
incidentes agora vivem em Postgres (ver tests/integration/conftest_db.py
para o fixture de banco real usado pelos testes de integração/API).
"""
import sys
from pathlib import Path

import pytest

# Garante que o pacote `sentinela` (em backend/) seja importável
# independentemente de onde o pytest for executado.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinela.core import firewall  # noqa: E402
from sentinela.core import reputacao  # noqa: E402

# pytest só permite registrar plugins (fixtures partilhadas por caminho
# pontilhado) no conftest.py de nível mais alto — por isso as fixtures de
# banco real (tests/integration/conftest_db.py) e de cliente HTTP da API
# (tests/api/conftest_api.py) são registradas aqui, não redeclaradas em
# cada subpasta.
pytest_plugins = [
    "tests.integration.conftest_db",
    "tests.api.conftest_api",
]


@pytest.fixture(autouse=True)
def isolar_arquivos_de_estado(tmp_path, monkeypatch):
    """
    Redireciona todos os arquivos que sentinela.core.firewall escreveria
    (estado, log de texto, auditoria, regras persistidas) para dentro de um
    diretório temporário exclusivo deste teste, e evita QUALQUER chamada
    real ao iptables.
    """
    monkeypatch.setattr(firewall, "ARQUIVO_LOG_BLOQUEIOS", str(tmp_path / "bloqueios_firewall.log"))
    monkeypatch.setattr(firewall, "ARQUIVO_AUDITORIA", str(tmp_path / "auditoria.jsonl"))
    monkeypatch.setattr(firewall, "ARQUIVO_ESTADO", str(tmp_path / "bloqueios_estado.json"))
    monkeypatch.setattr(firewall, "ARQUIVO_REGRAS_PERSISTIDAS", str(tmp_path / "rules.v4"))
    monkeypatch.setattr(firewall, "ARQUIVO_REGRAS_PERSISTIDAS_V6", str(tmp_path / "rules.v6"))
    monkeypatch.setattr(firewall, "ARQUIVO_IPSET_PERSISTIDO", str(tmp_path / "ipset.conf"))
    yield tmp_path


@pytest.fixture(autouse=True)
def limpar_cache_reputacao():
    """Evita que o cache em memória de sentinela.core.reputacao vaze entre testes."""
    reputacao._cache.clear()
    reputacao._ultima_consulta_vt = 0.0
    yield
    reputacao._cache.clear()


class _TempoSemEspera:
    """
    Substitui a referência ao módulo `time` só dentro do namespace de
    reputacao.py. NÃO usar monkeypatch.setattr(reputacao.time, "sleep", ...)
    aqui: como `reputacao.time` é o mesmo objeto do módulo `time` da
    biblioteca padrão (não uma cópia), isso sobrescreveria time.sleep para
    o processo inteiro. A troca do objeto `time` local evita o problema
    pela raiz.
    """
    def sleep(self, segundos):
        pass

    def __getattr__(self, nome):
        import time as tempo_real
        return getattr(tempo_real, nome)


@pytest.fixture(autouse=True)
def sem_espera_real_virustotal(monkeypatch):
    """
    reputacao.py se auto-limita a ~4 consultas/min ao VirusTotal dormindo
    entre chamadas. Isso deixaria a suíte de testes lenta sem trazer nenhum
    benefício em um ambiente de teste, então neutralizamos apenas a espera
    vista pelo módulo reputacao (veja _TempoSemEspera acima).
    """
    monkeypatch.setattr(reputacao, "time", _TempoSemEspera())


@pytest.fixture
def linhas_log_exemplo():
    """Linhas de log sintéticas cobrindo tráfego normal e cada categoria de ataque."""
    return [
        '192.168.1.50 - - [26/Aug/2026:10:00:00] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n',
        # SQLi com evasão via URL-encoding (%20 no lugar de espaço)
        '203.0.113.5 - - [26/Aug/2026:10:01:00] "GET /vulneravel.php?id=1\'%20UNION%20SELECT%20null,pass%20FROM%20users HTTP/1.1" 200 4500 "-" "Mozilla/5.0"\n',
        # Path Traversal com evasão via URL-encoding (..%2f)
        '203.0.113.5 - - [26/Aug/2026:10:01:05] "GET /admin?cmd=..%2f..%2fetc%2fpasswd HTTP/1.1" 200 500 "-" "Mozilla/5.0"\n',
        # Scanner identificado só pelo User-Agent (sem payload malicioso na URL)
        '203.0.113.5 - - [26/Aug/2026:10:01:10] "GET / HTTP/1.1" 404 200 "-" "sqlmap/1.6"\n',
        # XSS
        '203.0.113.5 - - [26/Aug/2026:10:01:15] "GET /?x=<script>alert(1)</script> HTTP/1.1" 200 300 "-" "Mozilla/5.0"\n',
        # Command Injection
        '203.0.113.5 - - [26/Aug/2026:10:01:20] "GET /?cmd=;cat%20/etc/shadow HTTP/1.1" 200 300 "-" "Mozilla/5.0"\n',
        # IP com apenas 1 ataque, não deve cruzar o limite padrão
        '198.51.100.12 - - [26/Aug/2026:10:02:00] "GET /?busca=<script>alert(1)</script> HTTP/1.1" 200 2300 "-" "Mozilla/5.0"\n',
        # Linha fora do formato conhecido
        "isso nao e uma linha de log valida\n",
    ]


@pytest.fixture
def arquivo_log_exemplo(tmp_path, linhas_log_exemplo):
    caminho = tmp_path / "servidor_teste.log"
    caminho.write_text("".join(linhas_log_exemplo), encoding="utf-8")
    return str(caminho)
