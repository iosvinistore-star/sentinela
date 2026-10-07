# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
from pathlib import Path
import re

MIG = Path(__file__).parents[2] / "sentinela" / "db" / "migrations"


def test_migration_siem_retencao_define_tabela_fria():
    sql = (MIG / "0025_siem_retencao.sql").read_text(encoding="utf-8")
    assert "CREATE TABLE IF NOT EXISTS eventos_siem_cold" in sql
    assert "ENABLE ROW LEVEL SECURITY" in sql


def test_toda_tabela_com_guc_errado_e_corrigida_em_0030():
    """Regressão V8.1: 0024..0029 usavam app.empresa_id, mas o backend só seta
    app.current_tenant (db/pool.py). A 0030 precisa recriar a policy de TODA
    tabela afetada -- este teste quebra se alguém criar outra com o GUC errado."""
    afetadas = set()
    for arq in sorted(MIG.glob("[0-9][0-9][0-9][0-9]_*.sql")):
        if arq.name[:4] >= "0030":
            continue
        for m in re.finditer(r"CREATE POLICY\s+\w+\s+ON\s+(\w+)[^;]*app\.empresa_id", arq.read_text(encoding="utf-8")):
            afetadas.add(m.group(1))
    sql_0030 = (MIG / "0030_v82_corrige_rls_siem.sql").read_text(encoding="utf-8")
    assert afetadas, "esperava encontrar as policies antigas"
    for tabela in afetadas:
        assert f"'{tabela}'" in sql_0030, tabela
    for arq in MIG.glob("[0-9][0-9][0-9][0-9]_*.sql"):
        if arq.name[:4] > "0030":
            assert "app.empresa_id" not in arq.read_text(encoding="utf-8"), arq.name


def test_codigo_nunca_seta_app_empresa_id():
    raiz = Path(__file__).parents[2] / "sentinela"
    for py in raiz.rglob("*.py"):
        assert "app.empresa_id" not in py.read_text(encoding="utf-8"), py


def test_dashboard_siem_existe():
    text = (Path(__file__).parents[2] / "sentinela" / "api" / "v1" / "siem_dashboard.py").read_text(encoding="utf-8")
    assert "/resumo" in text
    assert "/fontes" in text
