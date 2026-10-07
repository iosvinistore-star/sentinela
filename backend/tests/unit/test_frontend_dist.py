# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Localização do build do React: repositório, imagem Docker e variável de ambiente."""
from pathlib import Path

from sentinela import main


def _dist(base: Path) -> Path:
    d = base / "frontend-react" / "dist"
    d.mkdir(parents=True)
    (d / "index.html").write_text("<html></html>")
    return d


def test_variavel_de_ambiente_tem_prioridade(tmp_path, monkeypatch):
    d = _dist(tmp_path)
    monkeypatch.setenv("SENTINELA_FRONTEND_DIST", str(d))
    assert main.localizar_dist_frontend() == str(d)


def test_estrutura_da_imagem_docker(tmp_path, monkeypatch):
    """Imagem: /app/sentinela/main.py e /app/frontend-react/dist (bug V8.1: nunca era achado)."""
    app_dir = tmp_path / "app"
    (app_dir / "sentinela").mkdir(parents=True)
    d = _dist(app_dir)
    monkeypatch.delenv("SENTINELA_FRONTEND_DIST", raising=False)
    monkeypatch.setattr(main, "__file__", str(app_dir / "sentinela" / "main.py"))
    assert main.localizar_dist_frontend() == str(d)


def test_sem_build_devolve_none(tmp_path, monkeypatch):
    (tmp_path / "x" / "sentinela").mkdir(parents=True)
    monkeypatch.delenv("SENTINELA_FRONTEND_DIST", raising=False)
    monkeypatch.setattr(main, "__file__", str(tmp_path / "x" / "sentinela" / "main.py"))
    assert main.localizar_dist_frontend() is None
