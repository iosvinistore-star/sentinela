# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testes de sentinela.config.Settings -- em especial `validar()`, o
fail-fast de inicialização que impede a aplicação de subir com configuração
crítica faltando (ver docstring de Settings.validar para o raciocínio de
cada checagem). Nenhum destes testes precisa de Postgres real: `validar()`
só olha para os próprios campos de Settings.
"""
import pytest

from sentinela.config import Settings

_BASE_VALIDA = {
    "env": "production",
    "database_url": "postgresql://user:pw@host/db",
    "jwt_secret": "segredo-bem-longo-e-aleatorio",
    "mfa_encryption_key": "FubcIZSMWTNTDq6fxHGe66Wooatc2PzAdSjz14ZmcQM=",
    "url_base_publica": "https://soc.exemplo.com",
    "allowed_hosts": "soc.exemplo.com",
}


def _settings(**overrides):
    campos = {**_BASE_VALIDA, **overrides}
    return Settings(**campos)


def test_producao_com_tudo_configurado_nao_levanta():
    _settings().validar()  # não deve levantar


def test_database_url_ausente_levanta_em_qualquer_ambiente():
    with pytest.raises(RuntimeError, match="DATABASE_URL"):
        _settings(env="development", database_url="", url_base_publica="", allowed_hosts="").validar()


def test_jwt_secret_ausente_levanta_mesmo_fora_de_producao():
    """JWT_SECRET vazio é uma chave HMAC válida (HS256 aceita) -- por isso
    é exigido em QUALQUER ambiente, não só produção (ver docstring)."""
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        _settings(env="development", jwt_secret="", url_base_publica="", allowed_hosts="").validar()


def test_mfa_encryption_key_ausente_levanta_mesmo_fora_de_producao():
    """Mesmo racional de JWT_SECRET (ver teste acima) -- sem chave, o
    segredo TOTP não poderia ser cifrado/decifrado em NENHUM ambiente."""
    with pytest.raises(RuntimeError, match="SENTINELA_MFA_ENCRYPTION_KEY"):
        _settings(env="development", mfa_encryption_key="", url_base_publica="", allowed_hosts="").validar()


def test_mfa_encryption_key_invalida_levanta():
    """Uma string qualquer não é uma chave Fernet válida (precisa ser 32
    bytes url-safe base64) -- falha rápido na inicialização em vez de um
    erro só na primeira tentativa de configurar MFA."""
    with pytest.raises(RuntimeError, match="SENTINELA_MFA_ENCRYPTION_KEY"):
        _settings(env="development", mfa_encryption_key="chave-invalida-qualquer",
                  url_base_publica="", allowed_hosts="").validar()


def test_url_base_publica_ausente_levanta_em_producao():
    with pytest.raises(RuntimeError, match="SENTINELA_URL_BASE_PUBLICA"):
        _settings(url_base_publica="").validar()


def test_url_base_publica_ausente_nao_levanta_fora_de_producao():
    _settings(env="development", url_base_publica="", allowed_hosts="").validar()


def test_allowed_hosts_ausente_levanta_em_producao():
    """Ponto 4 do review de hardening: SENTINELA_ALLOWED_HOSTS não pode
    ficar opcional em produção -- sem ele, o TrustedHostMiddleware (main.py)
    nunca é registrado e a aplicação aceita qualquer cabeçalho Host."""
    with pytest.raises(RuntimeError, match="SENTINELA_ALLOWED_HOSTS"):
        _settings(allowed_hosts="").validar()


def test_allowed_hosts_so_com_espacos_conta_como_ausente_em_producao():
    with pytest.raises(RuntimeError, match="SENTINELA_ALLOWED_HOSTS"):
        _settings(allowed_hosts="   ").validar()


def test_allowed_hosts_ausente_nao_levanta_fora_de_producao():
    """Preserva o comportamento permissivo de dev/teste -- quem não
    configura ALLOWED_HOSTS localmente não é forçado a fazê-lo."""
    _settings(env="test", allowed_hosts="", url_base_publica="").validar()


def test_max_corpo_requisicao_bytes_tem_default_sensato(monkeypatch):
    monkeypatch.delenv("SENTINELA_MAX_CORPO_BYTES", raising=False)
    settings = Settings()
    assert settings.max_corpo_requisicao_bytes == 12 * 1024 * 1024


def test_max_corpo_requisicao_bytes_e_configuravel_por_env(monkeypatch):
    monkeypatch.setenv("SENTINELA_MAX_CORPO_BYTES", "999")
    assert Settings().max_corpo_requisicao_bytes == 999


def test_producao_property_reflete_env():
    assert _settings(env="production").producao is True
    assert _settings(env="development").producao is False
    assert _settings(env="test").producao is False


# ---------------------------------------------------------------------------
# Correção de bug encontrado em revisão crítica (2026-09, achado 5):
# sessao_horas, reputacao_cache_ttl_horas e ciclo_autonomo_intervalo_segundos
# usavam `int(os.environ.get(...))` DIRETO como default do dataclass --
# avaliado só UMA VEZ, no import do módulo, em vez de a cada `Settings()`
# instanciado (ao contrário de todo outro campo, que usa
# `default_factory=lambda: obter_segredo(...)`). Estes testes são o mesmo
# padrão de `test_max_corpo_requisicao_bytes_e_configuravel_por_env` acima
# -- monkeypatch muda a env DEPOIS do módulo já ter sido importado (o caso
# real de um teste ou de um provedor de segredos trocado em runtime), e um
# `Settings()` novo precisa refletir a mudança na hora.
# ---------------------------------------------------------------------------

def test_sessao_horas_tem_default_sensato(monkeypatch):
    monkeypatch.delenv("SENTINELA_SESSAO_HORAS", raising=False)
    assert Settings().sessao_horas == 12


def test_sessao_horas_e_configuravel_por_env_a_cada_instanciacao(monkeypatch):
    monkeypatch.setenv("SENTINELA_SESSAO_HORAS", "3")
    assert Settings().sessao_horas == 3
    monkeypatch.setenv("SENTINELA_SESSAO_HORAS", "7")
    assert Settings().sessao_horas == 7  # não travou no valor lido na primeira instanciação


def test_reputacao_cache_ttl_horas_tem_default_sensato(monkeypatch):
    monkeypatch.delenv("SENTINELA_REPUTACAO_TTL_HORAS", raising=False)
    assert Settings().reputacao_cache_ttl_horas == 24


def test_reputacao_cache_ttl_horas_e_configuravel_por_env_a_cada_instanciacao(monkeypatch):
    monkeypatch.setenv("SENTINELA_REPUTACAO_TTL_HORAS", "1")
    assert Settings().reputacao_cache_ttl_horas == 1
    monkeypatch.setenv("SENTINELA_REPUTACAO_TTL_HORAS", "48")
    assert Settings().reputacao_cache_ttl_horas == 48


def test_ciclo_autonomo_intervalo_segundos_tem_default_sensato(monkeypatch):
    monkeypatch.delenv("SENTINELA_CICLO_AUTONOMO_INTERVALO_SEGUNDOS", raising=False)
    assert Settings().ciclo_autonomo_intervalo_segundos == 900


def test_ciclo_autonomo_intervalo_segundos_e_configuravel_por_env_a_cada_instanciacao(monkeypatch):
    monkeypatch.setenv("SENTINELA_CICLO_AUTONOMO_INTERVALO_SEGUNDOS", "60")
    assert Settings().ciclo_autonomo_intervalo_segundos == 60
    monkeypatch.setenv("SENTINELA_CICLO_AUTONOMO_INTERVALO_SEGUNDOS", "120")
    assert Settings().ciclo_autonomo_intervalo_segundos == 120
