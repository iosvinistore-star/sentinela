# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testes do mascaramento de segredos (core/redacao.py) -- item 16 do plano de
endurecimento pós-auditoria.
"""
from sentinela.core.redacao import (
    CAMPOS_SENSIVEIS,
    MASCARA,
    campo_sensivel,
    mascarar_dados,
    mascarar_texto,
)


def test_campo_sensivel_e_case_insensitive_e_normaliza_hifen():
    assert campo_sensivel("senha")
    assert campo_sensivel("SENHA")
    assert campo_sensivel("Senha_Nova")
    assert campo_sensivel("x-sentinela-csrf")  # "-" normalizado para "_"
    assert campo_sensivel("X-Sentinela-CSRF")


def test_campo_sensivel_devolve_falso_para_nomes_comuns_e_nao_string():
    assert not campo_sensivel("email")
    assert not campo_sensivel("nome")
    assert not campo_sensivel(None)
    assert not campo_sensivel(0)
    assert not campo_sensivel(123)


def test_mascarar_texto_substitui_bearer_token():
    texto = "Authorization: Bearer abc123.def456-ghi_789=="
    resultado = mascarar_texto(texto)
    assert "abc123" not in resultado
    assert f"Bearer {MASCARA}" in resultado


def test_mascarar_texto_substitui_jwt_solto_no_meio_da_frase():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc123def456ghi789jkl"
    texto = f"sessão inválida, token recebido: {jwt} -- rejeitado"
    resultado = mascarar_texto(texto)
    assert jwt not in resultado
    assert MASCARA in resultado


def test_mascarar_texto_preserva_texto_sem_segredo():
    texto = "usuário não encontrado para o email informado"
    assert mascarar_texto(texto) == texto


def test_mascarar_texto_lida_com_string_vazia_e_none():
    assert mascarar_texto("") == ""
    assert mascarar_texto(None) is None


def test_mascarar_dados_mascara_campo_sensivel_no_dict():
    dados = {"email": "a@b.com", "senha": "hunter2"}
    resultado = mascarar_dados(dados)
    assert resultado["email"] == "a@b.com"
    assert resultado["senha"] == MASCARA


def test_mascarar_dados_mascara_incondicionalmente_mesmo_valor_nao_string():
    # Um valor sensível não precisa ser string pra ser mascarado -- ex.: um
    # dict aninhado inteiro sob a chave "token".
    dados = {"token": {"access": "xyz", "expires": 3600}}
    resultado = mascarar_dados(dados)
    assert resultado["token"] == MASCARA


def test_mascarar_dados_e_recursivo_em_dicts_aninhados():
    dados = {"usuario": {"email": "a@b.com", "senha_atual": "abc", "senha_nova": "def"}}
    resultado = mascarar_dados(dados)
    assert resultado["usuario"]["email"] == "a@b.com"
    assert resultado["usuario"]["senha_atual"] == MASCARA
    assert resultado["usuario"]["senha_nova"] == MASCARA


def test_mascarar_dados_e_recursivo_em_listas():
    dados = {"eventos": [{"acao": "login", "senha": "abc"}, {"acao": "logout"}]}
    resultado = mascarar_dados(dados)
    assert resultado["eventos"][0]["senha"] == MASCARA
    assert resultado["eventos"][0]["acao"] == "login"
    assert resultado["eventos"][1] == {"acao": "logout"}


def test_mascarar_dados_mascara_token_solto_dentro_de_string_generica():
    dados = {"detalhe": "falha ao renovar: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def"}
    resultado = mascarar_dados(dados)
    assert "Bearer" in resultado["detalhe"]
    assert MASCARA in resultado["detalhe"]
    assert "eyJhbGciOiJIUzI1NiJ9" not in resultado["detalhe"]


def test_mascarar_dados_preserva_tipos_nao_dict_lista_str():
    assert mascarar_dados(123) == 123
    assert mascarar_dados(True) is True
    assert mascarar_dados(None) is None


def test_mascarar_dados_cobre_todos_os_campos_declarados():
    """Um teste de regressão simples: se alguém remover um nome de
    CAMPOS_SENSIVEIS por engano, este teste denuncia."""
    esperados = {
        "authorization", "cookie", "set_cookie", "x_sentinela_csrf",
        "senha", "senha_atual", "senha_nova", "password", "nova_senha",
        "token", "jwt", "refresh_token", "reset_token", "token_hash",
        "api_key", "apikey", "abuseipdb_api_key", "vt_api_key",
        "smtp_password", "smtp_user", "senha_hash", "dashboard_senha",
    }
    assert esperados <= CAMPOS_SENSIVEIS
    for campo in esperados:
        resultado = mascarar_dados({campo: "valor-secreto-qualquer"})
        assert resultado[campo] == MASCARA, f"campo {campo!r} não foi mascarado"
