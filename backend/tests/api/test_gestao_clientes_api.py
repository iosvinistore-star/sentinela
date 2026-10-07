# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Gestão de clientes em uma tela só: `POST /admin/clientes` (empresa +
contrato + admin + chave de ativação numa transação) e o primeiro acesso
da plataforma (`/setup`).

O que estes testes protegem, além do caminho feliz: que um cadastro que
falha no meio não deixa empresa órfã, que o CNPJ é de fato único, e que a
rota de primeiro acesso se fecha depois do primeiro uso -- ela cria um
SAAS_OWNER sem autenticação, então uma regressão ali é crítica.
"""
import secrets

import pytest

from sentinela.db.pool import superadmin_scoped_connection
from sentinela.services import chave_ativacao
from tests.api.conftest_api import logar

CSRF = {"X-Sentinela-CSRF": "1"}
HEADER_ENROLLMENT = "X-Sentinela-Enrollment-Token"


def _sufixo() -> str:
    return secrets.token_hex(4)


def _cnpj_unico() -> str:
    """CNPJ sintético com dígitos verificadores corretos -- o banco tem
    índice único em `cnpj`, então dois testes na mesma base não podem
    sortear o mesmo número."""
    base = "".join(secrets.choice("0123456789") for _ in range(8)) + "0001"
    for _ in range(2):
        pesos = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2][-len(base):]
        resto = sum(int(d) * p for d, p in zip(base, pesos)) % 11
        base += "0" if resto < 2 else str(11 - resto)
    return base


@pytest.mark.asyncio
async def test_cadastra_cliente_inteiro_e_agente_conecta(client, superadmin_de_teste, pool):
    """O fluxo que a tela "Novo cliente" dispara, ponta a ponta: uma
    chamada devolve login, senha e chave -- e a chave já serve para o
    agente entrar."""
    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    sufixo = _sufixo()
    cnpj = _cnpj_unico()
    r = await client.post("/api/v1/admin/clientes", headers=CSRF, json={
        "nome": f"Prefeitura Teste {sufixo}",
        "plano": "enterprise",
        "admin_email": f"ti-{sufixo}@cliente.gov.br",
        "contrato": {
            "cnpj": cnpj[:2] + "." + cnpj[2:5] + "." + cnpj[5:8] + "/" + cnpj[8:12] + "-" + cnpj[12:],
            "responsavel": "Maria Souza",
            "email_contato": f"maria-{sufixo}@cliente.gov.br",
            "telefone": "(81) 99999-0000",
            "contrato_numero": f"CT-{sufixo}",
            "contrato_vigencia": "2027-12-31",
        },
        "max_instalacoes": 5,
    })
    assert r.status_code == 201, r.text
    corpo = r.json()

    # O provedor recebe tudo o que precisa repassar -- uma vez só.
    assert corpo["admin"]["senha_gerada"] is True
    assert len(corpo["admin"]["senha_inicial"]) >= 12
    assert corpo["chave_ativacao"].startswith("SNT1-")
    for pedaco in (corpo["admin"]["senha_inicial"], corpo["chave_ativacao"], corpo["admin"]["email"]):
        assert pedaco in corpo["texto_para_cliente"]

    # CNPJ entra normalizado (só dígitos), venha formatado ou não.
    assert corpo["empresa"]["cnpj"] == cnpj
    assert corpo["empresa"]["contrato_numero"] == f"CT-{sufixo}"
    # Agentes já habilitados: era o passo extra que fazia o agente tomar 403.
    assert corpo["empresa"]["agentes_endpoint_habilitado"] is True

    # A chave devolvida funciona de verdade no enroll do agente.
    dados = chave_ativacao.ler(corpo["chave_ativacao"])
    r = await client.post("/api/v1/agentes/enroll", json={"hostname": f"pc-{sufixo}"},
                          headers={HEADER_ENROLLMENT: dados["token"]})
    assert r.status_code == 200, r.text
    assert r.json()["token"].startswith("agt_")

    # E o admin criado entra no painel com a senha devolvida.
    await client.post("/api/v1/auth/logout", headers=CSRF)
    r = await logar(client, corpo["admin"]["email"], corpo["admin"]["senha_inicial"])
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_cnpj_invalido_e_duplicado_nao_criam_empresa(client, superadmin_de_teste, pool):
    """Um cadastro recusado não pode deixar empresa pela metade -- foi por
    isso que a rota virou uma transação só."""
    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    sufixo = _sufixo()

    r = await client.post("/api/v1/admin/clientes", headers=CSRF, json={
        "nome": f"CNPJ Ruim {sufixo}", "admin_email": f"a-{sufixo}@x.com",
        "contrato": {"cnpj": "11.111.111/1111-11"},
    })
    assert r.status_code == 422 and "CNPJ" in r.json()["detail"]

    cnpj = _cnpj_unico()
    primeiro = await client.post("/api/v1/admin/clientes", headers=CSRF, json={
        "nome": f"Cliente Um {sufixo}", "admin_email": f"um-{sufixo}@x.com", "contrato": {"cnpj": cnpj},
    })
    assert primeiro.status_code == 201, primeiro.text

    repetido = await client.post("/api/v1/admin/clientes", headers=CSRF, json={
        "nome": f"Cliente Dois {sufixo}", "admin_email": f"dois-{sufixo}@x.com", "contrato": {"cnpj": cnpj},
    })
    assert repetido.status_code == 409 and f"Cliente Um {sufixo}" in repetido.json()["detail"]

    async with superadmin_scoped_connection(pool) as conn:
        nomes = await conn.fetch("SELECT nome FROM empresas WHERE nome LIKE $1", f"%{sufixo}")
    # Só o cadastro que deu 201 existe; os dois recusados não deixaram rastro.
    assert [n["nome"] for n in nomes] == [f"Cliente Um {sufixo}"]


@pytest.mark.asyncio
async def test_email_duplicado_desfaz_a_empresa_junto(client, superadmin_de_teste, usuario_de_teste, pool):
    """O e-mail do admin só colide no ÚLTIMO passo da transação -- é o caso
    em que o rollback importa."""
    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    sufixo = _sufixo()
    r = await client.post("/api/v1/admin/clientes", headers=CSRF, json={
        "nome": f"Colisao {sufixo}", "admin_email": usuario_de_teste["email"],
    })
    assert r.status_code == 409, r.text

    async with superadmin_scoped_connection(pool) as conn:
        restou = await conn.fetchval("SELECT count(*) FROM empresas WHERE nome = $1", f"Colisao {sufixo}")
    assert restou == 0


@pytest.mark.asyncio
async def test_edita_contrato_e_lista_traz_os_campos(client, superadmin_de_teste, pool):
    await logar(client, superadmin_de_teste["email"], superadmin_de_teste["senha"])
    sufixo = _sufixo()
    criado = await client.post("/api/v1/admin/clientes", headers=CSRF, json={
        "nome": f"Contrato {sufixo}", "admin_email": f"c-{sufixo}@x.com",
    })
    assert criado.status_code == 201, criado.text
    empresa_id = criado.json()["empresa"]["id"]

    novo_cnpj = _cnpj_unico()
    r = await client.patch(f"/api/v1/admin/empresas/{empresa_id}/contrato", headers=CSRF, json={
        "cnpj": novo_cnpj, "responsavel": "João Lima", "contrato_numero": f"CT-{sufixo}-B",
        "contrato_vigencia": "2028-01-31",
    })
    assert r.status_code == 200, r.text
    assert r.json()["empresa"]["responsavel"] == "João Lima"

    listagem = await client.get("/api/v1/admin/empresas")
    alvo = [e for e in listagem.json()["empresas"] if e["id"] == empresa_id][0]
    assert alvo["cnpj"] == novo_cnpj and alvo["contrato_numero"] == f"CT-{sufixo}-B"


@pytest.mark.asyncio
async def test_admin_da_empresa_nao_cadastra_cliente(client, usuario_de_teste):
    """Cadastrar cliente é do provedor, nunca do tenant."""
    await logar(client, usuario_de_teste["email"], usuario_de_teste["senha"])
    r = await client.post("/api/v1/admin/clientes", headers=CSRF,
                          json={"nome": "Tentativa", "admin_email": "x@y.com"})
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_primeiro_acesso_so_funciona_uma_vez(client, superadmin_de_teste):
    """Com a plataforma já configurada (o fixture criou um superadmin), a
    rota de primeiro acesso tem de estar fechada -- ela cria um
    SAAS_OWNER sem login."""
    r = await client.get("/api/v1/setup/status")
    assert r.status_code == 200 and r.json() == {
        "configurado": True, "precisa_configurar": False, "exige_token": False,
    }

    r = await client.post("/api/v1/setup/primeiro-acesso",
                          json={"email": "invasor@x.com", "senha": "SenhaQueNaoVaiColar1"})
    assert r.status_code == 409
