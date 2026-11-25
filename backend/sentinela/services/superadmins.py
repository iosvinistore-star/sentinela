# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Gestão da PRÓPRIA conta de superadmin -- hoje só a troca da própria senha.

Ver migrations/0013_token_version_superadmin.sql, cujo comentário apontava
exatamente esta lacuna: "não existe hoje um fluxo de troca da própria senha
para superadmin (só existe o script de criação inicial,
scripts/criar_superadmin.py) -- a revogação de sessão de superadmin é uma
ação operacional explícita (scripts/revogar_sessao_superadmin.py), não algo
que acontece sozinho." Este módulo fecha essa lacuna, espelhando
services/usuarios.py:trocar_propria_senha (mesmo raciocínio, mesma
garantia de segurança -- só troca a tabela-alvo).
"""
import asyncio

from sentinela.auth.security import hash_senha, validar_politica_senha, verificar_senha
from sentinela.repositories.superadmins import SuperadminRepositorio
from sentinela.services import auditoria as servico_auditoria

_PAPEIS_SAAS_VALIDOS = {"saas_owner", "saas_admin"}


def _publico(row):
    if row is None:
        return None
    d = dict(row)
    d["id"] = str(d["id"])
    return d


async def listar_saas_admins(sessao):
    """C4 -- listagem das contas de SaaS (Owner + Admin) -- só chamado por
    quem já passou por `exigir_saas_owner` (ver api/v1/admin.py)."""
    rows = await SuperadminRepositorio(sessao).listar()
    return [_publico(r) for r in rows]


async def criar_saas_admin(sessao, email: str, senha: str, papel: str, ator_superadmin_id) -> dict | None:
    """
    C4 -- operação EXCLUSIVA de SAAS_OWNER (a autorização em si é decisão da
    rota, ver api/v1/admin.py + auth/rbac.py:exigir_saas_owner). Só cria
    'saas_admin' ou 'saas_owner' -- nunca um terceiro valor.

    None se o email já existir (mesma semântica de
    services/usuarios.py:criar_usuario -- email é único GLOBALMENTE, entre
    usuarios E superadmins não há checagem cruzada aqui, mas a UNIQUE
    constraint de `superadmins.email` já cobre duplicidade dentro da
    própria tabela).
    """
    if papel not in _PAPEIS_SAAS_VALIDOS:
        raise ValueError(f"papel inválido -- use um de {sorted(_PAPEIS_SAAS_VALIDOS)}")
    validar_politica_senha(senha)
    email = email.strip().lower()
    if len(email) > 320 or "@" not in email:
        raise ValueError("email inválido")
    senha_hash = await asyncio.to_thread(hash_senha, senha)
    row = await SuperadminRepositorio(sessao).inserir_ignorando_email_duplicado(email, senha_hash, papel)
    if row is not None:
        await servico_auditoria.registrar_evento(
            sessao, None, "USER_CREATED", {"email": email, "papel_saas": papel},
            ator_superadmin_id=ator_superadmin_id,
        )
    return _publico(row)


async def trocar_propria_senha(sessao, superadmin_id, senha_atual: str, senha_nova: str) -> int | None:
    """
    Exige a senha ATUAL antes de trocar -- mesmo motivo de
    services/usuarios.py:trocar_propria_senha (sessão deixada aberta num
    computador compartilhado não deveria bastar pra trocar a senha sem
    quem está mexendo saber a senha de fato). Devolve None (sem trocar
    nada) se a senha atual não bater; devolve o novo `token_version` em
    caso de sucesso.

    Incrementa `token_version` na MESMA UPDATE que troca a senha (ver
    migrations/0013_token_version_superadmin.sql) -- invalida
    imediatamente qualquer OUTRA sessão de superadmin já aberta (cookie
    vazado, navegador compartilhado) na próxima requisição (ver
    auth/dependencies.py:conexao_superadmin/web/deps.py:
    conexao_superadmin_web). Quem chama a partir de uma requisição HTTP
    autenticada precisa reemitir o cookie de sessão com o `token_version`
    devolvido aqui -- senão a PRÓPRIA sessão que troca a senha também
    seria derrubada na requisição seguinte (ver api/v1/admin.py e
    web/routes_admin.py).
    """
    validar_politica_senha(senha_nova)
    repo = SuperadminRepositorio(sessao)
    senha_hash_atual = await repo.obter_senha_hash(superadmin_id)
    if senha_hash_atual is None or not await asyncio.to_thread(verificar_senha, senha_atual, senha_hash_atual):
        return None
    senha_hash_nova = await asyncio.to_thread(hash_senha, senha_nova)
    return await repo.trocar_senha(superadmin_id, senha_hash_nova)


async def existe_algum_superadmin(sessao) -> bool:
    return await SuperadminRepositorio(sessao).existe_algum()


async def travar_primeiro_acesso(sessao, chave: int) -> None:
    await SuperadminRepositorio(sessao).travar_transacao(chave)
