# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Gestão de usuários. Duas superfícies de conexão usam este módulo:
  - conn tenant-scoped (RLS): um admin gerencia os usuários da PRÓPRIA
    empresa -- RLS em `usuarios` já garante que só vê/edita da sua empresa,
    então `listar_usuarios`/`atualizar_usuario` não precisam filtrar por
    empresa_id explicitamente.
  - conn superadmin-scoped (BYPASSRLS): usado só por api/v1/admin.py, que
    passa um `empresa_id` explícito vindo de fora da sessão de quem chama
    (ex.: criar o admin inicial de uma empresa nova, ou listar usuários de
    uma empresa arbitrária) -- ver `listar_usuarios_por_empresa`.

`criar_usuario` serve os dois casos: quem chama sempre fornece o
`empresa_id` (da própria sessão, no caso tenant-scoped; escolhido
explicitamente, no caso superadmin-scoped).
"""
import asyncio

from sentinela.auth.security import hash_senha, validar_politica_senha, verificar_senha
from sentinela.repositories.usuarios import UsuarioRepositorio
from sentinela.services import auditoria as servico_auditoria


def _publico(row):
    if row is None:
        return None
    d = dict(row)
    d["id"] = str(d["id"])
    d["empresa_id"] = str(d["empresa_id"])
    return d


async def listar_usuarios(sessao):
    return [_publico(r) for r in await UsuarioRepositorio(sessao).listar()]


async def listar_usuarios_por_empresa(sessao, empresa_id):
    return [_publico(r) for r in await UsuarioRepositorio(sessao).listar(empresa_id)]


async def criar_usuario(sessao, empresa_id, email: str, papel: str, senha: str,
                          ator_usuario_id=None, ator_superadmin_id=None):
    """None se o email já existir -- é único GLOBALMENTE, não por empresa
    (ver 0001_tabelas.sql: o login não pergunta "qual empresa" antes da senha)."""
    validar_politica_senha(senha)
    email = email.strip().lower()
    if len(email) > 320 or "@" not in email:
        raise ValueError("email inválido")
    # asyncio.to_thread: bcrypt é caro em CPU de propósito -- rodar direto
    # aqui bloquearia o event loop do processo pela duração do hash,
    # travando outras requisições concorrentes de QUALQUER tenant.
    senha_hash = await asyncio.to_thread(hash_senha, senha)
    row = await UsuarioRepositorio(sessao).inserir_ignorando_email_duplicado(empresa_id, email, papel, senha_hash)
    if row is not None:
        await servico_auditoria.registrar_evento(
            sessao, empresa_id, "usuario.criado", {"email": email, "papel": papel},
            ator_usuario_id=ator_usuario_id, ator_superadmin_id=ator_superadmin_id,
        )
    return _publico(row)


async def atualizar_usuario(sessao, empresa_id, usuario_id, papel: str | None = None,
                              ativo: bool | None = None, ator_usuario_id=None):
    # `AND empresa_id = $4` é redundante com a RLS de `conexao_tenant`
    # (que já restringe toda query de app_tenant à empresa da sessão) --
    # mas o parâmetro `empresa_id` já chegava até aqui sem nunca ser usado
    # na query, o que só funcionava por a RLS estar correta. Defesa em
    # profundidade: mesmo que a RLS falhe/seja removida por engano numa
    # migration futura, um admin não consegue atualizar um usuario_id de
    # OUTRA empresa só porque adivinhou/enumerou o UUID.
    campos = {k: v for k, v in (("papel", papel), ("ativo", ativo)) if v is not None}
    row = await UsuarioRepositorio(sessao).atualizar(empresa_id, usuario_id, campos)
    if row is not None:
        await servico_auditoria.registrar_evento(
            sessao, empresa_id, "usuario.atualizado", {"usuario_id": str(usuario_id), "papel": papel, "ativo": ativo},
            ator_usuario_id=ator_usuario_id,
        )
    return _publico(row)


async def trocar_propria_senha(sessao, usuario_id, senha_atual: str, senha_nova: str) -> int | None:
    """
    Exige a senha ATUAL antes de trocar -- sem isso, uma sessão deixada
    aberta (computador compartilhado, sessão sequestrada) permitiria trocar
    a senha sem quem está mexendo saber a senha de fato. Devolve None (sem
    trocar nada) se a senha atual não bater; devolve o novo `token_version`
    (int) em caso de sucesso.

    Incrementa `token_version` na MESMA UPDATE que troca a senha (ver
    migrations/0011_token_version.sql) -- isso invalida imediatamente
    qualquer OUTRA sessão já aberta deste usuário na próxima requisição
    (auth/dependencies.py:conexao_tenant, web/deps.py:conexao_tenant_web).
    Quem chama esta função a partir de uma requisição HTTP autenticada
    precisa reemitir o cookie de sessão com o `token_version` devolvido
    aqui -- senão a PRÓPRIA sessão que troca a senha também seria
    derrubada na requisição seguinte (ver api/v1/usuarios.py e
    web/routes_usuarios.py).
    """
    validar_politica_senha(senha_nova)
    repo = UsuarioRepositorio(sessao)
    senha_hash_atual = await repo.obter_senha_hash(usuario_id)
    if senha_hash_atual is None or not await asyncio.to_thread(verificar_senha, senha_atual, senha_hash_atual):
        return None
    senha_hash_nova = await asyncio.to_thread(hash_senha, senha_nova)
    return await repo.trocar_senha(usuario_id, senha_hash_nova)
