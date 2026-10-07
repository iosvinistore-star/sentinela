# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Lookup de credenciais no login — o único lugar do sistema onde faz sentido
consultar `usuarios`/`superadmins` ANTES de saber a empresa do chamador
(problema do "ovo e galinha": RLS em `usuarios` exige um tenant já setado,
mas no momento do login ainda não sabemos qual é).

Resolvido rodando numa `superadmin_scoped_connection` (BYPASSRLS) fazendo
só uma busca indexada por email — seguro porque o filtro (email) vem do
próprio chamador, e a única coisa que sai daqui é o suficiente para
verificar uma senha e emitir um JWT, nunca uma listagem.
"""
import asyncio

import bcrypt

from sentinela.auth.security import verificar_senha
from sentinela.repositories.superadmins import SuperadminRepositorio
from sentinela.repositories.usuarios import UsuarioRepositorio

# Hash gerado uma vez no processo para manter o custo de bcrypt mesmo quando
# o email não existe em nenhuma das duas tabelas -- ver comentário em
# `autenticar` sobre por que isso roda para AS DUAS tabelas, não só uma.
HASH_DUMMY = bcrypt.hashpw(b"sentinela-dummy-password", bcrypt.gensalt()).decode("utf-8")


class ContaEmpresaInativaError(Exception):
    """
    Levantada por `autenticar()` quando a senha confere mas a empresa do
    usuário não está com status 'ativa' (suspensa/cancelada). Sinalizada
    separadamente de "credenciais inválidas" de propósito: o chamador já
    provou que conhece a senha correta, então não há vazamento de
    informação em dizer explicitamente "sua empresa está suspensa" em vez
    do genérico "email ou senha inválidos" -- e isso evita o cliente
    achar que digitou a senha errada quando na verdade foi suspenso.
    """
    def __init__(self, status: str):
        self.status = status


async def autenticar(pool, email: str, senha: str):
    """
    Retorna um dict {"tipo": "usuario"|"superadmin", ...campos} se as
    credenciais baterem e (no caso de usuário de empresa) a empresa estiver
    ativa. Levanta `ContaEmpresaInativaError` se a senha confere mas a
    empresa está suspensa/cancelada. Retorna None para credenciais
    inválidas. Nunca levanta exceção por erro de credencial em si (só por
    erro de infraestrutura, ou pela condição de empresa inativa acima).

    Custo de bcrypt normalizado por tentativa mal-sucedida: SEMPRE roda
    exatamente duas checagens de senha (uma para `usuarios`, outra para
    `superadmins`, cada uma contra o hash real se a linha existir ou contra
    HASH_DUMMY se não existir) antes de devolver None. Rodar a checagem da
    tabela `superadmins` de forma condicional (só quando a linha existe,
    como numa versão anterior deste arquivo) criava um canal de tempo
    observável: um email de superadmin errado levava ~2x o tempo de um
    email comum ou inexistente (2 bcrypt.checkpw contra 1), o que permitia
    a um atacante remoto distinguir "este email é de superadmin" -- o alvo
    de maior valor do sistema -- só medindo a latência da resposta.

    Cada `verificar_senha` roda em `asyncio.to_thread`: bcrypt é
    propositalmente caro em CPU, e chamado direto aqui bloquearia o único
    event loop do processo pela duração inteira do hash -- travando
    QUALQUER outra requisição concorrente (de qualquer tenant) enquanto
    uma única tentativa de login é verificada. Mesmo padrão já usado para
    core.analisador_logs/core.firewall/core.reputacao (ver
    services/firewall.py, services/reputacao.py, api/v1/logs.py).
    """
    email = email.strip().lower()
    # As duas consultas (cada qual com seu hash real ou HASH_DUMMY) rodam
    # ANTES do bcrypt e a conexão é devolvida ao pool antes dele: o hash é
    # caro em CPU e não deve segurar uma conexão/transação do banco aberta.
    async with pool.superadmin_session() as sessao:
        usuario = await UsuarioRepositorio(sessao).buscar_ativo_para_login(email)
        superadmin = await SuperadminRepositorio(sessao).buscar_para_login(email)

    senha_valida_usuario = await asyncio.to_thread(
        verificar_senha, senha, usuario["senha_hash"] if usuario else HASH_DUMMY
    )
    if usuario and senha_valida_usuario:
        if usuario["empresa_status"] != "ativa":
            raise ContaEmpresaInativaError(usuario["empresa_status"])
        return {
            "tipo": "usuario",
            "id": usuario["id"],
            "empresa_id": usuario["empresa_id"],
            "email": usuario["email"],
            "papel": usuario["papel"],
            "token_version": usuario["token_version"],
            "mfa_habilitado": usuario["mfa_habilitado"],
        }

    senha_valida_superadmin = await asyncio.to_thread(
        verificar_senha, senha, superadmin["senha_hash"] if superadmin else HASH_DUMMY
    )
    if superadmin and senha_valida_superadmin:
        return {
            "tipo": "superadmin",
            "id": superadmin["id"],
            "empresa_id": None,
            "email": superadmin["email"],
            "papel": "superadmin",
            "token_version": superadmin["token_version"],
            "papel_saas": superadmin["papel"],
            "mfa_habilitado": superadmin["mfa_habilitado"],
        }

    return None
