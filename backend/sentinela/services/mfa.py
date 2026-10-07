# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Fase C -- persistência e regras de negócio de MFA/TOTP (C6/C7/C8).

Este módulo assume que quem chama já tem uma conexão RLS-scoped válida
(tenant-scoped, `conexao_tenant`) -- MFA administrativo (`resetar_mfa_admin`)
depende da MESMA RLS para garantir que um COMPANY_ADMIN só reseta MFA de um
usuário da PRÓPRIA empresa (a query nem precisa filtrar `empresa_id`
explicitamente por causa disso -- mesmo padrão que `services/usuarios.py`
já documenta).

Todas as funções aqui retornam dados já seguros para expor via API --
NUNCA o segredo TOTP em claro, nunca um recovery code depois do momento de
geração (C6/C7: nunca logar/reexibir segredo, TOTP, recovery code).
"""
from __future__ import annotations

from sentinela.auth import mfa as auth_mfa
from sentinela.repositories.mfa import MfaRepositorio
from sentinela.services import auditoria as servico_auditoria


class MfaJaHabilitadoError(Exception):
    """Levantada por `iniciar_configuracao` se o usuário já tem MFA ativo -- precisa desativar antes de reconfigurar."""


class MfaNaoConfiguradoError(Exception):
    """Levantada por `confirmar_configuracao` se não há um setup pendente (`iniciar_configuracao` nunca foi chamado, ou já expirou/foi limpo)."""


class CodigoInvalidoError(Exception):
    """Código TOTP (ou recovery code) não confere -- usada tanto no setup quanto no login e no reset."""


async def obter_status_mfa(sessao, usuario_id) -> dict:
    row = await MfaRepositorio(sessao).obter_status(usuario_id)
    if row is None:
        return {"mfa_habilitado": False, "mfa_confirmado_em": None}
    return {"mfa_habilitado": row["mfa_habilitado"], "mfa_confirmado_em": row["mfa_confirmado_em"]}


async def iniciar_configuracao(sessao, chave_fernet: str, usuario_id, email: str) -> dict:
    """
    Gera um segredo TOTP novo e grava CIFRADO em `usuarios.mfa_secret_cifrado`
    -- mas `mfa_habilitado` continua `false` até `confirmar_configuracao` sedar
    o código de verdade. Sobrescrever um setup pendente anterior (usuário que
    começou o setup, saiu da tela, e voltou) é seguro e intencional -- o
    segredo antigo nunca foi confirmado, então não protegia nada ainda.

    Levanta `MfaJaHabilitadoError` se o usuário já tem MFA ATIVO -- exige
    desativar explicitamente antes de reconfigurar (evita que alguém com uma
    sessão sequestrada troque o segredo de MFA de outra pessoa silenciosamente
    por baixo do MFA já habilitado).
    """
    repo = MfaRepositorio(sessao)
    estado = await repo.obter_segredo_e_status(usuario_id)
    if estado and estado[1]:
        raise MfaJaHabilitadoError()

    segredo = auth_mfa.gerar_segredo_totp()
    segredo_cifrado = auth_mfa.cifrar_segredo(segredo, chave_fernet)
    await repo.salvar_segredo_pendente(usuario_id, segredo_cifrado)
    return {
        "segredo": segredo,  # exibido uma vez, para digitação manual como alternativa ao QR
        "provisioning_uri": auth_mfa.gerar_uri_provisionamento(segredo, email),
    }


async def confirmar_configuracao(sessao, chave_fernet: str, empresa_id, usuario_id, codigo: str) -> list[str]:
    """
    Confirma o setup iniciado por `iniciar_configuracao`: decifra o segredo
    pendente, valida o código TOTP informado e só então ativa MFA de verdade
    (`mfa_habilitado = true`). Gera e retorna os recovery codes (C7) -- em
    CLARO, só nesta resposta; só o hash de cada um é persistido.

    Levanta `MfaNaoConfiguradoError` se não há segredo pendente, e
    `CodigoInvalidoError` se o código não confere (setup permanece pendente,
    não ativado -- o usuário pode tentar de novo).
    """
    repo = MfaRepositorio(sessao)
    estado = await repo.obter_segredo_e_status(usuario_id)
    if estado is None or estado[0] is None:
        raise MfaNaoConfiguradoError()
    secret_cifrado, habilitado = estado
    if habilitado:
        raise MfaJaHabilitadoError()
    segredo = auth_mfa.decifrar_segredo(secret_cifrado, chave_fernet)
    if not auth_mfa.verificar_codigo_totp(segredo, codigo):
        raise CodigoInvalidoError()

    codigos_novos = await _gerar_e_persistir_recovery_codes(sessao, empresa_id, usuario_id)
    await repo.ativar(usuario_id)
    await servico_auditoria.registrar_evento(
        sessao, empresa_id, "MFA_ENABLED", {"usuario_id": str(usuario_id)}, ator_usuario_id=usuario_id,
    )
    return codigos_novos


async def desativar(sessao, empresa_id, usuario_id, ator_usuario_id=None) -> None:
    """
    Desativa MFA e apaga o segredo cifrado e todos os recovery codes
    (invalidados, não deletados -- mantém rastro de auditoria de quantos
    existiam/foram usados). Quem chama (rota) já deve ter validado um fator
    (senha atual OU um código TOTP/recovery válido) ANTES de chamar isto --
    este módulo não repete essa validação para não acoplar a decisão de
    "qual fator exigir para desativar" a esta camada de persistência.
    """
    repo = MfaRepositorio(sessao)
    await repo.desativar(usuario_id)
    await repo.invalidar_recovery_codes(usuario_id)
    await servico_auditoria.registrar_evento(
        sessao, empresa_id, "MFA_DISABLED", {"usuario_id": str(usuario_id)}, ator_usuario_id=ator_usuario_id,
    )


async def verificar_no_login(sessao, chave_fernet: str, empresa_id, usuario_id, *, codigo: str | None = None,
                               recovery_code: str | None = None) -> bool:
    """
    Chamada pelo segundo passo do login (senha já validada, ver
    api/v1/auth.py:mfa_verify). Tenta primeiro `codigo` (TOTP) se informado,
    senão `recovery_code`. Audita MFA_FAILED em qualquer tentativa recusada
    e RECOVERY_CODE_USED quando um recovery code é aceito -- nunca loga o
    valor do código/segredo em si (C10), só o resultado e o usuário_id.

    Devolve True/False -- quem chama decide o que fazer com o resultado
    (a rota já aplica rate limiting ANTES de chegar aqui, ver
    auth/dependencies.py padrão de limitador_login para o mesmo raciocínio).
    """
    if codigo:
        estado = await MfaRepositorio(sessao).obter_segredo_e_status(usuario_id)
        if estado is None or estado[0] is None:
            ok = False
        else:
            segredo = auth_mfa.decifrar_segredo(estado[0], chave_fernet)
            ok = auth_mfa.verificar_codigo_totp(segredo, codigo)
        if not ok:
            await servico_auditoria.registrar_evento(
                sessao, empresa_id, "MFA_FAILED", {"usuario_id": str(usuario_id), "metodo": "totp"},
                ator_usuario_id=usuario_id,
            )
        return ok

    if recovery_code:
        return await _consumir_recovery_code(sessao, empresa_id, usuario_id, recovery_code)

    await servico_auditoria.registrar_evento(
        sessao, empresa_id, "MFA_FAILED", {"usuario_id": str(usuario_id), "metodo": "nenhum_informado"},
        ator_usuario_id=usuario_id,
    )
    return False


async def _consumir_recovery_code(sessao, empresa_id, usuario_id, recovery_code: str) -> bool:
    """
    C7: single-use -- um recovery code válido é marcado `usado_em` na MESMA
    query que o aceita (UPDATE ... WHERE usado_em IS NULL, ver abaixo), então
    duas tentativas concorrentes com o MESMO código nunca conseguem as duas
    "ganhar" (a segunda não encontra mais a linha elegível).

    Varre os candidatos AINDA elegíveis (não usados, não invalidados) e
    verifica o hash bcrypt de cada um -- não há como fazer isso com uma
    única query SQL (bcrypt não é indexável/comparável em SQL puro), mas o
    número de códigos ativos por usuário é pequeno (no máximo
    QUANTIDADE_RECOVERY_CODES, tipicamente 10), então o custo é aceitável.
    """
    repo = MfaRepositorio(sessao)
    for codigo_id, codigo_hash in await repo.listar_recovery_elegiveis(usuario_id):
        if auth_mfa.verificar_recovery_code(recovery_code, codigo_hash):
            if not await repo.consumir_recovery_code(codigo_id):
                continue
            await servico_auditoria.registrar_evento(
                sessao, empresa_id, "RECOVERY_CODE_USED", {"usuario_id": str(usuario_id)}, ator_usuario_id=usuario_id,
            )
            return True

    await servico_auditoria.registrar_evento(
        sessao, empresa_id, "MFA_FAILED", {"usuario_id": str(usuario_id), "metodo": "recovery_code"},
        ator_usuario_id=usuario_id,
    )
    return False


async def regenerar_recovery_codes(sessao, empresa_id, usuario_id) -> list[str]:
    """
    C7: "permitir regeneração controlada" -- invalida todos os códigos
    AINDA não usados/invalidados (os já usados continuam com `usado_em`
    preenchido, preservando o rastro de auditoria de quais foram consumidos
    e quando) e gera um conjunto novo completo. Quem chama (rota) já exige
    MFA habilitado e um fator de confirmação antes de chegar aqui -- mesmo
    raciocínio de `desativar`.
    """
    await MfaRepositorio(sessao).invalidar_recovery_codes(usuario_id)
    codigos_novos = await _gerar_e_persistir_recovery_codes(sessao, empresa_id, usuario_id)
    await servico_auditoria.registrar_evento(
        sessao, empresa_id, "RECOVERY_CODES_REGENERATED", {"usuario_id": str(usuario_id)}, ator_usuario_id=usuario_id,
    )
    return codigos_novos


async def resetar_mfa_admin(sessao, empresa_id, usuario_alvo_id, ator_usuario_id) -> None:
    """
    C8 -- reset administrativo de MFA (usuário perdeu o autenticador).
    Diferente de `desativar` (self-service, exige um fator do PRÓPRIO
    usuário): aqui quem desativa é OUTRA pessoa (um COMPANY_ADMIN da mesma
    empresa, ver `auth/rbac.py:PERM_MFA_RESET_OTHERS`), então:

      - a autorização (quem pode chamar isto) é decisão da ROTA
        (`exigir_permissao("mfa.reset_others")`), não deste módulo;
      - a RLS (`conexao_tenant`) já garante que `usuario_alvo_id` pertence
        à MESMA empresa de quem está chamando -- um UPDATE aqui simplesmente
        não encontra nenhuma linha se o alvo for de outro tenant;
      - o evento de auditoria (MFA_RESET) identifica TANTO o ator quanto o
        alvo -- nunca um reset "anônimo" (C8: "identificar quem realizou o
        reset" e "identificar o usuário afetado").

    Não há bypass silencioso possível: mesmo com a permissão, a ação SEMPRE
    gera o evento MFA_RESET abaixo, antes de qualquer outra coisa acontecer.
    """
    # `AND empresa_id = $2` é redundante com a RLS de `conexao_tenant` (que
    # já restringe toda query de app_tenant à empresa da sessão) -- mesma
    # defesa em profundidade documentada em services/usuarios.py:
    # atualizar_usuario, pelo mesmo motivo.
    repo = MfaRepositorio(sessao)
    if not await repo.desativar(usuario_alvo_id, empresa_id):
        raise MfaNaoConfiguradoError("usuário não encontrado nesta empresa")
    await repo.invalidar_recovery_codes(usuario_alvo_id)
    await servico_auditoria.registrar_evento(
        sessao, empresa_id, "MFA_RESET",
        {"usuario_alvo_id": str(usuario_alvo_id), "ator_usuario_id": str(ator_usuario_id)},
        ator_usuario_id=ator_usuario_id,
    )


async def _gerar_e_persistir_recovery_codes(sessao, empresa_id, usuario_id) -> list[str]:
    repo = MfaRepositorio(sessao)
    codigos = auth_mfa.gerar_recovery_codes()
    for codigo in codigos:
        await repo.inserir_recovery_code(usuario_id, auth_mfa.hash_recovery_code(codigo), empresa_id=empresa_id)
    return codigos


async def obter_status_mfa_superadmin(sessao, superadmin_id) -> dict:
    row = await MfaRepositorio(sessao, "superadmin").obter_status(superadmin_id)
    if row is None:
        return {"mfa_habilitado": False, "mfa_confirmado_em": None}
    return {"mfa_habilitado": row["mfa_habilitado"], "mfa_confirmado_em": row["mfa_confirmado_em"]}


async def iniciar_configuracao_superadmin(sessao, chave_fernet: str, superadmin_id, email: str) -> dict:
    repo = MfaRepositorio(sessao, "superadmin")
    estado = await repo.obter_segredo_e_status(superadmin_id)
    if estado and estado[1]:
        raise MfaJaHabilitadoError()
    segredo = auth_mfa.gerar_segredo_totp()
    await repo.salvar_segredo_pendente(superadmin_id, auth_mfa.cifrar_segredo(segredo, chave_fernet))
    return {"segredo": segredo, "provisioning_uri": auth_mfa.gerar_uri_provisionamento(segredo, email)}


async def confirmar_configuracao_superadmin(sessao, chave_fernet: str, superadmin_id, codigo: str) -> list[str]:
    repo = MfaRepositorio(sessao, "superadmin")
    estado = await repo.obter_segredo_e_status(superadmin_id)
    if estado is None or estado[0] is None:
        raise MfaNaoConfiguradoError()
    if estado[1]:
        raise MfaJaHabilitadoError()
    segredo = auth_mfa.decifrar_segredo(estado[0], chave_fernet)
    if not auth_mfa.verificar_codigo_totp(segredo, codigo):
        raise CodigoInvalidoError()
    codes = auth_mfa.gerar_recovery_codes()
    for code in codes:
        await repo.inserir_recovery_code(superadmin_id, auth_mfa.hash_recovery_code(code))
    await repo.ativar(superadmin_id)
    await servico_auditoria.registrar_evento(
        sessao, None, "MFA_ENABLED", {"superadmin_id": str(superadmin_id)}, ator_superadmin_id=superadmin_id
    )
    return codes


async def verificar_no_login_superadmin(
    sessao, chave_fernet: str, superadmin_id, *, codigo: str | None = None, recovery_code: str | None = None
) -> bool:
    repo = MfaRepositorio(sessao, "superadmin")
    if codigo:
        estado = await repo.obter_segredo_e_status(superadmin_id)
        ok = bool(
            estado and estado[0]
            and auth_mfa.verificar_codigo_totp(auth_mfa.decifrar_segredo(estado[0], chave_fernet), codigo)
        )
        if not ok:
            await servico_auditoria.registrar_evento(
                sessao, None, "MFA_FAILED", {"superadmin_id": str(superadmin_id), "metodo": "totp"},
                ator_superadmin_id=superadmin_id,
            )
        return ok
    if recovery_code:
        for codigo_id, codigo_hash in await repo.listar_recovery_elegiveis(superadmin_id):
            if auth_mfa.verificar_recovery_code(recovery_code, codigo_hash) and await repo.consumir_recovery_code(codigo_id):
                await servico_auditoria.registrar_evento(
                    sessao, None, "RECOVERY_CODE_USED", {"superadmin_id": str(superadmin_id)},
                    ator_superadmin_id=superadmin_id,
                )
                return True
    await servico_auditoria.registrar_evento(
        sessao, None, "MFA_FAILED",
        {"superadmin_id": str(superadmin_id), "metodo": "recovery_code" if recovery_code else "nenhum_informado"},
        ator_superadmin_id=superadmin_id,
    )
    return False


async def desativar_superadmin(sessao, superadmin_id, ator_superadmin_id) -> None:
    repo = MfaRepositorio(sessao, "superadmin")
    await repo.desativar(superadmin_id)
    await repo.invalidar_recovery_codes(superadmin_id)
    await servico_auditoria.registrar_evento(
        sessao, None, "MFA_DISABLED", {"superadmin_id": str(superadmin_id)}, ator_superadmin_id=ator_superadmin_id
    )
