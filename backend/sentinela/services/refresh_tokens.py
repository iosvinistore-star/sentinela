# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sentinela.auth.security import gerar_refresh_token, hash_refresh_token
from sentinela.repositories.refresh_tokens import RefreshTokenRepositorio

REFRESH_DIAS = 30


async def criar(sessao, conta_tipo: str, conta_id, token_version: int, family_id=None) -> tuple[str, uuid.UUID]:
    token = gerar_refresh_token()
    family_id = family_id or uuid.uuid4()
    await RefreshTokenRepositorio(sessao).inserir(
        family_id, hash_refresh_token(token), conta_tipo, conta_id, token_version,
        datetime.now(timezone.utc) + timedelta(days=REFRESH_DIAS),
    )
    return token, family_id


async def rotacionar(sessao, token: str):
    repo = RefreshTokenRepositorio(sessao)
    registro = await repo.obter_para_rotacao(hash_refresh_token(token))
    if registro is None:
        return None, "invalido"
    if registro.revogado_em is not None:
        return None, "revogado"
    if registro.usado_em is not None:
        await repo.revogar_familia(registro.family_id)
        # Reuso de refresh token é tratado como possível roubo da família:
        # invalida também as sessões de acesso emitidas para a conta.
        await repo.invalidar_sessoes_da_conta(registro.conta_tipo, registro.conta_id)
        return None, "replay"
    if registro.expira_em <= datetime.now(timezone.utc):
        return None, "expirado"
    await repo.marcar_usado(registro.id)
    novo, family_id = await criar(sessao, registro.conta_tipo, registro.conta_id, registro.token_version, registro.family_id)
    return {**registro.para_dict(), "novo_token": novo, "family_id": family_id}, None
