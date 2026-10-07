# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Acesso a dados de MFA/TOTP para as DUAS espécies de conta (usuário de
empresa e superadmin): mesma lógica, tabelas diferentes -- parametrizado por
`tipo` em vez de duplicar o repositório.
"""
from dataclasses import dataclass

from sqlalchemy import func, select, update

from sentinela.models import Superadmin, SuperadminMfaRecoveryCode, Usuario, UsuarioMfaRecoveryCode
from sentinela.repositories.base import RepositorioBase


@dataclass(frozen=True)
class _Espec:
    conta: type
    codigo: type
    fk_conta: str  # nome da coluna FK em *_mfa_recovery_codes


_ESPECS = {
    "usuario": _Espec(Usuario, UsuarioMfaRecoveryCode, "usuario_id"),
    "superadmin": _Espec(Superadmin, SuperadminMfaRecoveryCode, "superadmin_id"),
}


class MfaRepositorio(RepositorioBase):
    def __init__(self, sessao, tipo: str = "usuario"):
        super().__init__(sessao)
        self._e = _ESPECS[tipo]

    async def obter_status(self, conta_id):
        c = self._e.conta
        linha = (await self.sessao.execute(select(c.mfa_habilitado, c.mfa_confirmado_em).where(c.id == conta_id))).one_or_none()
        return dict(linha._mapping) if linha else None

    async def obter_segredo_e_status(self, conta_id):
        """(segredo_cifrado, habilitado) ou None se a conta não existe."""
        c = self._e.conta
        linha = (await self.sessao.execute(select(c.mfa_secret_cifrado, c.mfa_habilitado).where(c.id == conta_id))).one_or_none()
        return (linha.mfa_secret_cifrado, linha.mfa_habilitado) if linha else None

    async def salvar_segredo_pendente(self, conta_id, segredo_cifrado: bytes) -> None:
        c = self._e.conta
        await self.sessao.execute(
            update(c).where(c.id == conta_id).values(mfa_secret_cifrado=segredo_cifrado, mfa_confirmado_em=None)
            .execution_options(synchronize_session=False)
        )

    async def ativar(self, conta_id) -> None:
        c = self._e.conta
        await self.sessao.execute(
            update(c).where(c.id == conta_id).values(mfa_habilitado=True, mfa_confirmado_em=func.now())
            .execution_options(synchronize_session=False)
        )

    async def desativar(self, conta_id, empresa_id=None) -> bool:
        """Zera MFA da conta; com `empresa_id`, só se ela for dessa empresa. True se achou a conta."""
        c = self._e.conta
        stmt = update(c).where(c.id == conta_id)
        if empresa_id is not None:
            stmt = stmt.where(c.empresa_id == empresa_id)
        stmt = stmt.values(mfa_habilitado=False, mfa_secret_cifrado=None, mfa_confirmado_em=None).returning(c.id)
        return (await self.sessao.execute(stmt.execution_options(synchronize_session=False))).first() is not None

    async def invalidar_recovery_codes(self, conta_id) -> None:
        k = self._e.codigo
        fk = getattr(k, self._e.fk_conta)
        await self.sessao.execute(
            update(k).where(fk == conta_id, k.usado_em.is_(None), k.invalidado_em.is_(None))
            .values(invalidado_em=func.now()).execution_options(synchronize_session=False)
        )

    async def inserir_recovery_code(self, conta_id, codigo_hash: str, empresa_id=None) -> None:
        campos = {self._e.fk_conta: conta_id, "codigo_hash": codigo_hash}
        if empresa_id is not None:
            campos["empresa_id"] = empresa_id
        self.sessao.add(self._e.codigo(**campos))
        await self.sessao.flush()

    async def listar_recovery_elegiveis(self, conta_id) -> list[tuple]:
        """[(id, codigo_hash)] ainda não usados nem invalidados."""
        k = self._e.codigo
        fk = getattr(k, self._e.fk_conta)
        stmt = select(k.id, k.codigo_hash).where(fk == conta_id, k.usado_em.is_(None), k.invalidado_em.is_(None))
        return [(r.id, r.codigo_hash) for r in await self.sessao.execute(stmt)]

    async def consumir_recovery_code(self, codigo_id) -> bool:
        """Marca usado; False se outra requisição concorrente já o consumiu."""
        k = self._e.codigo
        stmt = (
            update(k).where(k.id == codigo_id, k.usado_em.is_(None)).values(usado_em=func.now())
            .returning(k.id).execution_options(synchronize_session=False)
        )
        return (await self.sessao.execute(stmt)).first() is not None
