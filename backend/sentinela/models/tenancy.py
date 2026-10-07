# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Modelos ORM -- tenancy."""

import datetime
import uuid
from typing import ClassVar, Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    PrimaryKeyConstraint,
    Text,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from sentinela.database.base import Base


class Empresa(Base):
    __tablename__ = "empresas"
    __table_args__ = (
        CheckConstraint(
            "modo_firewall = ANY (ARRAY['observacao'::text, 'dry_run'::text, 'manual'::text, 'automacao_controlada'::text, 'automacao_total'::text])",
            name="empresas_modo_firewall_check",
        ),
        CheckConstraint("status = ANY (ARRAY['ativa'::text, 'suspensa'::text, 'cancelada'::text])", name="empresas_status_check"),
        PrimaryKeyConstraint("id", name="empresas_pkey"),
        Index("uq_empresas_cnpj", "cnpj", postgresql_where="(cnpj IS NOT NULL)", unique=True),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, server_default=text("gen_random_uuid()"))
    nome: Mapped[str] = mapped_column(Text, nullable=False)
    plano: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'padrao'::text"))
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'ativa'::text"))
    criada_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    modo_firewall: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'automacao_controlada'::text"))
    modo_firewall_auto: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    auto_triagem_incidentes: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    agentes_endpoint_habilitado: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    cnpj: Mapped[Optional[str]] = mapped_column(Text)
    responsavel: Mapped[Optional[str]] = mapped_column(Text)
    email_contato: Mapped[Optional[str]] = mapped_column(Text)
    telefone: Mapped[Optional[str]] = mapped_column(Text)
    contrato_numero: Mapped[Optional[str]] = mapped_column(Text)
    contrato_vigencia: Mapped[Optional[datetime.date]] = mapped_column(Date)
    observacoes: Mapped[Optional[str]] = mapped_column(Text)


class Plano(Base):
    __tablename__ = "planos"
    __table_args__ = (
        CheckConstraint("max_endpoints >= 0", name="planos_max_endpoints_check"),
        PrimaryKeyConstraint("id", name="planos_pkey"),
        UniqueConstraint("codigo", name="planos_codigo_key"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, server_default=text("gen_random_uuid()"))
    codigo: Mapped[str] = mapped_column(Text, nullable=False)
    nome_exibicao: Mapped[str] = mapped_column(Text, nullable=False)
    max_endpoints: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    recursos: Mapped[object] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    ativo: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))


class Usuario(Base):
    __tablename__ = "usuarios"
    _sensiveis: ClassVar[frozenset[str]] = frozenset({"senha_hash", "mfa_secret_cifrado"})
    __table_args__ = (
        CheckConstraint("papel = ANY (ARRAY['admin'::text, 'analista'::text, 'viewer'::text])", name="usuarios_papel_check"),
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], name="usuarios_empresa_id_fkey"),
        PrimaryKeyConstraint("id", name="usuarios_pkey"),
        UniqueConstraint("email", name="usuarios_email_key"),
        Index("idx_usuarios_empresa", "empresa_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, server_default=text("gen_random_uuid()"))
    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    email: Mapped[str] = mapped_column(Text, nullable=False)
    papel: Mapped[str] = mapped_column(Text, nullable=False)
    senha_hash: Mapped[str] = mapped_column(Text, nullable=False)
    ativo: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    token_version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    mfa_habilitado: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    mfa_secret_cifrado: Mapped[Optional[bytes]] = mapped_column(LargeBinary)
    mfa_confirmado_em: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(True))


class Superadmin(Base):
    __tablename__ = "superadmins"
    _sensiveis: ClassVar[frozenset[str]] = frozenset({"senha_hash", "mfa_secret_cifrado"})
    __table_args__ = (
        CheckConstraint("papel = ANY (ARRAY['saas_owner'::text, 'saas_admin'::text])", name="superadmins_papel_check"),
        PrimaryKeyConstraint("id", name="superadmins_pkey"),
        UniqueConstraint("email", name="superadmins_email_key"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, server_default=text("gen_random_uuid()"))
    email: Mapped[str] = mapped_column(Text, nullable=False)
    senha_hash: Mapped[str] = mapped_column(Text, nullable=False)
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    token_version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    papel: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'saas_owner'::text"))
    mfa_habilitado: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    mfa_secret_cifrado: Mapped[Optional[bytes]] = mapped_column(LargeBinary)
    mfa_confirmado_em: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(True))


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    _sensiveis: ClassVar[frozenset[str]] = frozenset({"token_hash"})
    __table_args__ = (
        CheckConstraint("conta_tipo = ANY (ARRAY['usuario'::text, 'superadmin'::text])", name="refresh_tokens_conta_tipo_check"),
        PrimaryKeyConstraint("id", name="refresh_tokens_pkey"),
        UniqueConstraint("token_hash", name="refresh_tokens_token_hash_key"),
        Index("idx_refresh_tokens_conta", "conta_tipo", "conta_id"),
        Index("idx_refresh_tokens_family", "family_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, server_default=text("gen_random_uuid()"))
    family_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    token_hash: Mapped[str] = mapped_column(Text, nullable=False)
    conta_tipo: Mapped[str] = mapped_column(Text, nullable=False)
    conta_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    token_version: Mapped[int] = mapped_column(Integer, nullable=False)
    expira_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False)
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    usado_em: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(True))
    revogado_em: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(True))


class UsuarioMfaRecoveryCode(Base):
    __tablename__ = "usuarios_mfa_recovery_codes"
    _sensiveis: ClassVar[frozenset[str]] = frozenset({"codigo_hash"})
    __table_args__ = (
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], name="usuarios_mfa_recovery_codes_empresa_id_fkey"),
        ForeignKeyConstraint(["usuario_id"], ["usuarios.id"], ondelete="CASCADE", name="usuarios_mfa_recovery_codes_usuario_id_fkey"),
        PrimaryKeyConstraint("id", name="usuarios_mfa_recovery_codes_pkey"),
        Index("idx_mfa_recovery_codes_usuario", "usuario_id", postgresql_where="((usado_em IS NULL) AND (invalidado_em IS NULL))"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, server_default=text("gen_random_uuid()"))
    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    usuario_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    codigo_hash: Mapped[str] = mapped_column(Text, nullable=False)
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    usado_em: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(True))
    invalidado_em: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(True))


class SuperadminMfaRecoveryCode(Base):
    __tablename__ = "superadmins_mfa_recovery_codes"
    _sensiveis: ClassVar[frozenset[str]] = frozenset({"codigo_hash"})
    __table_args__ = (
        ForeignKeyConstraint(["superadmin_id"], ["superadmins.id"], ondelete="CASCADE", name="superadmins_mfa_recovery_codes_superadmin_id_fkey"),
        PrimaryKeyConstraint("id", name="superadmins_mfa_recovery_codes_pkey"),
        Index("idx_superadmin_mfa_recovery_codes", "superadmin_id", postgresql_where="((usado_em IS NULL) AND (invalidado_em IS NULL))"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, server_default=text("gen_random_uuid()"))
    superadmin_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    codigo_hash: Mapped[str] = mapped_column(Text, nullable=False)
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    usado_em: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(True))
    invalidado_em: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(True))


class RedefinicaoSenha(Base):
    __tablename__ = "redefinicoes_senha"
    _sensiveis: ClassVar[frozenset[str]] = frozenset({"token_hash"})
    __table_args__ = (
        ForeignKeyConstraint(["usuario_id"], ["usuarios.id"], ondelete="CASCADE", name="redefinicoes_senha_usuario_id_fkey"),
        PrimaryKeyConstraint("id", name="redefinicoes_senha_pkey"),
        UniqueConstraint("token_hash", name="redefinicoes_senha_token_hash_key"),
        Index("idx_redefinicoes_senha_usuario", "usuario_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, server_default=text("gen_random_uuid()"))
    usuario_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    token_hash: Mapped[str] = mapped_column(Text, nullable=False)
    expira_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False)
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    usado_em: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(True))
