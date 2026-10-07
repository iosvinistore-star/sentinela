# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Modelos ORM -- licenciamento."""

import datetime
import uuid
from typing import Optional

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKeyConstraint, Index, PrimaryKeyConstraint, Text, UniqueConstraint, Uuid, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from sentinela.database.base import Base


class Licenca(Base):
    __tablename__ = "licencas"
    __table_args__ = (
        CheckConstraint("status = ANY (ARRAY['ativa'::text, 'suspensa'::text, 'expirada'::text, 'revogada'::text])", name="licencas_status_check"),
        ForeignKeyConstraint(["criado_por_superadmin_id"], ["superadmins.id"], name="licencas_criado_por_superadmin_id_fkey"),
        ForeignKeyConstraint(["criado_por_usuario_id"], ["usuarios.id"], name="licencas_criado_por_usuario_id_fkey"),
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], name="licencas_empresa_id_fkey"),
        ForeignKeyConstraint(["plano_id"], ["planos.id"], name="licencas_plano_id_fkey"),
        PrimaryKeyConstraint("id", name="licencas_pkey"),
        UniqueConstraint("token_prefixo", name="licencas_token_prefixo_key"),
        Index("idx_licencas_empresa", "empresa_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, server_default=text("gen_random_uuid()"))
    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    plano_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    token_prefixo: Mapped[str] = mapped_column(Text, nullable=False)
    token_hash: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'ativa'::text"))
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    ativada_em: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(True))
    expira_em: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(True))
    criado_por_usuario_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid)
    criado_por_superadmin_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid)
    ultima_validacao_em: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(True))


class LicencaEndpoint(Base):
    __tablename__ = "licencas_endpoints"
    __table_args__ = (
        ForeignKeyConstraint(["agente_id"], ["agentes.id"], name="licencas_endpoints_agente_id_fkey"),
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], name="licencas_endpoints_empresa_id_fkey"),
        ForeignKeyConstraint(["licenca_id"], ["licencas.id"], name="licencas_endpoints_licenca_id_fkey"),
        PrimaryKeyConstraint("id", name="licencas_endpoints_pkey"),
        UniqueConstraint("agente_id", name="licencas_endpoints_agente_id_key"),
        Index("idx_licencas_endpoints_empresa", "empresa_id"),
        Index("idx_licencas_endpoints_ocupadas", "licenca_id", postgresql_where="(liberado_em IS NULL)"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, server_default=text("gen_random_uuid()"))
    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    licenca_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    agente_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    ocupado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    liberado_em: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(True))


class LicencaEvento(Base):
    __tablename__ = "licencas_eventos"
    __table_args__ = (
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], name="licencas_eventos_empresa_id_fkey"),
        ForeignKeyConstraint(["licenca_id"], ["licencas.id"], name="licencas_eventos_licenca_id_fkey"),
        PrimaryKeyConstraint("id", name="licencas_eventos_pkey"),
        Index("idx_licencas_eventos_empresa_tempo", "empresa_id", "criado_em"),
        Index("idx_licencas_eventos_licenca", "licenca_id", "criado_em"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    licenca_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    tipo: Mapped[str] = mapped_column(Text, nullable=False)
    detalhes: Mapped[object] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))


class LicencaNonceUsado(Base):
    __tablename__ = "licencas_nonces_usados"
    __table_args__ = (
        ForeignKeyConstraint(["licenca_id"], ["licencas.id"], ondelete="CASCADE", name="licencas_nonces_usados_licenca_id_fkey"),
        PrimaryKeyConstraint("id", name="licencas_nonces_usados_pkey"),
        UniqueConstraint("licenca_id", "nonce", name="licencas_nonces_usados_licenca_id_nonce_key"),
        Index("idx_licencas_nonces_usados_criado_em", "criado_em"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    licenca_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    nonce: Mapped[str] = mapped_column(Text, nullable=False)
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
