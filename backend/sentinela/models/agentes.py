# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Modelos ORM -- agentes."""

import datetime
import uuid
from typing import ClassVar, Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    PrimaryKeyConstraint,
    Text,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from sentinela.database.base import Base


class Agente(Base):
    __tablename__ = "agentes"
    _sensiveis: ClassVar[frozenset[str]] = frozenset({"token_hash"})
    __table_args__ = (
        CheckConstraint("status = ANY (ARRAY['ativo'::text, 'revogado'::text])", name="agentes_status_check"),
        ForeignKeyConstraint(["criado_por_usuario_id"], ["usuarios.id"], name="agentes_criado_por_usuario_id_fkey"),
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], name="agentes_empresa_id_fkey"),
        PrimaryKeyConstraint("id", name="agentes_pkey"),
        UniqueConstraint("token_prefixo", name="agentes_token_prefixo_key"),
        Index("idx_agentes_empresa", "empresa_id"),
        Index("idx_agentes_empresa_hostname_ativo", "empresa_id", "hostname", postgresql_where="(status = 'ativo'::text)", unique=True),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, server_default=text("gen_random_uuid()"))
    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    hostname: Mapped[str] = mapped_column(Text, nullable=False)
    sistema_operacional: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("''::text"))
    versao_agente: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("''::text"))
    token_prefixo: Mapped[str] = mapped_column(Text, nullable=False)
    token_hash: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'ativo'::text"))
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    habilitado: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    criado_por_usuario_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid)
    ultimo_heartbeat_em: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(True))


class AgenteEnrollmentToken(Base):
    __tablename__ = "agentes_enrollment_tokens"
    _sensiveis: ClassVar[frozenset[str]] = frozenset({"token_hash"})
    __table_args__ = (
        CheckConstraint("max_usos IS NULL OR max_usos > 0", name="agentes_enrollment_tokens_max_usos_check"),
        CheckConstraint("status = ANY (ARRAY['ativo'::text, 'revogado'::text])", name="agentes_enrollment_tokens_status_check"),
        ForeignKeyConstraint(["criado_por_usuario_id"], ["usuarios.id"], name="agentes_enrollment_tokens_criado_por_usuario_id_fkey"),
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], name="agentes_enrollment_tokens_empresa_id_fkey"),
        PrimaryKeyConstraint("id", name="agentes_enrollment_tokens_pkey"),
        UniqueConstraint("token_prefixo", name="agentes_enrollment_tokens_token_prefixo_key"),
        Index("idx_agentes_enrollment_tokens_empresa", "empresa_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, server_default=text("gen_random_uuid()"))
    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    token_prefixo: Mapped[str] = mapped_column(Text, nullable=False)
    token_hash: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'ativo'::text"))
    expira_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False)
    usos: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    max_usos: Mapped[Optional[int]] = mapped_column(Integer)
    criado_por_usuario_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid)


class AgenteEvento(Base):
    __tablename__ = "agentes_eventos"
    __table_args__ = (
        CheckConstraint("tipo = ANY (ARRAY['heartbeat'::text, 'processo_suspeito'::text])", name="agentes_eventos_tipo_check"),
        ForeignKeyConstraint(["agente_id"], ["agentes.id"], name="agentes_eventos_agente_id_fkey"),
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], name="agentes_eventos_empresa_id_fkey"),
        PrimaryKeyConstraint("id", name="agentes_eventos_pkey"),
        Index("idx_agentes_eventos_agente", "agente_id", "recebido_em"),
        Index("idx_agentes_eventos_empresa_tempo", "empresa_id", "recebido_em"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    agente_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    tipo: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[object] = mapped_column(JSONB, nullable=False)
    recebido_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))


class EdrTelemetria(Base):
    __tablename__ = "edr_telemetria"
    __table_args__ = (
        ForeignKeyConstraint(["agente_id"], ["agentes.id"], ondelete="SET NULL", name="edr_telemetria_agente_id_fkey"),
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], ondelete="CASCADE", name="edr_telemetria_empresa_id_fkey"),
        PrimaryKeyConstraint("id", name="edr_telemetria_pkey"),
        Index("idx_edr_dedup", "empresa_id", "agente_id", "pid", "processo", "criado_em"),
        Index("idx_edr_hash", "empresa_id", "hash_sha256"),
        Index("idx_edr_tenant_time", "empresa_id", "criado_em"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    tipo: Mapped[str] = mapped_column(Text, nullable=False)
    severidade: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'INFO'::text"))
    detalhes: Mapped[object] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    agente_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid)
    hostname: Mapped[Optional[str]] = mapped_column(Text)
    processo: Mapped[Optional[str]] = mapped_column(Text)
    pid: Mapped[Optional[int]] = mapped_column(Integer)
    usuario: Mapped[Optional[str]] = mapped_column(Text)
    caminho: Mapped[Optional[str]] = mapped_column(Text)
    hash_sha256: Mapped[Optional[str]] = mapped_column(Text)
    parent_pid: Mapped[Optional[int]] = mapped_column(Integer)
    destino_ip: Mapped[Optional[object]] = mapped_column(INET)
    destino_porta: Mapped[Optional[int]] = mapped_column(Integer)
    protocolo: Mapped[Optional[str]] = mapped_column(Text)
