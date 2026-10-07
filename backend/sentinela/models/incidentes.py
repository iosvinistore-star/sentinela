# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Modelos ORM -- incidentes."""

import datetime
import uuid
from typing import ClassVar, Optional

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKeyConstraint, Index, Integer, PrimaryKeyConstraint, Text, UniqueConstraint, Uuid, text
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from sentinela.database.base import Base


class Incidente(Base):
    __tablename__ = "incidentes"
    __table_args__ = (
        CheckConstraint("origem = ANY (ARRAY['rede'::text, 'endpoint'::text])", name="incidentes_origem_check"),
        CheckConstraint("resolvido_por = ANY (ARRAY['humano'::text, 'sistema'::text])", name="incidentes_resolvido_por_check"),
        CheckConstraint("severidade = ANY (ARRAY['LOW'::text, 'MEDIUM'::text, 'HIGH'::text, 'CRITICAL'::text])", name="incidentes_severidade_check"),
        CheckConstraint("status = ANY (ARRAY['OPEN'::text, 'EM_ANDAMENTO'::text, 'RESOLVIDO'::text, 'FALSO_POSITIVO'::text])", name="incidentes_status_check"),
        ForeignKeyConstraint(["agente_id"], ["agentes.id"], name="incidentes_agente_id_fkey"),
        ForeignKeyConstraint(["em_andamento_por_usuario_id"], ["usuarios.id"], name="incidentes_em_andamento_por_usuario_id_fkey"),
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], name="incidentes_empresa_id_fkey"),
        PrimaryKeyConstraint("id", name="incidentes_pkey"),
        UniqueConstraint("empresa_id", "incident_id", name="incidentes_empresa_id_incident_id_key"),
        Index("idx_incidentes_agente_aberto", "empresa_id", "agente_id", "status", postgresql_where="(agente_id IS NOT NULL)"),
        Index("idx_incidentes_empresa", "empresa_id", "criado_em"),
        Index("idx_incidentes_empresa_criado", "empresa_id", "criado_em"),
        Index("idx_incidentes_empresa_severidade", "empresa_id", "severidade", "criado_em"),
        Index("idx_incidentes_empresa_status", "empresa_id", "status", "criado_em"),
        Index("idx_incidentes_origem", "empresa_id", "origem"),
        Index("idx_incidentes_status", "empresa_id", "status"),
        Index("idx_incidentes_status_atualizado", "status", "atualizado_em"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    incident_id: Mapped[str] = mapped_column(Text, nullable=False)
    ip: Mapped[object] = mapped_column(INET, nullable=False)
    severidade: Mapped[str] = mapped_column(Text, nullable=False)
    pontuacao_risco: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'OPEN'::text"))
    ataques: Mapped[object] = mapped_column(JSONB, nullable=False)
    observacoes: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("''::text"))
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    atualizado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    origem: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'rede'::text"))
    em_andamento_por_usuario_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid)
    resolvido_por: Mapped[Optional[str]] = mapped_column(Text)
    agente_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid)


class BloqueioFirewall(Base):
    __tablename__ = "bloqueios_firewall"
    __table_args__ = (
        CheckConstraint("status = ANY (ARRAY['ativo'::text, 'expirado'::text, 'removido'::text])", name="bloqueios_firewall_status_check"),
        ForeignKeyConstraint(["criado_por_usuario_id"], ["usuarios.id"], name="bloqueios_firewall_criado_por_usuario_id_fkey"),
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], name="bloqueios_firewall_empresa_id_fkey"),
        ForeignKeyConstraint(["incidente_id"], ["incidentes.id"], name="bloqueios_firewall_incidente_id_fkey"),
        PrimaryKeyConstraint("id", name="bloqueios_firewall_pkey"),
        Index("idx_bloqueios_ativo_unico", "empresa_id", "ip", postgresql_where="(status = 'ativo'::text)", unique=True),
        Index("idx_bloqueios_empresa", "empresa_id", "ip"),
        Index("idx_bloqueios_empresa_status", "empresa_id", "status", "bloqueado_em"),
        Index("idx_bloqueios_firewall_incidente", "incidente_id", postgresql_where="(incidente_id IS NOT NULL)"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    ip: Mapped[object] = mapped_column(INET, nullable=False)
    motivo: Mapped[str] = mapped_column(Text, nullable=False)
    origem: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'api'::text"))
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'ativo'::text"))
    bloqueado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    expira_em: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(True))
    removido_em: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(True))
    criado_por_usuario_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid)
    incidente_id: Mapped[Optional[int]] = mapped_column(BigInteger)


class IpProtegido(Base):
    __tablename__ = "ips_protegidos"
    __table_args__ = (
        CheckConstraint("origem = ANY (ARRAY['manual'::text, 'automatico'::text])", name="ips_protegidos_origem_check"),
        ForeignKeyConstraint(["criado_por_usuario_id"], ["usuarios.id"], name="ips_protegidos_criado_por_usuario_id_fkey"),
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], name="ips_protegidos_empresa_id_fkey"),
        PrimaryKeyConstraint("id", name="ips_protegidos_pkey"),
        UniqueConstraint("empresa_id", "ip", name="ips_protegidos_empresa_id_ip_key"),
        Index("idx_ips_protegidos_empresa", "empresa_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    ip: Mapped[object] = mapped_column(INET, nullable=False)
    motivo: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("''::text"))
    origem: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'manual'::text"))
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    criado_por_usuario_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid)


class ReputacaoCache(Base):
    __tablename__ = "reputacao_cache"
    __table_args__ = (
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], name="reputacao_cache_empresa_id_fkey"),
        PrimaryKeyConstraint("empresa_id", "ip", name="reputacao_cache_pkey"),
    )

    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    ip: Mapped[object] = mapped_column(INET, primary_key=True)
    dados: Mapped[object] = mapped_column(JSONB, nullable=False)
    classificacao: Mapped[str] = mapped_column(Text, nullable=False)
    consultado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))


class EventoSeguranca(Base):
    __tablename__ = "eventos_seguranca"
    __table_args__ = (
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], name="eventos_seguranca_empresa_id_fkey"),
        PrimaryKeyConstraint("id", name="eventos_seguranca_pkey"),
        Index("idx_eventos_seguranca_empresa_criado", "empresa_id", "criado_em"),
        Index("idx_eventos_seguranca_empresa_ip_data", "empresa_id", "ip", "data_evento"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    ip: Mapped[object] = mapped_column(INET, nullable=False)
    tipo_ataque: Mapped[str] = mapped_column(Text, nullable=False)
    fonte: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'log'::text"))
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    data_evento: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(True))
    status_http: Mapped[Optional[str]] = mapped_column(Text)
    requisicao: Mapped[Optional[str]] = mapped_column(Text)


class Auditoria(Base):
    __tablename__ = "auditoria"
    __table_args__ = (
        ForeignKeyConstraint(["ator_superadmin_id"], ["superadmins.id"], name="fk_auditoria_superadmin"),
        ForeignKeyConstraint(["ator_usuario_id"], ["usuarios.id"], name="auditoria_ator_usuario_id_fkey"),
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], name="auditoria_empresa_id_fkey"),
        PrimaryKeyConstraint("id", name="auditoria_pkey"),
        Index("idx_auditoria_empresa", "empresa_id", "criado_em"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    acao: Mapped[str] = mapped_column(Text, nullable=False)
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    empresa_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid)
    ator_usuario_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid)
    ator_superadmin_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid)
    detalhes: Mapped[Optional[object]] = mapped_column(JSONB)


class PushInscricao(Base):
    __tablename__ = "push_inscricoes"
    _sensiveis: ClassVar[frozenset[str]] = frozenset({"chave_auth", "chave_p256dh"})
    __table_args__ = (
        CheckConstraint(
            "usuario_id IS NOT NULL AND superadmin_id IS NULL AND empresa_id IS NOT NULL OR usuario_id IS NULL AND superadmin_id IS NOT NULL AND empresa_id IS NULL",
            name="push_dono_exclusivo",
        ),
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], ondelete="CASCADE", name="push_inscricoes_empresa_id_fkey"),
        ForeignKeyConstraint(["superadmin_id"], ["superadmins.id"], ondelete="CASCADE", name="push_inscricoes_superadmin_id_fkey"),
        ForeignKeyConstraint(["usuario_id"], ["usuarios.id"], ondelete="CASCADE", name="push_inscricoes_usuario_id_fkey"),
        PrimaryKeyConstraint("id", name="push_inscricoes_pkey"),
        Index("ix_push_empresa", "empresa_id", postgresql_where="(empresa_id IS NOT NULL)"),
        Index("ix_push_usuario", "usuario_id", postgresql_where="(usuario_id IS NOT NULL)"),
        Index("uq_push_endpoint", "endpoint", unique=True),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, server_default=text("gen_random_uuid()"))
    endpoint: Mapped[str] = mapped_column(Text, nullable=False)
    chave_p256dh: Mapped[str] = mapped_column(Text, nullable=False)
    chave_auth: Mapped[str] = mapped_column(Text, nullable=False)
    criada_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    falhas_seguidas: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    empresa_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid)
    usuario_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid)
    superadmin_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid)
    aparelho: Mapped[Optional[str]] = mapped_column(Text)
    usada_em: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(True))
