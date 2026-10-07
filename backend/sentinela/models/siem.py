# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Modelos ORM -- siem."""

import datetime
import uuid
from typing import Optional

from sqlalchemy import BigInteger, Boolean, DateTime, Double, ForeignKeyConstraint, Index, Integer, PrimaryKeyConstraint, Text, UniqueConstraint, Uuid, text
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from sentinela.database.base import Base


class EventoSiem(Base):
    __tablename__ = "eventos_siem"
    __table_args__ = (
        ForeignKeyConstraint(["agente_id"], ["agentes.id"], name="eventos_siem_agente_id_fkey"),
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], name="eventos_siem_empresa_id_fkey"),
        PrimaryKeyConstraint("id", name="eventos_siem_pkey"),
        Index("idx_eventos_siem_empresa_severity", "empresa_id", "severity", "timestamp"),
        Index("idx_eventos_siem_empresa_source", "empresa_id", "source_type", "timestamp"),
        Index("idx_eventos_siem_empresa_timestamp", "empresa_id", "timestamp"),
        Index("idx_eventos_siem_iocs_gin", "iocs", postgresql_using="gin"),
        Index("idx_eventos_siem_source_ip", "empresa_id", "source_ip", "timestamp"),
        Index("idx_eventos_siem_tags_gin", "tags", postgresql_using="gin"),
        Index("idx_eventos_siem_tenant_agente_ts", "empresa_id", "agente_id", "timestamp"),
        Index("idx_eventos_siem_tenant_hostname_ts", "empresa_id", "hostname", "timestamp", postgresql_where="(hostname IS NOT NULL)"),
        Index("idx_eventos_siem_tenant_source_type_ts", "empresa_id", "source_type", "timestamp"),
        Index("idx_eventos_siem_tenant_username_ts", "empresa_id", "username", "timestamp", postgresql_where="(username IS NOT NULL)"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    timestamp: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    source_type: Mapped[str] = mapped_column(Text, nullable=False)
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    raw_event: Mapped[str] = mapped_column(Text, nullable=False)
    tags: Mapped[object] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    mitre_techniques: Mapped[object] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    iocs: Mapped[object] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    agente_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid)
    hostname: Mapped[Optional[str]] = mapped_column(Text)
    source_ip: Mapped[Optional[object]] = mapped_column(INET)
    destination_ip: Mapped[Optional[object]] = mapped_column(INET)
    source_port: Mapped[Optional[int]] = mapped_column(Integer)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer)
    protocol: Mapped[Optional[str]] = mapped_column(Text)
    username: Mapped[Optional[str]] = mapped_column(Text)
    action: Mapped[Optional[str]] = mapped_column(Text)


class EventoSiemCold(Base):
    __tablename__ = "eventos_siem_cold"
    __table_args__ = (
        ForeignKeyConstraint(["agente_id"], ["agentes.id"], name="eventos_siem_cold_agente_id_fkey"),
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], name="eventos_siem_cold_empresa_id_fkey"),
        PrimaryKeyConstraint("id", name="eventos_siem_cold_pkey"),
        Index("idx_eventos_siem_cold_empresa_timestamp", "empresa_id", "timestamp"),
        Index("idx_eventos_siem_cold_source", "empresa_id", "source_type", "timestamp"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    timestamp: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    source_type: Mapped[str] = mapped_column(Text, nullable=False)
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    raw_event: Mapped[str] = mapped_column(Text, nullable=False)
    tags: Mapped[object] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    mitre_techniques: Mapped[object] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    iocs: Mapped[object] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False)
    arquivado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    agente_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid)
    hostname: Mapped[Optional[str]] = mapped_column(Text)
    source_ip: Mapped[Optional[object]] = mapped_column(INET)
    destination_ip: Mapped[Optional[object]] = mapped_column(INET)
    source_port: Mapped[Optional[int]] = mapped_column(Integer)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer)
    protocol: Mapped[Optional[str]] = mapped_column(Text)
    username: Mapped[Optional[str]] = mapped_column(Text)
    action: Mapped[Optional[str]] = mapped_column(Text)


class SiemFonte(Base):
    __tablename__ = "siem_fontes"
    __table_args__ = (
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], ondelete="CASCADE", name="siem_fontes_empresa_id_fkey"),
        PrimaryKeyConstraint("id", name="siem_fontes_pkey"),
        Index("idx_siem_fontes_tenant_tipo", "empresa_id", "tipo"),
        Index("uq_siem_fontes_tenant_nome", "empresa_id", text("lower(nome)"), unique=True),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    nome: Mapped[str] = mapped_column(Text, nullable=False)
    tipo: Mapped[str] = mapped_column(Text, nullable=False)
    configuracao: Mapped[object] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    ativo: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))


class SiemAgenteFonte(Base):
    __tablename__ = "siem_agente_fontes"
    __table_args__ = (
        ForeignKeyConstraint(["agente_id"], ["agentes.id"], ondelete="CASCADE", name="siem_agente_fontes_agente_id_fkey"),
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], ondelete="CASCADE", name="siem_agente_fontes_empresa_id_fkey"),
        PrimaryKeyConstraint("id", name="siem_agente_fontes_pkey"),
        UniqueConstraint("agente_id", "tipo", name="siem_agente_fontes_agente_id_tipo_key"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    agente_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    tipo: Mapped[str] = mapped_column(Text, nullable=False)
    total_eventos: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("0"))
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    ultimo_evento_em: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(True))


class SiemCorrelacao(Base):
    __tablename__ = "siem_correlacoes"
    __table_args__ = (
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], ondelete="CASCADE", name="siem_correlacoes_empresa_id_fkey"),
        ForeignKeyConstraint(["playbook_id"], ["soar_playbooks.id"], ondelete="SET NULL", name="siem_correlacoes_playbook_id_fkey"),
        PrimaryKeyConstraint("id", name="siem_correlacoes_pkey"),
        Index("idx_siem_correlacoes_tenant_data", "empresa_id", "criado_em"),
        Index("idx_siem_correlacoes_tenant_regra", "empresa_id", "regra", "criado_em"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    regra: Mapped[str] = mapped_column(Text, nullable=False)
    evento_ids: Mapped[list[int]] = mapped_column(ARRAY(BigInteger()), nullable=False, server_default=text("'{}'::bigint[]"))
    severidade: Mapped[str] = mapped_column(Text, nullable=False)
    score: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    cti_match: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    detalhes: Mapped[object] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    playbook_id: Mapped[Optional[int]] = mapped_column(BigInteger)


class SigmaRegra(Base):
    __tablename__ = "sigma_regras"
    __table_args__ = (
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], ondelete="CASCADE", name="sigma_regras_empresa_id_fkey"),
        PrimaryKeyConstraint("id", name="sigma_regras_pkey"),
        UniqueConstraint("empresa_id", "nome", name="sigma_regras_empresa_id_nome_key"),
        Index("idx_sigma_regras_tenant", "empresa_id", "ativo"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    nome: Mapped[str] = mapped_column(Text, nullable=False)
    titulo: Mapped[str] = mapped_column(Text, nullable=False)
    nivel: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'medium'::text"))
    logsource: Mapped[object] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    detection: Mapped[object] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    tags: Mapped[object] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    ativo: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    atualizado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))


class SigmaAlerta(Base):
    __tablename__ = "sigma_alertas"
    __table_args__ = (
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], ondelete="CASCADE", name="sigma_alertas_empresa_id_fkey"),
        ForeignKeyConstraint(["evento_id"], ["eventos_siem.id"], ondelete="SET NULL", name="sigma_alertas_evento_id_fkey"),
        ForeignKeyConstraint(["regra_id"], ["sigma_regras.id"], ondelete="CASCADE", name="sigma_alertas_regra_id_fkey"),
        PrimaryKeyConstraint("id", name="sigma_alertas_pkey"),
        Index("idx_sigma_alertas_tenant", "empresa_id", "criado_em"),
        Index("uq_sigma_alertas_regra_evento", "regra_id", "evento_id", unique=True),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    regra_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    severidade: Mapped[str] = mapped_column(Text, nullable=False)
    evidencias: Mapped[object] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    evento_id: Mapped[Optional[int]] = mapped_column(BigInteger)


class SoarPlaybook(Base):
    __tablename__ = "soar_playbooks"
    __table_args__ = (
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], ondelete="CASCADE", name="soar_playbooks_empresa_id_fkey"),
        PrimaryKeyConstraint("id", name="soar_playbooks_pkey"),
        Index("idx_soar_playbooks_tenant", "empresa_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    nome: Mapped[str] = mapped_column(Text, nullable=False)
    gatilho: Mapped[str] = mapped_column(Text, nullable=False)
    acoes: Mapped[object] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    ativo: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))


class SoarExecucao(Base):
    __tablename__ = "soar_execucoes"
    __table_args__ = (
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], ondelete="CASCADE", name="soar_execucoes_empresa_id_fkey"),
        ForeignKeyConstraint(["playbook_id"], ["soar_playbooks.id"], ondelete="CASCADE", name="soar_execucoes_playbook_id_fkey"),
        PrimaryKeyConstraint("id", name="soar_execucoes_pkey"),
        Index("idx_soar_execucoes_tenant", "empresa_id", "executado_em"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    playbook_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    resultado: Mapped[object] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    executado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    incidente_id: Mapped[Optional[int]] = mapped_column(BigInteger)


class CtiIndicador(Base):
    __tablename__ = "cti_indicadores"
    __table_args__ = (
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], ondelete="CASCADE", name="cti_indicadores_empresa_id_fkey"),
        PrimaryKeyConstraint("id", name="cti_indicadores_pkey"),
        UniqueConstraint("empresa_id", "stix_id", name="cti_indicadores_empresa_id_stix_id_key"),
        Index("idx_cti_indicadores_valor", "empresa_id", "valor"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    tipo: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'STIX'::text"))
    indicator_type: Mapped[str] = mapped_column(Text, nullable=False)
    valor: Mapped[str] = mapped_column(Text, nullable=False)
    labels: Mapped[object] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    raw: Mapped[object] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    stix_id: Mapped[Optional[str]] = mapped_column(Text)
    pattern: Mapped[Optional[str]] = mapped_column(Text)
    confidence: Mapped[Optional[int]] = mapped_column(Integer)
    valid_until: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(True))


class UebaPerfil(Base):
    __tablename__ = "ueba_perfis"
    __table_args__ = (
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], ondelete="CASCADE", name="ueba_perfis_empresa_id_fkey"),
        PrimaryKeyConstraint("id", name="ueba_perfis_pkey"),
        UniqueConstraint("empresa_id", "chave", "tipo", name="ueba_perfis_empresa_id_chave_tipo_key"),
        Index("idx_ueba_perfis_tenant", "empresa_id", "tipo", "atualizado_em"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    chave: Mapped[str] = mapped_column(Text, nullable=False)
    tipo: Mapped[str] = mapped_column(Text, nullable=False)
    janela_inicio: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False)
    janela_fim: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False)
    total_eventos: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("0"))
    usuarios_distintos: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("0"))
    ips_distintos: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("0"))
    media_horaria: Mapped[float] = mapped_column(Double(53), nullable=False, server_default=text("0"))
    desvio_horario: Mapped[float] = mapped_column(Double(53), nullable=False, server_default=text("0"))
    atualizado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))


class UebaAnomalia(Base):
    __tablename__ = "ueba_anomalias"
    __table_args__ = (
        ForeignKeyConstraint(["empresa_id"], ["empresas.id"], ondelete="CASCADE", name="ueba_anomalias_empresa_id_fkey"),
        ForeignKeyConstraint(["evento_id"], ["eventos_siem.id"], ondelete="SET NULL", name="ueba_anomalias_evento_id_fkey"),
        PrimaryKeyConstraint("id", name="ueba_anomalias_pkey"),
        Index("idx_ueba_anomalias_tenant", "empresa_id", "criado_em"),
        Index("uq_ueba_anomalias_entidade_hora", "empresa_id", "chave", "janela_hora", unique=True),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    empresa_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    chave: Mapped[str] = mapped_column(Text, nullable=False)
    score: Mapped[float] = mapped_column(Double(53), nullable=False)
    motivo: Mapped[str] = mapped_column(Text, nullable=False)
    evidencias: Mapped[object] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    criado_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    janela_hora: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False)
    evento_id: Mapped[Optional[int]] = mapped_column(BigInteger)
    tipo: Mapped[Optional[str]] = mapped_column(Text)
