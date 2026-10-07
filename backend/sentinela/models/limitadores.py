# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Modelos ORM -- limitadores."""

import datetime
from typing import Optional

from sqlalchemy import BigInteger, DateTime, Index, Integer, PrimaryKeyConstraint, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from sentinela.database.base import Base


class LimiteTentativa(Base):
    __tablename__ = "limite_tentativas"
    __table_args__ = (
        PrimaryKeyConstraint("chave", name="limite_tentativas_pkey"),
        Index("idx_limite_tentativas_limpeza", "janela_inicio", postgresql_where="(bloqueado_ate IS NULL)"),
    )

    chave: Mapped[str] = mapped_column(Text, primary_key=True)
    janela_inicio: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False)
    contador: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    bloqueado_ate: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(True))


class LimiteUploadEvento(Base):
    __tablename__ = "limite_upload_eventos"
    __table_args__ = (PrimaryKeyConstraint("id", name="limite_upload_eventos_pkey"), Index("idx_limite_upload_eventos_chave_tempo", "chave", "ocorrido_em"))

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    chave: Mapped[str] = mapped_column(Text, nullable=False)
    ocorrido_em: Mapped[datetime.datetime] = mapped_column(DateTime(True), nullable=False, server_default=text("now()"))
    bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
