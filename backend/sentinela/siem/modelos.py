# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator


class EventoSIEMEntrada(BaseModel):
    timestamp: datetime | None = None
    source: str = Field(min_length=1, max_length=255)
    source_type: str = Field(default="generic", max_length=80)
    hostname: str | None = Field(default=None, max_length=255)
    source_ip: str | None = Field(default=None, max_length=64)
    destination_ip: str | None = Field(default=None, max_length=64)
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, max_length=32)
    username: str | None = Field(default=None, max_length=255)
    event_type: str = Field(default="log", max_length=120)
    action: str | None = Field(default=None, max_length=120)
    severity: str = Field(default="INFO", max_length=32)
    message: str = Field(min_length=1, max_length=100_000)
    raw_event: str | None = Field(default=None, max_length=200_000)
    tags: list[str] = Field(default_factory=list, max_length=50)
    mitre_techniques: list[str] = Field(default_factory=list, max_length=50)
    iocs: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("source_ip", "destination_ip", mode="before")
    @classmethod
    def _validar_ip(cls, v: Any) -> str | None:
        # V8.2: antes qualquer string ia para o cast ::inet do INSERT em lote --
        # um único IP inválido derrubava o lote inteiro com 500 (e o Agent
        # retentava o mesmo lote venenoso). Agora é rejeitado na validação.
        if v is None or (isinstance(v, str) and not v.strip()):
            return None
        try:
            return str(ipaddress.ip_address(str(v).strip().split("%")[0]))
        except ValueError as exc:
            raise ValueError("endereço IP inválido") from exc

    @field_validator("timestamp")
    @classmethod
    def _timestamp_utc(cls, v: datetime | None) -> datetime | None:
        if v is not None and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v

    def normalizado(self, empresa_id: str, agente_id: str | None = None) -> dict[str, Any]:
        ts = self.timestamp or datetime.now(timezone.utc)
        return {
            "empresa_id": empresa_id,
            "agente_id": agente_id,
            "timestamp": ts,
            "source": self.source,
            "source_type": self.source_type,
            "hostname": self.hostname,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "username": self.username,
            "event_type": self.event_type,
            "action": self.action,
            "severity": self.severity.upper(),
            "message": self.message,
            "raw_event": self.raw_event or self.message,
            "tags": self.tags,
            "mitre_techniques": self.mitre_techniques,
            "iocs": self.iocs,
        }
