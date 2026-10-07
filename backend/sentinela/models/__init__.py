# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Modelos ORM (um módulo por domínio). Importar este pacote registra todas as tabelas em Base.metadata."""

from sentinela.models.tenancy import Empresa, Plano, Usuario, Superadmin, RefreshToken, UsuarioMfaRecoveryCode, SuperadminMfaRecoveryCode, RedefinicaoSenha
from sentinela.models.licenciamento import Licenca, LicencaEndpoint, LicencaEvento, LicencaNonceUsado
from sentinela.models.agentes import Agente, AgenteEnrollmentToken, AgenteEvento, EdrTelemetria
from sentinela.models.incidentes import Incidente, BloqueioFirewall, IpProtegido, ReputacaoCache, EventoSeguranca, Auditoria, PushInscricao
from sentinela.models.siem import (
    EventoSiem,
    EventoSiemCold,
    SiemFonte,
    SiemAgenteFonte,
    SiemCorrelacao,
    SigmaRegra,
    SigmaAlerta,
    SoarPlaybook,
    SoarExecucao,
    CtiIndicador,
    UebaPerfil,
    UebaAnomalia,
)
from sentinela.models.limitadores import LimiteTentativa, LimiteUploadEvento

__all__ = [
    "Empresa",
    "Plano",
    "Usuario",
    "Superadmin",
    "RefreshToken",
    "UsuarioMfaRecoveryCode",
    "SuperadminMfaRecoveryCode",
    "RedefinicaoSenha",
    "Licenca",
    "LicencaEndpoint",
    "LicencaEvento",
    "LicencaNonceUsado",
    "Agente",
    "AgenteEnrollmentToken",
    "AgenteEvento",
    "EdrTelemetria",
    "Incidente",
    "BloqueioFirewall",
    "IpProtegido",
    "ReputacaoCache",
    "EventoSeguranca",
    "Auditoria",
    "PushInscricao",
    "EventoSiem",
    "EventoSiemCold",
    "SiemFonte",
    "SiemAgenteFonte",
    "SiemCorrelacao",
    "SigmaRegra",
    "SigmaAlerta",
    "SoarPlaybook",
    "SoarExecucao",
    "CtiIndicador",
    "UebaPerfil",
    "UebaAnomalia",
    "LimiteTentativa",
    "LimiteUploadEvento",
]
