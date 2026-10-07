# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Envio de email -- hoje só usado pelo fluxo de "esqueci minha senha" (ver
services/redefinicao_senha.py). Uma implementação só por trás desta
função: SMTP genérico, configurado por variável de ambiente (mesmo padrão
de core/segredos.py) -- funciona com qualquer provedor que fale SMTP
(Gmail com senha de app, Outlook, Amazon SES, SendGrid, Mailgun etc.),
sem prender o projeto a um SDK de um fornecedor específico.

Se SMTP_HOST não estiver configurado, `enviar_email` não levanta exceção:
loga um aviso e devolve False. Mesmo espírito de ABUSEIPDB_API_KEY/
VT_API_KEY em reputacao.py -- uma integração externa não configurada
degrada uma funcionalidade specífica, não derruba o resto do sistema.
"""
import logging
import smtplib
from email.message import EmailMessage

from sentinela.core.segredos import obter_segredo

logger = logging.getLogger("sentinela.email")


def smtp_configurado() -> bool:
    return bool(obter_segredo("SMTP_HOST"))


def enviar_email(destinatario: str, assunto: str, corpo_texto: str) -> bool:
    host = obter_segredo("SMTP_HOST")
    if not host:
        logger.warning(
            "SMTP_HOST não configurado -- email para %s NÃO enviado (assunto: %r). "
            "Configure SMTP_HOST/SMTP_PORT/SMTP_USER/SMTP_PASSWORD/SMTP_FROM para habilitar o envio real.",
            destinatario, assunto,
        )
        return False

    porta = int(obter_segredo("SMTP_PORT", "587"))
    usuario = obter_segredo("SMTP_USER")
    senha = obter_segredo("SMTP_PASSWORD")
    remetente = obter_segredo("SMTP_FROM") or usuario or "sentinela-soc@localhost"
    usar_tls = (obter_segredo("SMTP_USE_TLS", "true") or "true").lower() != "false"

    msg = EmailMessage()
    msg["Subject"] = assunto
    msg["From"] = remetente
    msg["To"] = destinatario
    msg.set_content(corpo_texto)

    try:
        with smtplib.SMTP(host, porta, timeout=10) as servidor:
            if usar_tls:
                servidor.starttls()
            if usuario and senha:
                servidor.login(usuario, senha)
            servidor.send_message(msg)
        return True
    except Exception:
        logger.exception("Falha ao enviar email para %s", destinatario)
        return False
