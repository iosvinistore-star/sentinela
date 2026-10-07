# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Configuração central da aplicação. Lê tudo via
`sentinela.core.segredos.obter_segredo` (a mesma abstração que já existia
para DASHBOARD_SENHA/ABUSEIPDB_API_KEY/VT_API_KEY) para que trocar a fonte
de segredos (variável de ambiente -> Vault/Secrets Manager) no futuro seja
só trocar o provedor ativo, sem tocar em mais nada.
"""
import os
from dataclasses import dataclass, field

from sentinela.core.segredos import obter_segredo


def _obrigatorio(nome, ambiente):
    valor = obter_segredo(nome)
    if not valor:
        raise RuntimeError(
            f"{nome} não configurado (obrigatório em ambiente={ambiente}). "
            f"Defina a variável de ambiente {nome}."
        )
    return valor


@dataclass
class Settings:
    env: str = field(default_factory=lambda: obter_segredo("ENV", "development"))
    # "true"/"false" força o atributo Secure dos cookies de sessão; vazio = segue
    # o modo (Secure em produção). Existe para instalações em produção SEM HTTPS
    # (acesso por http://IP interno): o navegador descarta cookie Secure recebido
    # por HTTP fora de localhost, e o login simplesmente não funcionaria.
    cookie_seguro_forcado: str = field(default_factory=lambda: obter_segredo("SENTINELA_COOKIE_SEGURO", ""))
    # Token de PRIMEIRO ACESSO (ver api/v1/setup.py). O instalador sorteia e
    # imprime; sem ele, a criação da conta de gestão pelo navegador só é
    # aceita a partir da própria máquina (loopback). Vazio = só loopback.
    setup_token: str = field(default_factory=lambda: obter_segredo("SENTINELA_SETUP_TOKEN", ""))
    # Notificação de alerta no celular (Web Push -- ver services/push.py).
    # Par de chaves ESTÁVEL: trocá-lo invalida, em silêncio, todas as
    # inscrições já feitas nos aparelhos. Vazio = notificação desligada,
    # o resto do produto funciona igual.
    vapid_public_key: str = field(default_factory=lambda: obter_segredo("SENTINELA_VAPID_PUBLIC_KEY", ""))
    vapid_private_key: str = field(default_factory=lambda: obter_segredo("SENTINELA_VAPID_PRIVATE_KEY", ""))
    # Identifica o responsável pelo servidor para o serviço de push, que
    # usa isso para avisar sobre problemas de entrega. mailto: ou https:.
    vapid_subject: str = field(
        default_factory=lambda: obter_segredo("SENTINELA_VAPID_SUBJECT", "mailto:suporte@sentinela.local"),
    )
    database_url: str = field(default_factory=lambda: obter_segredo("DATABASE_URL", ""))
    database_url_admin: str = field(default_factory=lambda: obter_segredo("DATABASE_URL_ADMIN", ""))
    jwt_secret: str = field(default_factory=lambda: obter_segredo("JWT_SECRET", ""))
    jwt_algoritmo: str = "HS256"
    # Fase C (MFA/TOTP) -- chave de cifragem SIMÉTRICA do segredo TOTP em
    # repouso (auth/mfa.py, Fernet). Deliberadamente uma chave PRÓPRIA, nunca
    # `jwt_secret`: são dois segredos com blast radius diferente (JWT_SECRET
    # vazado permite forjar QUALQUER sessão; esta chave vazada só permite
    # decifrar segredos TOTP já roubados de outra forma -- reusar a mesma
    # chave para os dois papéis juntaria dois incidentes de segurança
    # separados num só). Precisa ser uma chave Fernet válida (32 bytes
    # url-safe base64 -- `Fernet.generate_key()`), validada em `validar()`.
    mfa_encryption_key: str = field(default_factory=lambda: obter_segredo("SENTINELA_MFA_ENCRYPTION_KEY", ""))
    # Correção de bug encontrado em revisão crítica (2026-09, achado 5):
    # estes três campos usavam `int(os.environ.get(...))` DIRETO como
    # default do dataclass -- uma expressão avaliada UMA VEZ, no momento em
    # que o CORPO DA CLASSE é executado (import do módulo), não a cada
    # `Settings()` instanciado. Todo outro campo desta classe usa
    # `default_factory=lambda: obter_segredo(...)` (reavaliado a cada
    # instanciação, e através do provedor de segredos trocável -- ver
    # core/segredos.py), então este era o único canto que quebrava o
    # contrato "sempre dinâmico" do módulo (docstring do topo do arquivo):
    # um teste que muda a variável de ambiente e cria um `Settings()` novo
    # (padrão usado em toda a suíte, ver tests/api/conftest_api.py) nunca
    # via a mudança nestes três campos especificamente -- eles ficavam
    # travados no valor lido da PRIMEIRA vez que `sentinela.config` foi
    # importado no processo. Latente/sem impacto ao vivo até agora porque
    # nenhum teste tentou variar estes três especificamente, mas é uma
    # inconsistência real do design.
    sessao_horas: int = field(default_factory=lambda: int(obter_segredo("SENTINELA_SESSAO_HORAS", "12")))
    reputacao_cache_ttl_horas: int = field(
        default_factory=lambda: int(obter_segredo("SENTINELA_REPUTACAO_TTL_HORAS", "24"))
    )
    cors_dev_origin: str = field(default_factory=lambda: obter_segredo("SENTINELA_DEV_CORS_ORIGIN", "http://localhost:5173"))
    # URL pública fixa (ex.: "https://soc.suaempresa.com", sem barra no
    # final) usada para montar links absolutos em e-mails (hoje só o de
    # redefinição de senha, ver services/redefinicao_senha.py). Sem isso, o
    # código caía de volta em `request.base_url` -- que o Starlette deriva
    # do cabeçalho HTTP `Host`, controlado pelo CLIENTE, não pelo servidor.
    # Um atacante não-autenticado que chamasse `/esqueci-senha` com um
    # `Host` forjado conseguia fazer o Sentinela mandar, para a vítima real,
    # um e-mail LEGÍTIMO (remetente correto) com o link de redefinição
    # apontando para um domínio do próprio atacante -- account takeover via
    # phishing, com o token de alta entropia sendo entregue ao atacante se a
    # vítima clicasse. Ver TrustedHostMiddleware (main.py) para a segunda
    # camada: mesmo sem configurar isto, ALLOWED_HOSTS pelo menos restringe
    # quais valores de Host a aplicação aceita processar.
    url_base_publica: str = field(default_factory=lambda: obter_segredo("SENTINELA_URL_BASE_PUBLICA", ""))
    # Lista de hostnames aceitos no cabeçalho Host, separados por vírgula
    # (ex.: "soc.suaempresa.com,localhost"). Vazio = TrustedHostMiddleware
    # não é ativado (comportamento permissivo de hoje, preservado para não
    # quebrar dev/testes que não configuram isto).
    allowed_hosts: str = field(default_factory=lambda: obter_segredo("SENTINELA_ALLOWED_HOSTS", ""))
    # Lista de IPs de proxy confiáveis, separados por vírgula (ex.: o IP
    # interno do load balancer/reverse proxy na frente do uvicorn). Vazio =
    # comportamento de sempre (X-Forwarded-For é ignorado, o limitador de
    # força bruta usa só a conexão TCP direta) -- ver
    # util.obter_ip_cliente para o porquê de isso ser opt-in: confiar no
    # header sem uma lista explícita de quem tem permissão de escrevê-lo
    # permite qualquer requisição forjar seu próprio "IP", zerando o rate
    # limit de login a cada tentativa.
    proxies_confiaveis: str = field(default_factory=lambda: obter_segredo("SENTINELA_PROXIES_CONFIAVEIS", ""))
    # Teto GLOBAL de tamanho de corpo de requisição, aplicado por
    # web/limite_corpo.py ANTES de qualquer parsing de rota (inclusive o
    # multipart de upload de log) -- ver o docstring daquele módulo para o
    # porquê disso ser necessário além do MAX_LOG_UPLOAD_BYTES já existente
    # em api/v1/logs.py. Default (12 MB) cobre o maior corpo legítimo hoje
    # (upload de log, 10 MB) com margem para overhead de multipart.
    max_corpo_requisicao_bytes: int = field(
        default_factory=lambda: int(os.environ.get("SENTINELA_MAX_CORPO_BYTES", str(12 * 1024 * 1024)))
    )
    # Kill-switch GLOBAL de automação do firewall (item 8 do plano de
    # endurecimento pós-auditoria) -- desligar isto força TODO bloqueio
    # automático (resposta a incidente, disparado por upload de log) a
    # virar dry-run, em QUALQUER tenant, independente do `modo_firewall`
    # de cada empresa (ver migrations/0012_...sql). Deliberadamente uma
    # variável de ambiente, não uma linha no Postgres: um botão de
    # emergência não deveria depender do banco estar saudável para
    # funcionar -- só um redeploy/restart muda isto, o que é exatamente a
    # garantia que se quer de um kill-switch (nada em tempo de execução,
    # nem um bug na aplicação, consegue religar sozinho). Não afeta o
    # bloqueio MANUAL feito por um admin via POST /firewall/bloqueios --
    # esse continua uma ação humana explícita, sempre disponível.
    firewall_automacao_habilitada: bool = field(
        default_factory=lambda: obter_segredo("SENTINELA_FIREWALL_AUTOMACAO_HABILITADA", "true").strip().lower()
        not in ("false", "0", "nao", "não")
    )
    # Intervalo (segundos) do ciclo autônomo em background (ver
    # services/automacao.py:rodar_ciclo_autonomo_periodicamente, iniciado
    # no lifespan em main.py) -- reavalia autoajuste de modo_firewall e
    # auto-triagem de incidentes para cada tenant com a flag opt-in
    # correspondente ligada (migrations/0014_...sql). Default 15min: rápido
    # o bastante para não deixar incidente parado dias esperando o próximo
    # ciclo, devagar o bastante para não sobrecarregar o Postgres com
    # varreduras cross-tenant repetidas.
    ciclo_autonomo_intervalo_segundos: int = field(
        default_factory=lambda: int(obter_segredo("SENTINELA_CICLO_AUTONOMO_INTERVALO_SEGUNDOS", "900"))
    )
    siem_hot_days: int = field(default_factory=lambda: int(obter_segredo("SENTINELA_SIEM_HOT_DAYS", "90")))
    siem_cold_days: int = field(default_factory=lambda: int(obter_segredo("SENTINELA_SIEM_COLD_DAYS", "365")))
    siem_retencao_intervalo_horas: int = field(default_factory=lambda: int(obter_segredo("SENTINELA_SIEM_RETENCAO_INTERVALO_HORAS", "24")))
    # Note: a whitelist de IPs/CIDRs protegidos contra bloqueio (item 9 do
    # plano de endurecimento, "whitelist que a automação nunca pode
    # remover/burlar") é lida DIRETO por core/firewall.py a partir de
    # SENTINELA_FIREWALL_WHITELIST_PROTEGIDA, não por esta classe -- ver o
    # comentário lá para o porquê disso ser a defesa de verdade.
    #
    # Fase E / E2 (ver ARQUITETURA_OBSERVABILIDADE.md §1.7) -- lidos e
    # aplicados em main.py:criar_app via core/logging_config.py, ANTES
    # até de validar() rodar (um valor inválido derruba a aplicação na
    # construção do FastAPI(), não na primeira requisição).
    log_nivel: str = field(default_factory=lambda: obter_segredo("SENTINELA_LOG_NIVEL", "INFO"))
    # Sem default condicionado a ENV de propósito -- ver o comentário de
    # validar() sobre JWT_SECRET para o motivo de este projeto evitar
    # comportamento que muda sozinho conforme o ambiente. "json" sempre,
    # a menos que alguém configure "texto" explicitamente (útil só para
    # legibilidade num terminal de desenvolvimento local).
    log_formato: str = field(default_factory=lambda: obter_segredo("SENTINELA_LOG_FORMATO", "json"))
    # Fase E / E1 (ver ARQUITETURA_OBSERVABILIDADE.md §2.4) -- vazio (default)
    # = /metrics nem existe operacionalmente (mesmo padrão de feature-flag
    # de agentes_endpoint_habilitado); configurado = /metrics exige o header
    # `X-Metrics-Token` com este valor exato. Não é PII nem segredo de
    # aplicação (só volume/latência por rota), mas não deveria ficar aberto
    # sem nenhuma barreira num serviço multi-tenant exposto à internet.
    metrics_token: str = field(default_factory=lambda: obter_segredo("SENTINELA_METRICS_TOKEN", ""))

    @property
    def producao(self) -> bool:
        return self.env == "production"

    @property
    def cookie_seguro(self) -> bool:
        valor = (self.cookie_seguro_forcado or "").strip().lower()
        if valor in {"true", "1", "sim"}:
            return True
        if valor in {"false", "0", "nao", "não"}:
            return False
        return self.producao

    def validar(self):
        """Falha rápido na inicialização, não na primeira requisição, se a
        configuração obrigatória estiver faltando.

        JWT_SECRET é exigido em QUALQUER ambiente, não só quando
        ENV=production -- um valor não configurado (`""`) ainda seria uma
        chave HMAC válida para jwt.encode/jwt.decode (HS256 aceita chave
        vazia), então antes desta correção qualquer ambiente cujo ENV não
        fosse literalmente "production" (staging esquecido, homologação
        exposta, ENV não definido) emitia e aceitava sessões assinadas com
        segredo vazio -- ou seja, forjáveis por qualquer pessoa que soubesse
        o algoritmo (público). Não existe cenário legítimo para rodar com
        JWT_SECRET vazio fora de um teste automatizado, que já define a
        variável explicitamente (ver tests/api/conftest_api.py).

        `url_base_publica` só é exigida em produção (não em dev/teste, onde
        `request.base_url` local é inofensivo) -- ver o comentário do campo
        acima para o porquê de não confiar no Host em produção."""
        if not self.database_url:
            raise RuntimeError("DATABASE_URL não configurado.")
        if not self.jwt_secret:
            raise RuntimeError(
                "JWT_SECRET não configurado. Obrigatório em qualquer ambiente -- "
                "gere um valor longo e aleatório, ex.: `openssl rand -hex 32`."
            )
        if not self.mfa_encryption_key:
            raise RuntimeError(
                "SENTINELA_MFA_ENCRYPTION_KEY não configurado. Obrigatório em qualquer "
                "ambiente -- gere com: python -c \"from cryptography.fernet import Fernet; "
                'print(Fernet.generate_key().decode())"'
            )
        try:
            from cryptography.fernet import Fernet

            Fernet(self.mfa_encryption_key.encode("utf-8"))
        except Exception as exc:
            raise RuntimeError(
                "SENTINELA_MFA_ENCRYPTION_KEY inválido -- precisa ser uma chave Fernet "
                "(32 bytes url-safe base64). Gere com: python -c \"from cryptography.fernet "
                'import Fernet; print(Fernet.generate_key().decode())"'
            ) from exc
        if self.producao and not self.url_base_publica:
            raise RuntimeError(
                "SENTINELA_URL_BASE_PUBLICA não configurado. Obrigatório em produção -- "
                "sem isso, links de e-mail (ex.: redefinição de senha) são montados a "
                "partir do cabeçalho Host, que o cliente controla (host-header poisoning)."
            )
        # `allowed_hosts` era só OPCIONAL (ver comentário no campo acima) --
        # em dev/teste isso preserva o comportamento permissivo de sempre,
        # mas em produção deixar o TrustedHostMiddleware desativado por
        # omissão é o tipo de coisa que não deveria depender de alguém
        # lembrar de preencher uma variável de ambiente. Sem
        # TrustedHostMiddleware, QUALQUER valor de cabeçalho Host é aceito
        # e `Request.base_url`/`Request.url` (usados por qualquer rota
        # futura que ainda não passe por SENTINELA_URL_BASE_PUBLICA) saem
        # diretamente dele.
        if self.producao and not self.allowed_hosts.strip():
            raise RuntimeError(
                "SENTINELA_ALLOWED_HOSTS não configurado. Obrigatório em produção -- "
                "sem isso, o TrustedHostMiddleware fica desativado e a aplicação aceita "
                "qualquer valor no cabeçalho Host. Defina os hostnames aceitos, separados "
                "por vírgula (ex.: SENTINELA_ALLOWED_HOSTS=soc.suaempresa.com)."
            )


def carregar_settings() -> Settings:
    return Settings()
