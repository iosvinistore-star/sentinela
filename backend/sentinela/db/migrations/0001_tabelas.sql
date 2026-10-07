-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
-- Sentinela SOC — schema multi-tenant base.
-- Convenção: tudo em português (mesmo estilo do resto do código), UUID para
-- tenants/usuários, bigserial para tabelas de alto volume (incidentes,
-- bloqueios, auditoria).

CREATE TABLE IF NOT EXISTS empresas (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    nome        text NOT NULL,
    plano       text NOT NULL DEFAULT 'padrao',
    status      text NOT NULL DEFAULT 'ativa' CHECK (status IN ('ativa','suspensa','cancelada')),
    criada_em   timestamptz NOT NULL DEFAULT now()
);

-- Desvio do documento de migração original: email é ÚNICO GLOBALMENTE (não
-- (empresa_id, email)) porque o formulário de login não pergunta "qual
-- empresa" antes da senha — ver auth/dependencies.py e o comentário no
-- plano de implementação.
CREATE TABLE IF NOT EXISTS usuarios (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    empresa_id    uuid NOT NULL REFERENCES empresas(id),
    email         text NOT NULL UNIQUE,
    papel         text NOT NULL CHECK (papel IN ('admin','analista')),
    senha_hash    text NOT NULL,
    ativo         boolean NOT NULL DEFAULT true,
    criado_em     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS incidentes (
    id                bigserial PRIMARY KEY,
    empresa_id        uuid NOT NULL REFERENCES empresas(id),
    incident_id       text NOT NULL,             -- formato mantido: INC-YYYYMMDD-<ip8>-HHMMSS
    ip                inet NOT NULL,
    severidade        text NOT NULL CHECK (severidade IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    pontuacao_risco   integer NOT NULL,
    status            text NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','EM_ANDAMENTO','RESOLVIDO','FALSO_POSITIVO')),
    ataques           jsonb NOT NULL,
    observacoes       text NOT NULL DEFAULT '',
    criado_em         timestamptz NOT NULL DEFAULT now(),
    atualizado_em     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (empresa_id, incident_id)
);

CREATE TABLE IF NOT EXISTS bloqueios_firewall (
    id                     bigserial PRIMARY KEY,
    empresa_id             uuid NOT NULL REFERENCES empresas(id),
    ip                     inet NOT NULL,
    motivo                 text NOT NULL,
    origem                 text NOT NULL DEFAULT 'api',
    status                 text NOT NULL DEFAULT 'ativo' CHECK (status IN ('ativo','expirado','removido')),
    bloqueado_em           timestamptz NOT NULL DEFAULT now(),
    expira_em              timestamptz,
    removido_em            timestamptz,
    criado_por_usuario_id  uuid REFERENCES usuarios(id)
);

CREATE TABLE IF NOT EXISTS auditoria (
    id                   bigserial PRIMARY KEY,
    empresa_id           uuid REFERENCES empresas(id),   -- nulo em ações globais de superadmin
    ator_usuario_id      uuid REFERENCES usuarios(id),
    ator_superadmin_id   uuid,                             -- FK adicionada depois que superadmins existir
    acao                 text NOT NULL,
    detalhes             jsonb,
    criado_em            timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS superadmins (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email        text UNIQUE NOT NULL,
    senha_hash   text NOT NULL,
    criado_em    timestamptz NOT NULL DEFAULT now()
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_auditoria_superadmin'
    ) THEN
        ALTER TABLE auditoria ADD CONSTRAINT fk_auditoria_superadmin
            FOREIGN KEY (ator_superadmin_id) REFERENCES superadmins(id);
    END IF;
END $$;

-- Cache é tenant-scoped para impedir que uma empresa consiga envenenar
-- ou sobrescrever a reputação usada por outra empresa. O rate-limit das
-- APIs externas continua protegido pela camada de cache/serviço.
CREATE TABLE IF NOT EXISTS reputacao_cache (
    empresa_id      uuid NOT NULL REFERENCES empresas(id),
    ip              inet NOT NULL,
    dados           jsonb NOT NULL,
    classificacao   text NOT NULL,
    consultado_em   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (empresa_id, ip)
);
