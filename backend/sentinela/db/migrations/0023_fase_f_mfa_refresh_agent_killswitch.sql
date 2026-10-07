-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
-- Fase F: MFA para contas SaaS, refresh-token rotation e kill switch individual de Agent.
-- Aditiva sobre 0001-0022.

ALTER TABLE superadmins ADD COLUMN IF NOT EXISTS mfa_habilitado boolean NOT NULL DEFAULT false;
ALTER TABLE superadmins ADD COLUMN IF NOT EXISTS mfa_secret_cifrado bytea;
ALTER TABLE superadmins ADD COLUMN IF NOT EXISTS mfa_confirmado_em timestamptz;

CREATE TABLE IF NOT EXISTS superadmins_mfa_recovery_codes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    superadmin_id uuid NOT NULL REFERENCES superadmins(id) ON DELETE CASCADE,
    codigo_hash text NOT NULL,
    usado_em timestamptz,
    invalidado_em timestamptz,
    criado_em timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_superadmin_mfa_recovery_codes
    ON superadmins_mfa_recovery_codes (superadmin_id)
    WHERE usado_em IS NULL AND invalidado_em IS NULL;
GRANT SELECT, INSERT, UPDATE, DELETE ON superadmins_mfa_recovery_codes TO app_superadmin;

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    family_id uuid NOT NULL,
    token_hash text NOT NULL UNIQUE,
    conta_tipo text NOT NULL CHECK (conta_tipo IN ('usuario', 'superadmin')),
    conta_id uuid NOT NULL,
    token_version integer NOT NULL,
    expira_em timestamptz NOT NULL,
    usado_em timestamptz,
    revogado_em timestamptz,
    criado_em timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_conta ON refresh_tokens(conta_tipo, conta_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON refresh_tokens TO app_superadmin;

ALTER TABLE agentes ADD COLUMN IF NOT EXISTS habilitado boolean NOT NULL DEFAULT true;
