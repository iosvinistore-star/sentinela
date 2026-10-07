-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
-- Fase edital: event store SIEM multi-tenant.
CREATE TABLE IF NOT EXISTS eventos_siem (
    id                  bigserial PRIMARY KEY,
    empresa_id          uuid NOT NULL REFERENCES empresas(id),
    agente_id           uuid NULL REFERENCES agentes(id),
    timestamp           timestamptz NOT NULL,
    source              text NOT NULL,
    source_type         text NOT NULL,
    hostname            text,
    source_ip           inet,
    destination_ip      inet,
    source_port         integer,
    destination_port    integer,
    protocol            text,
    username            text,
    event_type          text NOT NULL,
    action              text,
    severity            text NOT NULL,
    message             text NOT NULL,
    raw_event           text NOT NULL,
    tags                jsonb NOT NULL DEFAULT '[]'::jsonb,
    mitre_techniques    jsonb NOT NULL DEFAULT '[]'::jsonb,
    iocs                jsonb NOT NULL DEFAULT '[]'::jsonb,
    criado_em           timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_eventos_siem_empresa_timestamp ON eventos_siem (empresa_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_eventos_siem_empresa_source ON eventos_siem (empresa_id, source_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_eventos_siem_empresa_severity ON eventos_siem (empresa_id, severity, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_eventos_siem_source_ip ON eventos_siem (empresa_id, source_ip, timestamp DESC);

ALTER TABLE eventos_siem ENABLE ROW LEVEL SECURITY;
ALTER TABLE eventos_siem FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='eventos_siem' AND policyname='eventos_siem_tenant') THEN
        CREATE POLICY eventos_siem_tenant ON eventos_siem
            USING (empresa_id = current_setting('app.empresa_id', true)::uuid)
            WITH CHECK (empresa_id = current_setting('app.empresa_id', true)::uuid);
    END IF;
END $$;

GRANT SELECT, INSERT, UPDATE, DELETE ON eventos_siem TO app_tenant;
GRANT USAGE, SELECT ON SEQUENCE eventos_siem_id_seq TO app_tenant;
