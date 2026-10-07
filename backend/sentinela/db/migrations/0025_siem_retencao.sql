-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
-- Retenção do edital: 90 dias quentes + 275 dias frios = 365 dias totais.
CREATE TABLE IF NOT EXISTS eventos_siem_cold (
    id                  bigint PRIMARY KEY,
    empresa_id          uuid NOT NULL REFERENCES empresas(id),
    agente_id           uuid NULL REFERENCES agentes(id),
    timestamp           timestamptz NOT NULL,
    source              text NOT NULL,
    source_type         text NOT NULL,
    hostname            text,
    source_ip            inet,
    destination_ip       inet,
    source_port          integer,
    destination_port     integer,
    protocol             text,
    username             text,
    event_type           text NOT NULL,
    action               text,
    severity             text NOT NULL,
    message              text NOT NULL,
    raw_event            text NOT NULL,
    tags                 jsonb NOT NULL DEFAULT '[]'::jsonb,
    mitre_techniques     jsonb NOT NULL DEFAULT '[]'::jsonb,
    iocs                 jsonb NOT NULL DEFAULT '[]'::jsonb,
    criado_em            timestamptz NOT NULL,
    arquivado_em         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_eventos_siem_cold_empresa_timestamp
    ON eventos_siem_cold (empresa_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_eventos_siem_cold_source
    ON eventos_siem_cold (empresa_id, source_type, timestamp DESC);
ALTER TABLE eventos_siem_cold ENABLE ROW LEVEL SECURITY;
ALTER TABLE eventos_siem_cold FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS eventos_siem_cold_tenant ON eventos_siem_cold;
CREATE POLICY eventos_siem_cold_tenant ON eventos_siem_cold
    USING (empresa_id = current_setting('app.empresa_id', true)::uuid)
    WITH CHECK (empresa_id = current_setting('app.empresa_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON eventos_siem_cold TO app_tenant;
