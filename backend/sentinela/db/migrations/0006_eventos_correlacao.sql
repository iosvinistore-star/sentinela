-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
-- Memória comportamental persistente entre uploads/coletas.
CREATE TABLE IF NOT EXISTS eventos_seguranca (
    id bigserial PRIMARY KEY,
    empresa_id uuid NOT NULL REFERENCES empresas(id),
    ip inet NOT NULL,
    data_evento timestamptz,
    tipo_ataque text NOT NULL,
    status_http text,
    requisicao text,
    fonte text NOT NULL DEFAULT 'log',
    criado_em timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_eventos_seguranca_empresa_ip_data
    ON eventos_seguranca (empresa_id, ip, data_evento DESC);
CREATE INDEX IF NOT EXISTS idx_eventos_seguranca_empresa_criado
    ON eventos_seguranca (empresa_id, criado_em DESC);

ALTER TABLE eventos_seguranca ENABLE ROW LEVEL SECURITY;
ALTER TABLE eventos_seguranca FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS eventos_seguranca_tenant ON eventos_seguranca;
CREATE POLICY eventos_seguranca_tenant ON eventos_seguranca
    USING (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON eventos_seguranca TO app_tenant;
GRANT USAGE, SELECT ON SEQUENCE eventos_seguranca_id_seq TO app_tenant;
GRANT SELECT, INSERT, UPDATE, DELETE ON eventos_seguranca TO app_superadmin;
GRANT USAGE, SELECT ON SEQUENCE eventos_seguranca_id_seq TO app_superadmin;
