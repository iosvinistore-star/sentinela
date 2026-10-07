-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
CREATE TABLE IF NOT EXISTS siem_fontes (
  id BIGSERIAL PRIMARY KEY,
  empresa_id UUID NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
  nome TEXT NOT NULL,
  tipo TEXT NOT NULL,
  configuracao JSONB NOT NULL DEFAULT '{}'::jsonb,
  ativo BOOLEAN NOT NULL DEFAULT true,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_siem_fontes_tenant_tipo ON siem_fontes(empresa_id, tipo);
ALTER TABLE siem_fontes ENABLE ROW LEVEL SECURITY;
ALTER TABLE siem_fontes FORCE ROW LEVEL SECURITY;
CREATE POLICY siem_fontes_tenant ON siem_fontes USING (empresa_id = current_setting('app.empresa_id', true)::uuid) WITH CHECK (empresa_id = current_setting('app.empresa_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON siem_fontes TO app_tenant;
GRANT USAGE, SELECT ON SEQUENCE siem_fontes_id_seq TO app_tenant;

CREATE TABLE IF NOT EXISTS siem_correlacoes (
  id BIGSERIAL PRIMARY KEY,
  empresa_id UUID NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
  regra TEXT NOT NULL,
  evento_ids BIGINT[] NOT NULL DEFAULT '{}',
  severidade TEXT NOT NULL,
  score INTEGER NOT NULL DEFAULT 0,
  cti_match BOOLEAN NOT NULL DEFAULT false,
  playbook_id BIGINT REFERENCES soar_playbooks(id) ON DELETE SET NULL,
  detalhes JSONB NOT NULL DEFAULT '{}'::jsonb,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_siem_correlacoes_tenant_data ON siem_correlacoes(empresa_id, criado_em DESC);
ALTER TABLE siem_correlacoes ENABLE ROW LEVEL SECURITY;
ALTER TABLE siem_correlacoes FORCE ROW LEVEL SECURITY;
CREATE POLICY siem_correlacoes_tenant ON siem_correlacoes USING (empresa_id = current_setting('app.empresa_id', true)::uuid) WITH CHECK (empresa_id = current_setting('app.empresa_id', true)::uuid);
GRANT SELECT, INSERT ON siem_correlacoes TO app_tenant;
GRANT USAGE, SELECT ON SEQUENCE siem_correlacoes_id_seq TO app_tenant;

CREATE TABLE IF NOT EXISTS siem_agente_fontes (
  id BIGSERIAL PRIMARY KEY,
  empresa_id UUID NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
  agente_id UUID NOT NULL REFERENCES agentes(id) ON DELETE CASCADE,
  tipo TEXT NOT NULL,
  ultimo_evento_em TIMESTAMPTZ,
  total_eventos BIGINT NOT NULL DEFAULT 0,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(agente_id, tipo)
);
ALTER TABLE siem_agente_fontes ENABLE ROW LEVEL SECURITY;
ALTER TABLE siem_agente_fontes FORCE ROW LEVEL SECURITY;
CREATE POLICY siem_agente_fontes_tenant ON siem_agente_fontes USING (empresa_id = current_setting('app.empresa_id', true)::uuid) WITH CHECK (empresa_id = current_setting('app.empresa_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON siem_agente_fontes TO app_tenant;
GRANT USAGE, SELECT ON SEQUENCE siem_agente_fontes_id_seq TO app_tenant;
