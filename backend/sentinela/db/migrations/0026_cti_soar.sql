-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
CREATE TABLE IF NOT EXISTS cti_indicadores (
  id BIGSERIAL PRIMARY KEY,
  empresa_id UUID NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
  stix_id TEXT,
  tipo TEXT NOT NULL DEFAULT 'STIX',
  indicator_type TEXT NOT NULL,
  valor TEXT NOT NULL,
  pattern TEXT,
  confidence INTEGER,
  valid_until TIMESTAMPTZ,
  labels JSONB NOT NULL DEFAULT '[]'::jsonb,
  raw JSONB NOT NULL DEFAULT '{}'::jsonb,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (empresa_id, stix_id)
);
CREATE INDEX IF NOT EXISTS idx_cti_indicadores_valor ON cti_indicadores(empresa_id, valor);
ALTER TABLE cti_indicadores ENABLE ROW LEVEL SECURITY;
ALTER TABLE cti_indicadores FORCE ROW LEVEL SECURITY;
CREATE POLICY cti_tenant ON cti_indicadores USING (empresa_id = current_setting('app.empresa_id', true)::uuid) WITH CHECK (empresa_id = current_setting('app.empresa_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON cti_indicadores TO app_tenant;
GRANT USAGE, SELECT ON SEQUENCE cti_indicadores_id_seq TO app_tenant;

CREATE TABLE IF NOT EXISTS soar_playbooks (
  id BIGSERIAL PRIMARY KEY,
  empresa_id UUID NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
  nome TEXT NOT NULL,
  gatilho TEXT NOT NULL,
  acoes JSONB NOT NULL DEFAULT '[]'::jsonb,
  ativo BOOLEAN NOT NULL DEFAULT true,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_soar_playbooks_tenant ON soar_playbooks(empresa_id);
ALTER TABLE soar_playbooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE soar_playbooks FORCE ROW LEVEL SECURITY;
CREATE POLICY soar_playbooks_tenant ON soar_playbooks USING (empresa_id = current_setting('app.empresa_id', true)::uuid) WITH CHECK (empresa_id = current_setting('app.empresa_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON soar_playbooks TO app_tenant;
GRANT USAGE, SELECT ON SEQUENCE soar_playbooks_id_seq TO app_tenant;

CREATE TABLE IF NOT EXISTS soar_execucoes (
  id BIGSERIAL PRIMARY KEY,
  empresa_id UUID NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
  playbook_id BIGINT NOT NULL REFERENCES soar_playbooks(id) ON DELETE CASCADE,
  incidente_id BIGINT,
  status TEXT NOT NULL,
  resultado JSONB NOT NULL DEFAULT '{}'::jsonb,
  executado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_soar_execucoes_tenant ON soar_execucoes(empresa_id, executado_em DESC);
ALTER TABLE soar_execucoes ENABLE ROW LEVEL SECURITY;
ALTER TABLE soar_execucoes FORCE ROW LEVEL SECURITY;
CREATE POLICY soar_execucoes_tenant ON soar_execucoes USING (empresa_id = current_setting('app.empresa_id', true)::uuid) WITH CHECK (empresa_id = current_setting('app.empresa_id', true)::uuid);
GRANT SELECT, INSERT ON soar_execucoes TO app_tenant;
GRANT USAGE, SELECT ON SEQUENCE soar_execucoes_id_seq TO app_tenant;
