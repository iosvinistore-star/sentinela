-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
-- UEBA + EDR/XDR + Sigma: camada multi-tenant e auditável.
CREATE TABLE IF NOT EXISTS ueba_perfis (
  id BIGSERIAL PRIMARY KEY,
  empresa_id UUID NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
  chave TEXT NOT NULL,
  tipo TEXT NOT NULL,
  janela_inicio TIMESTAMPTZ NOT NULL,
  janela_fim TIMESTAMPTZ NOT NULL,
  total_eventos BIGINT NOT NULL DEFAULT 0,
  usuarios_distintos BIGINT NOT NULL DEFAULT 0,
  ips_distintos BIGINT NOT NULL DEFAULT 0,
  media_horaria DOUBLE PRECISION NOT NULL DEFAULT 0,
  desvio_horario DOUBLE PRECISION NOT NULL DEFAULT 0,
  atualizado_em TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(empresa_id,chave,tipo)
);
CREATE INDEX IF NOT EXISTS idx_ueba_perfis_tenant ON ueba_perfis(empresa_id,tipo,atualizado_em DESC);
ALTER TABLE ueba_perfis ENABLE ROW LEVEL SECURITY; ALTER TABLE ueba_perfis FORCE ROW LEVEL SECURITY;
CREATE POLICY ueba_perfis_tenant ON ueba_perfis USING (empresa_id=current_setting('app.empresa_id',true)::uuid) WITH CHECK (empresa_id=current_setting('app.empresa_id',true)::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON ueba_perfis TO app_tenant; GRANT USAGE,SELECT ON SEQUENCE ueba_perfis_id_seq TO app_tenant;

CREATE TABLE IF NOT EXISTS ueba_anomalias (
  id BIGSERIAL PRIMARY KEY,
  empresa_id UUID NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
  evento_id BIGINT REFERENCES eventos_siem(id) ON DELETE SET NULL,
  chave TEXT NOT NULL,
  score DOUBLE PRECISION NOT NULL,
  motivo TEXT NOT NULL,
  evidencias JSONB NOT NULL DEFAULT '{}'::jsonb,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ueba_anomalias_tenant ON ueba_anomalias(empresa_id,criado_em DESC);
ALTER TABLE ueba_anomalias ENABLE ROW LEVEL SECURITY; ALTER TABLE ueba_anomalias FORCE ROW LEVEL SECURITY;
CREATE POLICY ueba_anomalias_tenant ON ueba_anomalias USING (empresa_id=current_setting('app.empresa_id',true)::uuid) WITH CHECK (empresa_id=current_setting('app.empresa_id',true)::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON ueba_anomalias TO app_tenant; GRANT USAGE,SELECT ON SEQUENCE ueba_anomalias_id_seq TO app_tenant;

CREATE TABLE IF NOT EXISTS sigma_regras (
  id BIGSERIAL PRIMARY KEY,
  empresa_id UUID NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
  nome TEXT NOT NULL,
  titulo TEXT NOT NULL,
  nivel TEXT NOT NULL DEFAULT 'medium',
  logsource JSONB NOT NULL DEFAULT '{}'::jsonb,
  detection JSONB NOT NULL DEFAULT '{}'::jsonb,
  tags JSONB NOT NULL DEFAULT '[]'::jsonb,
  ativo BOOLEAN NOT NULL DEFAULT true,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT now(), atualizado_em TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(empresa_id,nome)
);
CREATE INDEX IF NOT EXISTS idx_sigma_regras_tenant ON sigma_regras(empresa_id,ativo);
ALTER TABLE sigma_regras ENABLE ROW LEVEL SECURITY; ALTER TABLE sigma_regras FORCE ROW LEVEL SECURITY;
CREATE POLICY sigma_regras_tenant ON sigma_regras USING (empresa_id=current_setting('app.empresa_id',true)::uuid) WITH CHECK (empresa_id=current_setting('app.empresa_id',true)::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON sigma_regras TO app_tenant; GRANT USAGE,SELECT ON SEQUENCE sigma_regras_id_seq TO app_tenant;

CREATE TABLE IF NOT EXISTS sigma_alertas (
  id BIGSERIAL PRIMARY KEY,
  empresa_id UUID NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
  regra_id BIGINT NOT NULL REFERENCES sigma_regras(id) ON DELETE CASCADE,
  evento_id BIGINT REFERENCES eventos_siem(id) ON DELETE SET NULL,
  severidade TEXT NOT NULL,
  evidencias JSONB NOT NULL DEFAULT '{}'::jsonb,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sigma_alertas_tenant ON sigma_alertas(empresa_id,criado_em DESC);
ALTER TABLE sigma_alertas ENABLE ROW LEVEL SECURITY; ALTER TABLE sigma_alertas FORCE ROW LEVEL SECURITY;
CREATE POLICY sigma_alertas_tenant ON sigma_alertas USING (empresa_id=current_setting('app.empresa_id',true)::uuid) WITH CHECK (empresa_id=current_setting('app.empresa_id',true)::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON sigma_alertas TO app_tenant; GRANT USAGE,SELECT ON SEQUENCE sigma_alertas_id_seq TO app_tenant;

CREATE TABLE IF NOT EXISTS edr_telemetria (
  id BIGSERIAL PRIMARY KEY,
  empresa_id UUID NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
  agente_id UUID REFERENCES agentes(id) ON DELETE SET NULL,
  tipo TEXT NOT NULL,
  hostname TEXT,
  processo TEXT,
  pid INTEGER,
  usuario TEXT,
  caminho TEXT,
  hash_sha256 TEXT,
  parent_pid INTEGER,
  destino_ip INET,
  destino_porta INTEGER,
  protocolo TEXT,
  severidade TEXT NOT NULL DEFAULT 'INFO',
  detalhes JSONB NOT NULL DEFAULT '{}'::jsonb,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_edr_tenant_time ON edr_telemetria(empresa_id,criado_em DESC);
CREATE INDEX IF NOT EXISTS idx_edr_hash ON edr_telemetria(empresa_id,hash_sha256);
ALTER TABLE edr_telemetria ENABLE ROW LEVEL SECURITY; ALTER TABLE edr_telemetria FORCE ROW LEVEL SECURITY;
CREATE POLICY edr_tenant ON edr_telemetria USING (empresa_id=current_setting('app.empresa_id',true)::uuid) WITH CHECK (empresa_id=current_setting('app.empresa_id',true)::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON edr_telemetria TO app_tenant; GRANT USAGE,SELECT ON SEQUENCE edr_telemetria_id_seq TO app_tenant;
