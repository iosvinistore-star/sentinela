-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
-- V6: operação de fontes SIEM e índices para ingestão/correlação em escala.
CREATE INDEX IF NOT EXISTS idx_eventos_siem_tenant_agente_ts
  ON eventos_siem(empresa_id, agente_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_eventos_siem_tenant_source_type_ts
  ON eventos_siem(empresa_id, source_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_eventos_siem_iocs_gin
  ON eventos_siem USING GIN(iocs);
CREATE INDEX IF NOT EXISTS idx_eventos_siem_tags_gin
  ON eventos_siem USING GIN(tags);

CREATE UNIQUE INDEX IF NOT EXISTS uq_siem_fontes_tenant_nome
  ON siem_fontes(empresa_id, lower(nome));

GRANT SELECT ON eventos_siem TO app_tenant;
