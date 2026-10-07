-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
-- Sentinela SOC 2.0 — índices e dados auxiliares para correlação/triagem.
CREATE INDEX IF NOT EXISTS idx_incidentes_empresa_criado ON incidentes (empresa_id, criado_em DESC);
CREATE INDEX IF NOT EXISTS idx_incidentes_empresa_severidade ON incidentes (empresa_id, severidade, criado_em DESC);
CREATE INDEX IF NOT EXISTS idx_incidentes_empresa_status ON incidentes (empresa_id, status, criado_em DESC);
CREATE INDEX IF NOT EXISTS idx_bloqueios_empresa_status ON bloqueios_firewall (empresa_id, status, bloqueado_em DESC);
