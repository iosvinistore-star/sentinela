-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
-- Índices — empresa_id é sempre o primeiro campo de qualquer índice
-- composto, porque toda query de aplicação filtra por ele (via RLS).
-- Sem particionamento por empresa_id: ~400 tenants não justifica (ver
-- documento de migração original, seção "o que não fazer agora").

CREATE INDEX IF NOT EXISTS idx_incidentes_empresa ON incidentes (empresa_id, criado_em DESC);
CREATE INDEX IF NOT EXISTS idx_incidentes_status  ON incidentes (empresa_id, status);
CREATE INDEX IF NOT EXISTS idx_bloqueios_empresa   ON bloqueios_firewall (empresa_id, ip);

-- Só um bloqueio ATIVO por (empresa, ip) — torna o insert de bloqueio
-- idempotente via ON CONFLICT, tanto na API quanto no script de migração.
CREATE UNIQUE INDEX IF NOT EXISTS idx_bloqueios_ativo_unico
    ON bloqueios_firewall (empresa_id, ip) WHERE status = 'ativo';

CREATE INDEX IF NOT EXISTS idx_auditoria_empresa ON auditoria (empresa_id, criado_em DESC);
CREATE INDEX IF NOT EXISTS idx_usuarios_empresa   ON usuarios (empresa_id);
