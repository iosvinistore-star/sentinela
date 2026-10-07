-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
-- Itens 8-10 do plano de endurecimento pós-auditoria: kill-switch/modo de
-- firewall por tenant, e rastreabilidade completa de bloqueio -> incidente
-- que o originou.
--
-- `empresas.modo_firewall` -- cinco modos, do mais conservador ao mais
-- permissivo (ver services/resposta_incidentes.py para a lógica que
-- interpreta cada um):
--   observacao            -- nunca bloqueia (nem manual nem automático).
--   dry_run                -- todo bloqueio (automático) é simulado, nunca
--                             toca o kernel de verdade.
--   manual                 -- bloqueio automático (resposta a incidente,
--                             disparado por upload de log) desligado; um
--                             admin ainda pode bloquear explicitamente via
--                             POST /api/v1/firewall/bloqueios ou /firewall.
--   automacao_controlada    -- bloqueio automático permitido, mas nunca
--                             permanente (teto de 24h independente do que
--                             o chamador pediu). DEFAULT -- é o
--                             comportamento mais próximo do que o sistema
--                             já fazia antes deste plano.
--   automacao_total         -- bloqueio automático sem teto extra de
--                             duração.
-- Este modo é POR TENANT (não um kill-switch global -- esse é
-- `SENTINELA_FIREWALL_AUTOMACAO_HABILITADA`, uma variável de ambiente lida
-- em config.py, fora do banco de propósito: um kill-switch de emergência
-- não deveria depender do Postgres estar saudável para funcionar).
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS modo_firewall text NOT NULL DEFAULT 'automacao_controlada'
    CHECK (modo_firewall IN ('observacao', 'dry_run', 'manual', 'automacao_controlada', 'automacao_total'));

-- Link explícito bloqueio -> incidente que o originou (quando o bloqueio
-- veio de resposta automática a incidente, não de uma ação manual do
-- admin -- nesse caso fica NULL). Sem isto, "que incidente causou este
-- bloqueio" só dava pra inferir cruzando timestamp+IP à mão no log de
-- auditoria -- agora é uma FK navegável nos dois sentidos.
ALTER TABLE bloqueios_firewall ADD COLUMN IF NOT EXISTS incidente_id bigint REFERENCES incidentes(id);
