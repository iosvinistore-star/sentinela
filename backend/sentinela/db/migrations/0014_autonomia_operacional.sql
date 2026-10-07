-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
-- Modo autônomo: remove as quatro dependências de um humano presente que
-- ainda existiam depois do plano de endurecimento (ver services/automacao.py
-- para toda a lógica que consome estas colunas/tabela). Tudo aqui é OPT-IN
-- por tenant (default false/NULL) -- nenhuma empresa existente muda de
-- comportamento só por rodar esta migration; um superadmin liga
-- explicitamente por empresa em /admin/empresas, o mesmo lugar que já liga
-- modo_firewall.

-- 1) Autoajuste de modo_firewall (observacao/dry_run/manual ficam de fora
--    do autoajuste de propósito -- são escolhas deliberadas do tenant de
--    nunca automatizar; o autoajuste só transita dentro da escada
--    manual -> automacao_controlada -> automacao_total). Ver
--    services/automacao.py:avaliar_e_ajustar_modo_firewall.
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS modo_firewall_auto boolean NOT NULL DEFAULT false;

-- 2) Auto-triagem de incidentes parados (ver
--    services/automacao.py:auto_classificar_incidentes_abertos).
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS auto_triagem_incidentes boolean NOT NULL DEFAULT false;

-- 3) Quem/o que mudou o status de um incidente -- sem isto, "resolvido"
--    não dizia se foi um analista ou a triagem automática que decidiu.
--    em_andamento_por_usuario_id só é preenchido quando um HUMANO move para
--    EM_ANDAMENTO (services/incidentes.py:atualizar_status); a auto-triagem
--    nunca passa por EM_ANDAMENTO, vai direto pra RESOLVIDO/FALSO_POSITIVO.
ALTER TABLE incidentes ADD COLUMN IF NOT EXISTS em_andamento_por_usuario_id uuid REFERENCES usuarios(id);
ALTER TABLE incidentes ADD COLUMN IF NOT EXISTS resolvido_por text CHECK (resolvido_por IN ('humano', 'sistema'));

-- 4) Curadoria automática da whitelist -- distinta da
--    REDE_PROTEGIDA_OPERADOR (global, por variável de ambiente, ver
--    core/firewall.py): esta é POR TENANT e persistida, alimentada tanto
--    manualmente (um admin protege um IP no dashboard) quanto
--    automaticamente (ver services/automacao.py -- um humano reverte um
--    bloqueio automático rápido demais, ou um incidente ligado a um
--    bloqueio automático é marcado FALSO_POSITIVO). Transparente e
--    reversível de propósito: fica visível e removível pelo admin, nunca
--    some silenciosamente.
CREATE TABLE IF NOT EXISTS ips_protegidos (
    id                     bigserial PRIMARY KEY,
    empresa_id             uuid NOT NULL REFERENCES empresas(id),
    ip                     inet NOT NULL,
    motivo                 text NOT NULL DEFAULT '',
    origem                 text NOT NULL DEFAULT 'manual' CHECK (origem IN ('manual', 'automatico')),
    criado_por_usuario_id  uuid REFERENCES usuarios(id),
    criado_em              timestamptz NOT NULL DEFAULT now(),
    UNIQUE (empresa_id, ip)
);

ALTER TABLE ips_protegidos ENABLE ROW LEVEL SECURITY;
ALTER TABLE ips_protegidos FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_ips_protegidos ON ips_protegidos;
CREATE POLICY tenant_isolation_ips_protegidos ON ips_protegidos
    USING (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- Least-privilege igual ao resto do projeto (ver 0010_...sql): app_tenant
-- adiciona e remove entradas, mas nunca UPDATE (uma entrada é
-- criada/removida, nunca "editada" -- trocar de ideia sobre um IP é
-- remover a proteção e, se for o caso, recriá-la com outro motivo/origem,
-- preservando o rastro de auditoria de cada evento em vez de sobrescrevê-lo).
GRANT SELECT, INSERT, DELETE ON ips_protegidos TO app_tenant;
GRANT USAGE, SELECT ON SEQUENCE ips_protegidos_id_seq TO app_tenant;

GRANT SELECT, INSERT, UPDATE, DELETE ON ips_protegidos TO app_superadmin;
GRANT USAGE, SELECT ON SEQUENCE ips_protegidos_id_seq TO app_superadmin;

CREATE INDEX IF NOT EXISTS idx_ips_protegidos_empresa ON ips_protegidos (empresa_id);

-- Índices de suporte às consultas cross-tenant do ciclo autônomo (ver
-- services/automacao.py) -- ambas as tabelas já são consultadas por
-- empresa_id em outros lugares, mas o ciclo autônomo filtra também por
-- bloqueado_em/atualizado_em recentes em lotes de todas as empresas
-- elegíveis, então merece índice dedicado em vez de contar com os já
-- existentes por (empresa_id, status).
CREATE INDEX IF NOT EXISTS idx_bloqueios_firewall_incidente ON bloqueios_firewall (incidente_id) WHERE incidente_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_incidentes_status_atualizado ON incidentes (status, atualizado_em);
