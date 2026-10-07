-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
-- Row Level Security: preserva, no banco compartilhado, a garantia que
-- antes vinha "de graça" de um arquivo SQLite por empresa. Mesmo que uma
-- query da aplicação tenha um bug e esqueça o filtro empresa_id, o Postgres
-- barra o acesso cross-tenant no nível do banco.

ALTER TABLE incidentes         ENABLE ROW LEVEL SECURITY;
ALTER TABLE bloqueios_firewall ENABLE ROW LEVEL SECURITY;
ALTER TABLE auditoria          ENABLE ROW LEVEL SECURITY;
ALTER TABLE usuarios           ENABLE ROW LEVEL SECURITY;

-- FORCE: aplica a policy mesmo para o dono da tabela (sentinela_app cria
-- estas tabelas via esta migration, então sem FORCE ele burlaria a policy).
ALTER TABLE incidentes         FORCE ROW LEVEL SECURITY;
ALTER TABLE bloqueios_firewall FORCE ROW LEVEL SECURITY;
ALTER TABLE auditoria          FORCE ROW LEVEL SECURITY;
ALTER TABLE usuarios           FORCE ROW LEVEL SECURITY;
ALTER TABLE reputacao_cache    ENABLE ROW LEVEL SECURITY;
ALTER TABLE reputacao_cache    FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_incidentes ON incidentes;
DROP POLICY IF EXISTS tenant_isolation_bloqueios ON bloqueios_firewall;
DROP POLICY IF EXISTS tenant_isolation_auditoria ON auditoria;
DROP POLICY IF EXISTS tenant_isolation_usuarios ON usuarios;
DROP POLICY IF EXISTS tenant_isolation_reputacao ON reputacao_cache;

CREATE POLICY tenant_isolation_incidentes ON incidentes
    USING (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
CREATE POLICY tenant_isolation_bloqueios ON bloqueios_firewall
    USING (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
CREATE POLICY tenant_isolation_auditoria ON auditoria
    USING (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
CREATE POLICY tenant_isolation_usuarios ON usuarios
    USING (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
CREATE POLICY tenant_isolation_reputacao ON reputacao_cache
    USING (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- empresas e superadmins não recebem RLS: só são tocadas por operações
-- explicitamente executadas como app_superadmin (BYPASSRLS).
