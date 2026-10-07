-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
-- Cache de reputação: isolamento por tenant.
-- O cache é descartável; em instalações que já tinham a versão global,
-- descartamos as entradas antigas em vez de atribuí-las arbitrariamente a
-- uma empresa. Elas serão recriadas sob demanda.
DROP TABLE IF EXISTS reputacao_cache;

CREATE TABLE reputacao_cache (
    empresa_id      uuid NOT NULL REFERENCES empresas(id),
    ip              inet NOT NULL,
    dados           jsonb NOT NULL,
    classificacao   text NOT NULL,
    consultado_em   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (empresa_id, ip)
);

ALTER TABLE reputacao_cache ENABLE ROW LEVEL SECURITY;
ALTER TABLE reputacao_cache FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_reputacao ON reputacao_cache
    USING (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON reputacao_cache TO app_tenant;
GRANT SELECT, INSERT, UPDATE, DELETE ON reputacao_cache TO app_superadmin;
