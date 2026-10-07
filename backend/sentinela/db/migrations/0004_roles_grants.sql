-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
-- Roles e grants.
--
-- Decisão: UM pool/DSN só. `sentinela_app` é LOGIN NOINHERIT (zero
-- privilégio próprio) e membro de app_tenant E app_superadmin; cada
-- transação faz `SET LOCAL ROLE` explícito (ver db/pool.py) pra ganhar
-- qualquer privilégio. Falha fechada: esquecer o SET LOCAL ROLE => erro de
-- permissão do Postgres, nunca acesso indevido. Mais simples de operar do
-- que dois pools/DSNs separados.
--
-- __SENTINELA_APP_PASSWORD__ é substituído por run_migrations.py com o
-- valor de SENTINELA_APP_DB_PASSWORD antes de executar este arquivo — o
-- Postgres não aceita parâmetros bind ($1) em DDL como CREATE ROLE.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_tenant') THEN
        CREATE ROLE app_tenant NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_superadmin') THEN
        CREATE ROLE app_superadmin NOLOGIN BYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinela_app') THEN
        CREATE ROLE sentinela_app LOGIN NOINHERIT PASSWORD '__SENTINELA_APP_PASSWORD__';
    ELSE
        ALTER ROLE sentinela_app PASSWORD '__SENTINELA_APP_PASSWORD__';
    END IF;
END $$;

GRANT app_tenant TO sentinela_app;
GRANT app_superadmin TO sentinela_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON incidentes, bloqueios_firewall, auditoria, usuarios TO app_tenant;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_tenant;

GRANT SELECT, INSERT, UPDATE, DELETE ON empresas, usuarios, incidentes, bloqueios_firewall, auditoria, superadmins, reputacao_cache TO app_superadmin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_superadmin;
