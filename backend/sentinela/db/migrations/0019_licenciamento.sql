-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
-- Licenciamento SaaS: primeira etapa da evolução do Sentinela para uma
-- plataforma com licenciamento centralizado (ver ARQUITETURA_LICENCIAMENTO.md
-- na raiz do repo para o desenho completo). Aditiva sobre 0001-0018, nunca
-- edita nada existente -- mesma convenção do resto deste diretório.
--
-- Conceito NOVO e DISTINTO de "agentes" (0016/0017/0018): "agentes" é o
-- Sentinela Endpoint (EDR local); "licencas" é o direito de uso do produto
-- em si, concedido por empresa. Um agente pode existir sem licença
-- comercial nenhuma hoje (nada aqui torna isso obrigatório -- ligar a
-- exigência de licença ativa a alguma rota é uma decisão de produto para
-- uma etapa futura, fora deste escopo). As duas tabelas de token
-- (agentes.token_* / licencas.token_*) são independentes por design: nunca
-- compartilham prefixo, hash ou tabela.

-- 1) Catálogo de planos -- GLOBAL, sem RLS (mesmo motivo de `empresas` não
--    ter RLS: só o superadmin deveria gerenciar o catálogo comercial).
--    Preço fica de fora de propósito -- o escopo combinado com o cliente
--    explicitamente pede para NÃO implementar cobrança ainda; esta tabela
--    só define limites técnicos e capacidades por plano.
CREATE TABLE IF NOT EXISTS planos (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    codigo         text NOT NULL UNIQUE,
    nome_exibicao  text NOT NULL,
    max_endpoints  integer NOT NULL DEFAULT 1 CHECK (max_endpoints >= 0),
    -- jsonb em vez de colunas fixas por capacidade: novas capacidades por
    -- plano (ex.: "deteccao_avancada", "grace_period_dias" -- ver
    -- ARQUITETURA_LICENCIAMENTO.md §6) não exigem migration nova, só um
    -- UPDATE nesta coluna.
    recursos       jsonb NOT NULL DEFAULT '{}'::jsonb,
    ativo          boolean NOT NULL DEFAULT true,
    criado_em      timestamptz NOT NULL DEFAULT now()
);

-- Seed dos 4 planos padrão do escopo (Starter/Professional/Business/
-- Enterprise). ON CONFLICT DO NOTHING: reaplicar esta migration (ou rodar
-- de novo em ambiente já seedado manualmente) nunca sobrescreve limites que
-- um superadmin já tenha ajustado via UPDATE depois do deploy inicial.
-- grace_period_dias (ver ARQUITETURA_LICENCIAMENTO.md §6) default 3 --
-- Enterprise fica com 7 (cliente maior, mais tolerância a instabilidade de
-- rede local antes de a licença "expirar" do ponto de vista do Agent).
INSERT INTO planos (codigo, nome_exibicao, max_endpoints, recursos) VALUES
    ('starter',      'Starter',      5,   '{"grace_period_dias": 3}'::jsonb),
    ('professional', 'Professional', 25,  '{"grace_period_dias": 3}'::jsonb),
    ('business',     'Business',     100, '{"grace_period_dias": 5}'::jsonb),
    ('enterprise',   'Enterprise',   1000,'{"grace_period_dias": 7}'::jsonb)
ON CONFLICT (codigo) DO NOTHING;

-- 2) Licenças -- uma por empresa (uma empresa pode ter mais de uma ao longo
--    do tempo: renovações/upgrades de plano criam OU reaproveitam a mesma
--    linha, decisão de `services/licenciamento.py`, não uma restrição de
--    schema). Token de longa duração no MESMO padrão de `agentes` (prefixo
--    "lic", ver auth/licencas.py) -- família de token própria, nunca
--    reaproveita `agentes.token_prefixo`/`token_hash`.
CREATE TABLE IF NOT EXISTS licencas (
    id                          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    empresa_id                  uuid NOT NULL REFERENCES empresas(id),
    plano_id                    uuid NOT NULL REFERENCES planos(id),
    token_prefixo               text NOT NULL UNIQUE,
    token_hash                  text NOT NULL,
    status                      text NOT NULL DEFAULT 'ativa'
                                    CHECK (status IN ('ativa', 'suspensa', 'expirada', 'revogada')),
    ativada_em                  timestamptz,
    expira_em                   timestamptz,
    criado_em                   timestamptz NOT NULL DEFAULT now(),
    criado_por_usuario_id       uuid REFERENCES usuarios(id),
    criado_por_superadmin_id    uuid REFERENCES superadmins(id),
    ultima_validacao_em         timestamptz
);

ALTER TABLE licencas ENABLE ROW LEVEL SECURITY;
ALTER TABLE licencas FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_licencas ON licencas;
CREATE POLICY tenant_isolation_licencas ON licencas
    USING (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

CREATE INDEX IF NOT EXISTS idx_licencas_empresa ON licencas (empresa_id);
-- token_prefixo já é UNIQUE (cria o índice); documentado aqui pelo mesmo
-- motivo do comentário equivalente em 0016_agentes_endpoint.sql -- o
-- lookup de autenticação roda via superadmin_scoped_connection (BYPASSRLS),
-- o mesmo problema de "ovo e galinha" do login/agentes.

-- 3) Vagas de endpoint ocupadas por uma licença -- reaproveita `agentes`
--    como fonte de identidade do endpoint (não cria uma segunda noção de
--    "endpoint" paralela). Soft-release (liberado_em) preserva histórico,
--    nunca DELETE -- mesma filosofia do resto do projeto.
CREATE TABLE IF NOT EXISTS licencas_endpoints (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    empresa_id     uuid NOT NULL REFERENCES empresas(id),
    licenca_id     uuid NOT NULL REFERENCES licencas(id),
    agente_id      uuid NOT NULL REFERENCES agentes(id),
    ocupado_em     timestamptz NOT NULL DEFAULT now(),
    liberado_em    timestamptz,
    UNIQUE (agente_id)
);

ALTER TABLE licencas_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE licencas_endpoints FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_licencas_endpoints ON licencas_endpoints;
CREATE POLICY tenant_isolation_licencas_endpoints ON licencas_endpoints
    USING (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- Índice parcial (só vagas ainda ocupadas) -- é exatamente o WHERE usado
-- por services/licenciamento.py:registrar_endpoint para contar vagas em
-- uso contra planos.max_endpoints, mesmo truque de
-- idx_incidentes_agente_aberto (0018).
CREATE INDEX IF NOT EXISTS idx_licencas_endpoints_ocupadas
    ON licencas_endpoints (licenca_id)
    WHERE liberado_em IS NULL;
CREATE INDEX IF NOT EXISTS idx_licencas_endpoints_empresa ON licencas_endpoints (empresa_id);

-- 4) Auditoria dedicada de alta frequência (validação periódica do Agent) --
--    separada da tabela `auditoria` genérica pelo mesmo motivo de
--    `agentes_eventos` existir separado de `incidentes`: sem isso, o
--    volume normal de `validate` (a cada 15-60min por empresa) poluiria o
--    audit log administrativo com ruído, tornando mais difícil achar as
--    ações administrativas de verdade (quem suspendeu/revogou o quê).
CREATE TABLE IF NOT EXISTS licencas_eventos (
    id           bigserial PRIMARY KEY,
    empresa_id   uuid NOT NULL REFERENCES empresas(id),
    licenca_id   uuid NOT NULL REFERENCES licencas(id),
    tipo         text NOT NULL,
    detalhes     jsonb NOT NULL DEFAULT '{}'::jsonb,
    criado_em    timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE licencas_eventos ENABLE ROW LEVEL SECURITY;
ALTER TABLE licencas_eventos FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_licencas_eventos ON licencas_eventos;
CREATE POLICY tenant_isolation_licencas_eventos ON licencas_eventos
    USING (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

CREATE INDEX IF NOT EXISTS idx_licencas_eventos_empresa_tempo ON licencas_eventos (empresa_id, criado_em);
CREATE INDEX IF NOT EXISTS idx_licencas_eventos_licenca ON licencas_eventos (licenca_id, criado_em);

-- 5) Least-privilege igual ao resto do projeto (ver 0010/0016): app_tenant
--    nunca tem DELETE (revogar/suspender é UPDATE de status, ou
--    soft-release em licencas_endpoints) -- só app_superadmin (gestão
--    global, ex.: expurgo administrativo) recebe DELETE.
GRANT SELECT ON planos TO app_tenant, app_superadmin;
GRANT SELECT, INSERT, UPDATE, DELETE ON planos TO app_superadmin;

GRANT SELECT, INSERT, UPDATE ON licencas TO app_tenant;
GRANT SELECT, INSERT, UPDATE, DELETE ON licencas TO app_superadmin;

GRANT SELECT, INSERT, UPDATE ON licencas_endpoints TO app_tenant;
GRANT SELECT, INSERT, UPDATE, DELETE ON licencas_endpoints TO app_superadmin;

GRANT SELECT, INSERT ON licencas_eventos TO app_tenant;
GRANT SELECT, INSERT, UPDATE, DELETE ON licencas_eventos TO app_superadmin;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_tenant;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_superadmin;
