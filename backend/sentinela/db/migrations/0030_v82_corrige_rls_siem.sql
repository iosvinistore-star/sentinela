-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
-- V8.2 -- correção CRÍTICA de RLS das tabelas SIEM/CTI/SOAR/UEBA/Sigma/EDR.
--
-- Problema: as migrations 0024..0029 criaram as policies com
--   current_setting('app.empresa_id', true)
-- mas o backend inteiro escopa a transação com
--   set_config('app.current_tenant', ...)   (ver db/pool.py)
-- e as tabelas antigas (0003..0023) usam app.current_tenant. Resultado: sob o
-- role app_tenant, `app.empresa_id` é sempre NULL, todo INSERT viola o WITH
-- CHECK e todo SELECT volta vazio. Em Postgres real, a camada SIEM inteira
-- (ingestão, CTI, SOAR, UEBA, Sigma, EDR) não funcionava, e o heartbeat do
-- Agent com processo suspeito passou a devolver 500 (INSERT em edr_telemetria)
-- -- regressão de uma funcionalidade que já funcionava antes da V8.
--
-- Esta migration derruba TODAS as policies dessas tabelas e recria uma única
-- policy por tabela usando o mesmo GUC do resto do projeto.

DO $$
DECLARE
    t   text;
    pol record;
    tabelas text[] := ARRAY[
        'eventos_siem', 'eventos_siem_cold', 'cti_indicadores', 'soar_playbooks',
        'soar_execucoes', 'siem_fontes', 'siem_correlacoes', 'siem_agente_fontes',
        'ueba_perfis', 'ueba_anomalias', 'sigma_regras', 'sigma_alertas', 'edr_telemetria'
    ];
BEGIN
    FOREACH t IN ARRAY tabelas LOOP
        IF to_regclass('public.' || t) IS NULL THEN
            CONTINUE;
        END IF;
        FOR pol IN SELECT policyname FROM pg_policies WHERE schemaname = 'public' AND tablename = t LOOP
            EXECUTE format('DROP POLICY %I ON %I', pol.policyname, t);
        END LOOP;
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY %I ON %I USING (empresa_id = current_setting(''app.current_tenant'', true)::uuid) '
            'WITH CHECK (empresa_id = current_setting(''app.current_tenant'', true)::uuid)',
            t || '_tenant', t
        );
    END LOOP;
END $$;

-- Retenção: a rotina de manutenção roda como app_superadmin (BYPASSRLS) --
-- antes rodava com o login role NOINHERIT sem SET ROLE, então não tinha
-- privilégio nenhum nas tabelas e nunca arquivou/expirou nada.
GRANT SELECT, DELETE ON eventos_siem TO app_superadmin;
GRANT SELECT, INSERT, DELETE ON eventos_siem_cold TO app_superadmin;

-- soar_execucoes/siem_correlacoes: app_tenant só tinha SELECT/INSERT; mantém.

-- UEBA: linha de base POR ENTIDADE (antes comparava a contagem de uma
-- entidade com a média horária do tenant inteiro, o que praticamente nunca
-- disparava em tenants com mais de uma entidade e custava um scan de 24h do
-- tenant a CADA evento ingerido).
CREATE INDEX IF NOT EXISTS idx_eventos_siem_tenant_username_ts
    ON eventos_siem (empresa_id, username, timestamp DESC) WHERE username IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_eventos_siem_tenant_hostname_ts
    ON eventos_siem (empresa_id, hostname, timestamp DESC) WHERE hostname IS NOT NULL;

-- UEBA: no máximo uma anomalia por entidade por hora (antes, uma entidade em
-- pico gerava uma anomalia por evento -- milhares por minuto).
ALTER TABLE ueba_anomalias ADD COLUMN IF NOT EXISTS tipo TEXT;
ALTER TABLE ueba_anomalias ADD COLUMN IF NOT EXISTS janela_hora TIMESTAMPTZ;
UPDATE ueba_anomalias
   SET janela_hora = date_trunc('hour', criado_em AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
 WHERE janela_hora IS NULL;
DELETE FROM ueba_anomalias a
 USING ueba_anomalias b
 WHERE a.empresa_id = b.empresa_id AND a.chave = b.chave
   AND a.janela_hora = b.janela_hora AND a.id > b.id;
ALTER TABLE ueba_anomalias ALTER COLUMN janela_hora SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_ueba_anomalias_entidade_hora
    ON ueba_anomalias (empresa_id, chave, janela_hora);

-- Sigma: disparo idempotente (reavaliar o mesmo evento não duplica alerta).
DELETE FROM sigma_alertas a
 USING sigma_alertas b
 WHERE a.regra_id = b.regra_id AND a.evento_id = b.evento_id AND a.id > b.id;
CREATE UNIQUE INDEX IF NOT EXISTS uq_sigma_alertas_regra_evento
    ON sigma_alertas (regra_id, evento_id);

-- EDR: deduplicação do heartbeat (o mesmo processo suspeito era regravado a
-- cada heartbeat, para sempre).
CREATE INDEX IF NOT EXISTS idx_edr_dedup
    ON edr_telemetria (empresa_id, agente_id, pid, processo, criado_em DESC);

-- Correlação: consultas por regra/score no painel.
CREATE INDEX IF NOT EXISTS idx_siem_correlacoes_tenant_regra
    ON siem_correlacoes (empresa_id, regra, criado_em DESC);
