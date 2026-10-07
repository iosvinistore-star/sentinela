-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
-- Fase C (V3.1): RBAC de 5 papéis + MFA/TOTP. Aditiva sobre 0001-0019,
-- nunca edita nada existente -- mesma convenção do resto deste diretório.
--
-- DECISÃO DE COMPATIBILIDADE (documentada aqui por ser a peça central da
-- Fase C -- ver RBAC.md na raiz do repo para o desenho completo):
--
-- O escopo pede exatamente 5 papéis: SAAS_OWNER, SAAS_ADMIN, COMPANY_ADMIN,
-- SECURITY_ANALYST, VIEWER. O sistema já tinha DOIS conceitos de conta
-- totalmente separados desde 0001/0013: `usuarios.papel` (tenant-scoped:
-- 'admin'/'analista') e `superadmins` (tabela própria, sem `papel` nenhum
-- até esta migration -- todo superadmin era implicitamente "o mesmo nível
-- de poder"). Em vez de renomear os valores existentes ('admin'->
-- 'company_admin', 'analista'->'security_analyst') -- o que quebraria
-- TODO `exigir_papel("admin")`/`exigir_papel_web("admin")` espalhado por
-- ~10 arquivos de rota, além de qualquer sessão JWT já emitida --, os 5
-- papéis conceituais são mapeados para os valores JÁ EXISTENTES, mais dois
-- novos, aditivos:
--
--   SAAS_OWNER        <- superadmins.papel = 'saas_owner' (NOVO, default
--                        para toda linha já existente -- "hoje só existe
--                        um nível de superadmin" vira, sem nenhuma migração
--                        de dado além do DEFAULT, "todo superadmin de hoje
--                        é Owner", que é a leitura mais conservadora/segura
--                        possível de um dado que antes não distinguia nada)
--   SAAS_ADMIN        <- superadmins.papel = 'saas_admin' (NOVO)
--   COMPANY_ADMIN      <- usuarios.papel = 'admin' (EXISTENTE, sem mudança)
--   SECURITY_ANALYST   <- usuarios.papel = 'analista' (EXISTENTE, sem mudança)
--   VIEWER            <- usuarios.papel = 'viewer' (NOVO)
--
-- `sentinela.auth.rbac` (novo módulo Python) é o único lugar que conhece
-- este mapeamento -- ver seu docstring para o resolvedor de "papel
-- conceitual" e a matriz de permissões.
--
-- Zero linha de código de autorização EXISTENTE precisou mudar de
-- comportamento por causa disto: 'viewer' é um valor NOVO no CHECK de
-- `usuarios.papel`, então todo `exigir_papel("admin")`/`exigir_login`
-- já existente continua funcionando exatamente igual (um usuário 'viewer'
-- já cai no mesmo tratamento de "papel não permitido" que qualquer papel
-- não listado cairia). O que SIM precisou de ajuste pontual (ver
-- RBAC.md, "Retrofits") foram os poucos endpoints que mutavam dado usando
-- só `exigir_login`/`exigir_login_web` (sem `exigir_papel`) -- esses
-- aceitavam QUALQUER usuário de empresa, o que antes de 'viewer' existir
-- era equivalente a "admin ou analista", mas passaria a aceitar
-- 'viewer' também se não fossem trocados para `exigir_papel("admin",
-- "analista")` explicitamente.

-- 1) VIEWER: novo valor aditivo no CHECK de usuarios.papel.
ALTER TABLE usuarios DROP CONSTRAINT IF EXISTS usuarios_papel_check;
ALTER TABLE usuarios ADD CONSTRAINT usuarios_papel_check
    CHECK (papel IN ('admin', 'analista', 'viewer'));

-- 2) SAAS_OWNER vs SAAS_ADMIN: nova coluna em `superadmins`, nunca existiu
--    antes -- default 'saas_owner' preserva o comportamento de HOJE (um
--    superadmin existente continua podendo fazer tudo que fazia ontem; só
--    as duas operações marcadas como exclusivas do Owner na Fase C -- ver
--    RBAC.md -- passam a exigir 'saas_owner' explicitamente).
ALTER TABLE superadmins ADD COLUMN IF NOT EXISTS papel text NOT NULL DEFAULT 'saas_owner'
    CHECK (papel IN ('saas_owner', 'saas_admin'));

-- 3) MFA/TOTP -- estado por usuário (só `usuarios`; superadmin fica de
--    fora do escopo desta etapa, mesma nota de 0011_token_version.sql
--    sobre por que superadmin recebe tratamento à parte quando recebe).
--    `mfa_secret_cifrado`: NUNCA texto puro (C6) -- cifrado com Fernet
--    (AES-128-CBC + HMAC, ver auth/mfa.py) usando uma chave de aplicação
--    própria (`SENTINELA_MFA_ENCRYPTION_KEY`), não um hash bcrypt --
--    TOTP precisa do segredo em claro no momento de CALCULAR o código
--    esperado para comparar (diferente de senha, que só precisa de
--    comparação, nunca do valor original), então hash one-way não serve
--    aqui; cifragem reversível com chave própria (nunca a mesma do JWT) é
--    o mecanismo correto para este caso, mesmo racional de qualquer TOTP
--    server-side sério.
ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS mfa_habilitado boolean NOT NULL DEFAULT false;
ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS mfa_secret_cifrado bytea;
ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS mfa_confirmado_em timestamptz;

-- 4) Recovery codes -- tabela própria (não uma coluna array): cada código
--    tem seu próprio ciclo de vida (usado uma vez, invalidado em bloco numa
--    regeneração) e isso é natural como linhas, não como um jsonb mutável.
--    RLS por empresa_id (denormalizado a partir de usuarios.empresa_id na
--    escrita, mesmo padrão de bloqueios_firewall/incidentes) -- mesmo
--    sendo sempre acessada via usuario_id, toda tabela tenant-scoped deste
--    projeto tem sua própria policy (defesa em profundidade: um bug futuro
--    que esqueça o filtro por usuario_id ainda não vaza entre empresas).
--    Hash bcrypt (não cifragem): ao contrário do secret TOTP, um recovery
--    code só precisa ser COMPARADO no momento do uso, nunca recalculado --
--    mesmo caso de uso de uma senha, mesmo mecanismo (hash_senha/
--    verificar_senha de auth/security.py).
-- ON DELETE CASCADE em usuario_id (ao contrário de `auditoria.
-- ator_usuario_id`, que NUNCA usa CASCADE -- rastro de auditoria deve
-- sobreviver à exclusão do ator): um recovery code não tem NENHUM valor
-- histórico depois que o usuário dono deixa de existir, então cascatear é
-- o comportamento correto aqui, não só uma conveniência de teste (produção
-- também nunca deveria acumular recovery codes órfãos).
CREATE TABLE IF NOT EXISTS usuarios_mfa_recovery_codes (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    empresa_id     uuid NOT NULL REFERENCES empresas(id),
    usuario_id     uuid NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
    codigo_hash    text NOT NULL,
    usado_em       timestamptz,
    invalidado_em  timestamptz,
    criado_em      timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE usuarios_mfa_recovery_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE usuarios_mfa_recovery_codes FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_mfa_recovery_codes ON usuarios_mfa_recovery_codes;
CREATE POLICY tenant_isolation_mfa_recovery_codes ON usuarios_mfa_recovery_codes
    USING (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_usuario
    ON usuarios_mfa_recovery_codes (usuario_id)
    WHERE usado_em IS NULL AND invalidado_em IS NULL;

-- 5) Least-privilege igual ao resto do projeto: app_tenant nunca tem
--    DELETE (invalidação é UPDATE de invalidado_em/usado_em).
GRANT SELECT, INSERT, UPDATE ON usuarios_mfa_recovery_codes TO app_tenant;
GRANT SELECT, INSERT, UPDATE, DELETE ON usuarios_mfa_recovery_codes TO app_superadmin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_tenant;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_superadmin;

-- app_superadmin já tem SELECT/INSERT/UPDATE/DELETE em `usuarios` e
-- `superadmins` desde 0004_roles_grants.sql (GRANT ... ON empresas,
-- usuarios, ... TO app_superadmin) -- as colunas novas em `usuarios`/
-- `superadmins` acima não precisam de GRANT extra, um GRANT de tabela já
-- cobre colunas adicionadas depois.
