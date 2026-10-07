-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
-- Fase D / D3 -- enrollment self-service de agentes (ver
-- ARQUITETURA_LICENCIAMENTO.md §12 para o desenho completo, escrito ANTES
-- desta migration). Aditiva sobre 0001-0021, nunca edita nada existente.
--
-- Problema que isto resolve: hoje (`POST /agentes`) um ADMIN HUMANO cria
-- cada agente manualmente e copia o token de longa duração para configurar
-- a máquina -- não escala para "instalar em 50 laptops hoje" nem permite
-- um instalador verdadeiramente zero-touch. Um token de ENROLLMENT é uma
-- credencial de curta duração, escopada à empresa, que o instalador troca
-- pela identidade PERMANENTE do agente (o mesmo `agt_...` que
-- `criar_agente` já emite) no primeiro contato com o backend -- o token de
-- enrollment em si nunca autentica heartbeat nem qualquer outra rota.
--
-- Família de token PRÓPRIA (prefixo "enr", ver auth/enrollment.py) --
-- nunca compartilha tabela, prefixo ou hash com `agentes`/`licencas`,
-- mesmo princípio já seguido pelas duas famílias existentes.
CREATE TABLE IF NOT EXISTS agentes_enrollment_tokens (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    empresa_id              uuid NOT NULL REFERENCES empresas(id),
    token_prefixo           text NOT NULL UNIQUE,
    token_hash              text NOT NULL,
    status                  text NOT NULL DEFAULT 'ativo' CHECK (status IN ('ativo', 'revogado')),
    -- Sempre obrigatório (ao contrário de licencas.expira_em, que aceita
    -- NULL para "sem expiração definida") -- um token de enrollment é, por
    -- natureza, uma credencial de curta duração; "sem expiração" não é uma
    -- opção válida aqui (ver ARQUITETURA_LICENCIAMENTO.md §12 para o
    -- raciocínio -- é justamente o oposto do modelo de licença).
    expira_em               timestamptz NOT NULL,
    -- NULL = sem teto de usos (só a janela de tempo limita) -- um admin
    -- provisionando um número conhecido de máquinas pode opcionalmente
    -- travar em `max_usos` (ex.: "exatamente 20 laptops hoje").
    max_usos                integer CHECK (max_usos IS NULL OR max_usos > 0),
    usos                    integer NOT NULL DEFAULT 0,
    criado_em               timestamptz NOT NULL DEFAULT now(),
    criado_por_usuario_id   uuid REFERENCES usuarios(id)
);

ALTER TABLE agentes_enrollment_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE agentes_enrollment_tokens FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_agentes_enrollment_tokens ON agentes_enrollment_tokens;
CREATE POLICY tenant_isolation_agentes_enrollment_tokens ON agentes_enrollment_tokens
    USING (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- token_prefixo já é UNIQUE (cria o índice) -- documentado pelo mesmo
-- motivo do comentário equivalente em 0016/0019: o lookup de autenticação
-- (troca do token de enrollment pela identidade do agente) roda via
-- superadmin_scoped_connection (BYPASSRLS), mesmo problema de "ovo e
-- galinha" do login/agentes/licenças -- não se sabe o tenant antes de
-- resolver o token.
CREATE INDEX IF NOT EXISTS idx_agentes_enrollment_tokens_empresa ON agentes_enrollment_tokens (empresa_id);

-- Least-privilege igual ao resto do projeto: app_tenant nunca tem DELETE
-- (revogar é UPDATE de status, nunca apaga a linha -- mesma filosofia de
-- `agentes`/`licencas`).
GRANT SELECT, INSERT, UPDATE ON agentes_enrollment_tokens TO app_tenant;
GRANT SELECT, INSERT, UPDATE, DELETE ON agentes_enrollment_tokens TO app_superadmin;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_tenant, app_superadmin;
