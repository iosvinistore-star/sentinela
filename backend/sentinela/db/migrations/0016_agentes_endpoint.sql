-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
-- Sentinela Endpoint: primeira capacidade nova desde o modo autônomo --
-- agente local instalado na máquina do cliente (estilo EDR/antivírus),
-- reportando por heartbeat a este backend. Segue o mesmo padrão de
-- 0014_autonomia_operacional.sql: OPT-IN por tenant (default false), um
-- superadmin liga a capacidade em /admin/empresas -- nenhuma empresa
-- existente muda de comportamento só por rodar esta migration.
--
-- Decisão de escopo (ver documento de proposta técnica "Sentinela
-- Endpoint"): fase 1 é só OBSERVAÇÃO. O agente nunca decide nada sozinho
-- (não mata processo, não isola a máquina) -- ele só coleta e reporta, e
-- o backend decide se isso vira incidente, reaproveitando a MESMA tabela
-- `incidentes` que já existe para ataques de rede (ver alteração no fim
-- deste arquivo), não uma tabela paralela.

-- 1) Chave opt-in por tenant -- mesmo lugar/mesmo espírito de
--    modo_firewall_auto/auto_triagem_incidentes (0014): decisão
--    operacional do provedor do SOC, não algo que o próprio tenant liga
--    sozinho sem o superadmin saber.
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS agentes_endpoint_habilitado boolean NOT NULL DEFAULT false;

-- 2) Um agente por (empresa, hostname). Token de longa duração no formato
--    "agt_<prefixo hex>_<segredo>" -- só o PREFIXO fica em texto puro
--    (indexado, para lookup O(1) sem precisar rodar bcrypt contra todo
--    agente cadastrado a cada heartbeat); o token INTEIRO só existe em
--    hash (bcrypt, mesmo padrão de senha -- ver auth/agentes.py). Mostrado
--    ao admin da empresa UMA vez, na criação -- perdido o token, a única
--    forma de recuperar é revogar e criar outro (mesma filosofia de uma
--    API key comum).
CREATE TABLE IF NOT EXISTS agentes (
    id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    empresa_id             uuid NOT NULL REFERENCES empresas(id),
    hostname               text NOT NULL,
    sistema_operacional    text NOT NULL DEFAULT '',
    versao_agente          text NOT NULL DEFAULT '',
    token_prefixo          text NOT NULL UNIQUE,
    token_hash             text NOT NULL,
    status                 text NOT NULL DEFAULT 'ativo' CHECK (status IN ('ativo', 'revogado')),
    criado_por_usuario_id  uuid REFERENCES usuarios(id),
    criado_em              timestamptz NOT NULL DEFAULT now(),
    ultimo_heartbeat_em    timestamptz,
    UNIQUE (empresa_id, hostname)
);

ALTER TABLE agentes ENABLE ROW LEVEL SECURITY;
ALTER TABLE agentes FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_agentes ON agentes;
CREATE POLICY tenant_isolation_agentes ON agentes
    USING (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

CREATE INDEX IF NOT EXISTS idx_agentes_empresa ON agentes (empresa_id);
-- Usado só pelo lookup de autenticação (auth/agentes.py), que roda via
-- superadmin_scoped_connection (BYPASSRLS) -- não há como saber o tenant
-- ANTES de resolver o token, mesmo problema de "ovo e galinha" do login
-- de usuário (ver auth/login.py). token_prefixo já é UNIQUE acima, o que
-- cria o índice; esta linha existe só como documentação do motivo.

-- 3) Histórico bruto de cada heartbeat/evento -- separado de `incidentes`
--    de propósito: só os eventos que a avaliação de risco decide que
--    importam viram incidente de verdade (ver services/agentes.py). Sem
--    esta separação, o volume normal de heartbeats (a cada 15-30s, por
--    máquina) poluiria a tabela de incidentes com ruído.
CREATE TABLE IF NOT EXISTS agentes_eventos (
    id           bigserial PRIMARY KEY,
    empresa_id   uuid NOT NULL REFERENCES empresas(id),
    agente_id    uuid NOT NULL REFERENCES agentes(id),
    tipo         text NOT NULL CHECK (tipo IN ('heartbeat', 'processo_suspeito')),
    payload      jsonb NOT NULL,
    recebido_em  timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE agentes_eventos ENABLE ROW LEVEL SECURITY;
ALTER TABLE agentes_eventos FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_agentes_eventos ON agentes_eventos;
CREATE POLICY tenant_isolation_agentes_eventos ON agentes_eventos
    USING (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (empresa_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

CREATE INDEX IF NOT EXISTS idx_agentes_eventos_empresa_tempo ON agentes_eventos (empresa_id, recebido_em);
CREATE INDEX IF NOT EXISTS idx_agentes_eventos_agente ON agentes_eventos (agente_id, recebido_em);

-- Least-privilege igual ao resto do projeto (ver 0010_...sql e o
-- comentário equivalente em ips_protegidos, 0014_...sql): app_tenant
-- pode criar/atualizar/revogar seus próprios agentes (a rota de
-- heartbeat só faz UPDATE em ultimo_heartbeat_em, nunca DELETE -- revogar
-- é `status='revogado'`, preservando o histórico de agentes já usados,
-- nunca apagando a linha).
GRANT SELECT, INSERT, UPDATE ON agentes TO app_tenant;
GRANT SELECT, INSERT ON agentes_eventos TO app_tenant;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_tenant;

GRANT SELECT, INSERT, UPDATE, DELETE ON agentes, agentes_eventos TO app_superadmin;

-- 4) Unifica a origem do sinal na MESMA tabela de incidentes (em vez de um
--    painel/tabela paralela para "incidentes de endpoint") -- ver
--    services/incidentes.py:criar_incidente, que agora aceita um parâmetro
--    `origem` opcional (default 'rede', preservando o comportamento de
--    todo chamador existente que não passa esse argumento). DEFAULT +
--    NOT NULL torna esta uma migration aditiva seguramente aplicável em
--    cima de incidentes já existentes (todos ficam 'rede', o que sempre
--    foi verdade até aqui).
ALTER TABLE incidentes ADD COLUMN IF NOT EXISTS origem text NOT NULL DEFAULT 'rede' CHECK (origem IN ('rede', 'endpoint'));
CREATE INDEX IF NOT EXISTS idx_incidentes_origem ON incidentes (empresa_id, origem);
