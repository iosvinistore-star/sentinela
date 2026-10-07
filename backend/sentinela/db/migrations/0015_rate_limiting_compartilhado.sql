-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
-- Item 4 das "Limitações conhecidas" do README: os limitadores de abuso
-- (login/troca de senha, volume de upload de log por usuário/empresa)
-- viviam em memória do processo (ver auth/rate_limit.py e
-- core/limites_upload.py) -- com mais de uma réplica/worker atrás de um
-- load balancer, cada réplica tinha seu PRÓPRIO contador, multiplicando o
-- limite efetivo pelo número de réplicas. Esta migration cria as duas
-- tabelas que sentinela/db/limitadores_compartilhados.py usa para um
-- contador de verdade COMPARTILHADO entre réplicas via Postgres -- sem
-- adicionar uma dependência de infraestrutura nova (Redis), já que o
-- Postgres já é a fonte de verdade do resto do projeto.
--
-- (A concorrência de PROCESSAMENTO de upload -- quantas análises de log
-- rodam ao mesmo tempo NESTE processo -- continua em memória de propósito:
-- ela protege a threadpool deste worker especificamente, não é uma cota
-- por cliente, então não faz sentido compartilhar entre réplicas. Ver
-- core/limites_upload.py e o comentário em
-- db/limitadores_compartilhados.py:LimitadorUploadsCompartilhado.)
--
-- Sem RLS de propósito: nenhuma das duas guarda dado de negócio POR
-- TENANT -- são estruturas de controle operacional, com chave textual já
-- namespaced pelo chamador (ex. "login:203.0.113.5",
-- "trocar-senha:<usuario_id>", "empresa:<empresa_id>"). Mesmo grupo de
-- `empresas`/`superadmins` (ver 0003_rls.sql, comentário final) -- só
-- acessadas via app_superadmin (BYPASSRLS), mesmo fora de uma rota
-- superadmin, porque não há tenant nenhum pra escopar aqui.

CREATE TABLE IF NOT EXISTS limite_tentativas (
    chave text PRIMARY KEY,
    -- Janela FIXA (não deslizante) de propósito: um contador exato de
    -- janela deslizante exigiria guardar cada tentativa individualmente
    -- (como o `OrderedDict` em memória fazia) e recalcular a soma a cada
    -- chamada -- correto, mas mais caro e mais difícil de manter atômico
    -- sob concorrência entre réplicas. Janela fixa é o MESMO trade-off que
    -- a alternativa mais comum (INCR + EXPIRE no Redis) faz, e é
    -- suficiente para o que isto protege (força bruta de senha): o pior
    -- caso é um atacante conseguir, na borda entre duas janelas, até 2x
    -- `max_tentativas` numa janela efetiva mais curta -- não uma
    -- degradação continuada.
    janela_inicio timestamptz NOT NULL,
    contador integer NOT NULL DEFAULT 1,
    bloqueado_ate timestamptz
);

-- Suporte à limpeza oportunista de linhas totalmente expiradas (ver
-- LimitadorTentativasCompartilhado._limpar_antigas_ocasionalmente) --
-- sem isto, o número de linhas cresceria para sempre num processo de
-- longa duração exposto à internet (scanners, IPs únicos que nunca
-- voltam), exatamente o problema que o teto de memória (`max_chaves`) do
-- LimitadorTentativas original documentava e resolvia do lado em memória.
CREATE INDEX IF NOT EXISTS idx_limite_tentativas_limpeza
    ON limite_tentativas (janela_inicio)
    WHERE bloqueado_ate IS NULL;

CREATE TABLE IF NOT EXISTS limite_upload_eventos (
    id bigserial PRIMARY KEY,
    chave text NOT NULL,
    ocorrido_em timestamptz NOT NULL DEFAULT now(),
    bytes bigint NOT NULL
);

-- Cobre tanto a leitura (soma por chave dentro da janela) quanto a
-- limpeza oportunista (mesmo raciocínio da tabela acima).
CREATE INDEX IF NOT EXISTS idx_limite_upload_eventos_chave_tempo
    ON limite_upload_eventos (chave, ocorrido_em);

GRANT SELECT, INSERT, UPDATE, DELETE ON limite_tentativas, limite_upload_eventos TO app_superadmin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_superadmin;
