-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
--
-- 0032 -- inscrições de notificação no celular (Web Push).
--
-- Cada linha é UM APARELHO que aceitou receber alerta. O mesmo usuário
-- costuma ter dois ou três (celular, tablet, desktop), e cada um tem o seu
-- endpoint, então a chave natural é o endpoint, não o usuário.
--
-- O que fica guardado aqui são as chaves PÚBLICAS do aparelho (p256dh) e o
-- segredo de autenticação que o próprio navegador gerou (auth). Com eles o
-- servidor só consegue mandar notificação para aquele aparelho -- não são
-- credencial de acesso ao sistema. Ainda assim a tabela entra no RLS como
-- todas as outras: uma empresa não tem por que enxergar os aparelhos de
-- outra.
--
-- `falhas_seguidas`: um endpoint morre em silêncio quando o usuário
-- desinstala o app ou limpa os dados do navegador. O serviço de push
-- responde 404/410 e nunca mais volta a funcionar. Sem contar as falhas, a
-- tabela viraria um cemitério de endpoints mortos que o sistema tenta
-- entregar para sempre, a cada alerta.

CREATE TABLE IF NOT EXISTS push_inscricoes (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    empresa_id      uuid REFERENCES empresas (id) ON DELETE CASCADE,
    usuario_id      uuid REFERENCES usuarios (id) ON DELETE CASCADE,
    superadmin_id   uuid REFERENCES superadmins (id) ON DELETE CASCADE,
    endpoint        text NOT NULL,
    chave_p256dh    text NOT NULL,
    chave_auth      text NOT NULL,
    aparelho        text,
    criada_em       timestamptz NOT NULL DEFAULT now(),
    usada_em        timestamptz,
    falhas_seguidas integer NOT NULL DEFAULT 0,
    -- Ou é de um usuário de empresa, ou é de uma conta de plataforma.
    -- Nunca das duas, nunca de nenhuma.
    CONSTRAINT push_dono_exclusivo CHECK (
        (usuario_id IS NOT NULL AND superadmin_id IS NULL AND empresa_id IS NOT NULL)
        OR (usuario_id IS NULL AND superadmin_id IS NOT NULL AND empresa_id IS NULL)
    )
);

-- O mesmo aparelho reinscrevendo é UPDATE, não linha nova (o navegador
-- renova a inscrição sozinho de tempos em tempos, com o mesmo endpoint).
CREATE UNIQUE INDEX IF NOT EXISTS uq_push_endpoint ON push_inscricoes (endpoint);
CREATE INDEX IF NOT EXISTS ix_push_empresa ON push_inscricoes (empresa_id) WHERE empresa_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_push_usuario ON push_inscricoes (usuario_id) WHERE usuario_id IS NOT NULL;

ALTER TABLE push_inscricoes ENABLE ROW LEVEL SECURITY;
ALTER TABLE push_inscricoes FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS push_inscricoes_isolamento ON push_inscricoes;
CREATE POLICY push_inscricoes_isolamento ON push_inscricoes
    USING (empresa_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (empresa_id = current_setting('app.current_tenant', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON push_inscricoes TO sentinela_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON push_inscricoes TO app_tenant;
GRANT SELECT, INSERT, UPDATE, DELETE ON push_inscricoes TO app_superadmin;
