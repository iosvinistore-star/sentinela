-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
-- Tabela de tokens do fluxo "esqueci minha senha" (services/redefinicao_senha.py).
--
-- Sem RLS -- mesma categoria de empresas/superadmins/reputacao_cache: essa
-- tabela só é tocada via superadmin_scoped_connection (BYPASSRLS), porque
-- o pedido de reset acontece ANTES do chamador estar autenticado (mesmo
-- problema de "ovo e galinha" do login -- ver auth/login.py).
--
-- Só o HASH do token fica gravado (sha256, ver services/redefinicao_senha.py)
-- -- alguém com acesso de leitura ao banco não consegue usar um token só de
-- ver a linha. `usado_em` marca uso único; `expira_em` limita a validade
-- (1h, ver VALIDADE_HORAS no service).
-- ON DELETE CASCADE: hoje nada no projeto apaga uma linha de `usuarios`
-- de verdade (atualizar_usuario só muda papel/ativo), mas sem o cascade
-- uma eventual exclusão de usuário ficaria bloqueada por um token de reset
-- órfão -- efeito colateral surpreendente de uma tabela que ninguém
-- lembraria de checar antes de apagar um usuário.
CREATE TABLE IF NOT EXISTS redefinicoes_senha (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    usuario_id    uuid NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
    token_hash    text NOT NULL UNIQUE,
    expira_em     timestamptz NOT NULL,
    usado_em      timestamptz,
    criado_em     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_redefinicoes_senha_usuario ON redefinicoes_senha (usuario_id);

GRANT SELECT, INSERT, UPDATE ON redefinicoes_senha TO app_superadmin;
