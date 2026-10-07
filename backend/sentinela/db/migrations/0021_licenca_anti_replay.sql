-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
-- Fase D / D6 -- anti-replay para o token de licença (ver
-- ARQUITETURA_LICENCIAMENTO.md §11 para o desenho completo, escrito ANTES
-- desta migration). Aditiva sobre 0001-0020, nunca edita nada existente.
--
-- Gap identificado desde a etapa original de licenciamento
-- (GAP_REPORT_V3.1.md Fase 9: "a validação de licença é só bearer-token --
-- um token capturado pode ser reenviado indefinidamente"). Esta tabela
-- registra, POR LICENÇA (nunca global -- duas licenças diferentes podem
-- usar o mesmo valor de nonce sem colidir), os nonces já apresentados
-- dentro da janela de replay (5 minutos, ver
-- auth/dependencies.py:JANELA_REPLAY_SEGUNDOS) -- uma reapresentação do
-- MESMO (licenca_id, nonce) é recusada via a UNIQUE constraint abaixo
-- (INSERT ... ON CONFLICT DO NOTHING, atômico, sem race entre checar e
-- gravar).
-- `ON DELETE CASCADE` em `licenca_id` (ao contrário de `auditoria`, que
-- NUNCA cascateia -- trilha de auditoria tem valor histórico mesmo depois
-- que o ator/recurso é removido): um nonce usado não tem NENHUM valor
-- depois que a própria licença é apagada, mesmo raciocínio já aplicado a
-- `usuarios_mfa_recovery_codes.usuario_id` na Fase C. Sem isto, apagar uma
-- licença (só acontece via limpeza administrativa direta -- o fluxo normal
-- é sempre `status = 'revogada'`, nunca DELETE) ficaria bloqueado por
-- qualquer nonce residual dentro da janela de replay.
CREATE TABLE IF NOT EXISTS licencas_nonces_usados (
    id          bigserial PRIMARY KEY,
    licenca_id  uuid NOT NULL REFERENCES licencas(id) ON DELETE CASCADE,
    nonce       text NOT NULL,
    criado_em   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (licenca_id, nonce)
);

-- Sem RLS: o lookup roda em `Database.superadmin_session` (BYPASSRLS) --
-- mesmo "ovo e galinha" de `autenticar_licenca`/`agentes` (o token ainda
-- não foi resolvido para um tenant quando a checagem de nonce por si só
-- precisaria rodar; na prática a checagem de nonce só acontece DEPOIS de
-- `autenticar_licenca` já ter resolvido `licenca_id`, mas a conexão
-- tenant-scoped desta requisição ainda nem existe nesse ponto -- ela só é
-- aberta por `conexao_tenant_licenca`, uma dependência downstream). Nunca
-- exposta em nenhuma rota de leitura -- só escrita/limpeza pela camada de
-- autenticação.
CREATE INDEX IF NOT EXISTS idx_licencas_nonces_usados_criado_em ON licencas_nonces_usados (criado_em);

-- Least-privilege igual ao resto do projeto: só app_superadmin toca esta
-- tabela (é BYPASSRLS/Database.superadmin_session quem opera aqui, nunca
-- uma conexão tenant-scoped) -- inclusive DELETE, usado pela limpeza
-- oportunista de entradas já fora da janela de replay (ver docstring de
-- auth/dependencies.py:_registrar_nonce_ou_recusar).
GRANT SELECT, INSERT, DELETE ON licencas_nonces_usados TO app_superadmin;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_superadmin;
