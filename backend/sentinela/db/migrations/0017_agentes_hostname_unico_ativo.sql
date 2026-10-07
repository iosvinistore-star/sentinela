-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
-- Corrige bug encontrado em revisão crítica (2026-09): `agentes` tinha
-- `UNIQUE (empresa_id, hostname)` a nível de TABELA inteira (ver
-- 0016_agentes_endpoint.sql), sem escopo de status. Revogar um agente
-- (services/agentes.py:revogar_agente) NUNCA apaga a linha -- de
-- propósito, preserva o histórico de que aquele agente existiu e o que
-- reportou (mesmo espírito de ips_protegidos/sessão de superadmin, ver o
-- docstring da própria função). Mas com a constraint antiga, essa linha
-- revogada continuava ocupando o par (empresa_id, hostname) PARA SEMPRE:
-- reinstalar o agente na mesma máquina (cenário rotineiro -- reimagem de
-- disco, troca de hardware com o mesmo nome de host, ou simplesmente
-- "revoguei o token antigo e quero um novo para o mesmo host") batia num
-- 409 permanente em `criar_agente`, sem nenhuma saída a não ser o cliente
-- escolher um hostname diferente -- uma trava operacional real disfarçada
-- de erro de "hostname duplicado".
--
-- A correção: trocar a UNIQUE constraint de tabela inteira por um ÍNDICE
-- ÚNICO PARCIAL, escopado a `status = 'ativo'`. Múltiplas linhas
-- revogadas para o mesmo (empresa_id, hostname) passam a conviver
-- livremente (são só histórico), mas continua impossível ter DOIS
-- agentes ATIVOS simultâneos para o mesmo (empresa_id, hostname) -- a
-- garantia original que a constraint existia para dar continua de pé.
--
-- Aditiva sobre 0016 (nunca editado em place, mesma convenção do resto
-- deste diretório): a constraint antiga é derrubada e substituída por um
-- índice parcial equivalente em espírito, mais permissivo em escopo.
ALTER TABLE agentes DROP CONSTRAINT IF EXISTS agentes_empresa_id_hostname_key;

CREATE UNIQUE INDEX IF NOT EXISTS idx_agentes_empresa_hostname_ativo
    ON agentes (empresa_id, hostname)
    WHERE status = 'ativo';
