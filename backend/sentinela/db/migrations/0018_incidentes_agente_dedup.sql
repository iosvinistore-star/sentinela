-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
-- Corrige bug encontrado em revisão crítica (2026-09): um processo
-- suspeito residente (ex.: mimikatz que continua rodando, ou uma
-- ferramenta legítima cujo nome bate por coincidência com um indicador
-- conhecido -- ver services/agentes.py:_INDICADORES_CRITICOS) abria um
-- incidente CRITICAL NOVO a cada heartbeat, a cada 15-30s, indefinidamente
-- -- inundação pura da tabela de incidentes e fadiga de alerta para quem
-- analisa, justamente para o caso mais grave (CRITICAL), que é onde
-- fadiga de alerta é mais perigosa.
--
-- A correção (`services/incidentes.py:obter_incidente_endpoint_aberto` /
-- `acrescentar_deteccoes`, chamadas por
-- `services/agentes.py:registrar_heartbeat`) precisa saber A QUAL AGENTE
-- um incidente pertence para poder perguntar "este agente já tem um
-- incidente aberto?" -- o `ip` sozinho não serve para isso: `ip_local` do
-- heartbeat é opcional e, sem ele, todo agente cai no mesmo placeholder
-- "0.0.0.0" (ver services/agentes.py), o que faria agentes DIFERENTES
-- (máquinas diferentes) se fundirem no mesmo incidente por engano.
--
-- Aditiva sobre 0016/0017 (nunca editados em place, mesma convenção do
-- resto deste diretório): coluna nova, NULLABLE (incidentes de origem
-- 'rede' nunca têm agente, ficam NULL para sempre -- comportamento
-- existente preservado).
ALTER TABLE incidentes ADD COLUMN IF NOT EXISTS agente_id uuid REFERENCES agentes(id);

-- Índice parcial (só linhas com agente_id) -- é exatamente o WHERE de
-- obter_incidente_endpoint_aberto (empresa_id, agente_id, status IN
-- ('OPEN','EM_ANDAMENTO')); incidentes de rede (agente_id NULL, a grande
-- maioria da tabela) nunca entram neste índice.
CREATE INDEX IF NOT EXISTS idx_incidentes_agente_aberto
    ON incidentes (empresa_id, agente_id, status)
    WHERE agente_id IS NOT NULL;
