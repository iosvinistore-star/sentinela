-- SENTINELA-COPYRIGHT-INICIO
-- Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
-- Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
-- Ver o arquivo LICENSE na raiz do projeto.
-- SENTINELA-COPYRIGHT-FIM
--
-- 0031 -- dados de CONTRATO da empresa cliente.
--
-- Até aqui `empresas` só tinha nome/plano/status: o suficiente para o
-- motor multi-tenant, mas não para a GESTÃO comercial (quem é o
-- responsável, qual o CNPJ, qual o número e a vigência do contrato).
-- Sem isso, o provedor mantinha essa informação fora do produto -- em
-- planilha -- e o cadastro de um cliente novo virava um roteiro de
-- várias telas. Estas colunas são todas opcionais de propósito: empresas
-- que já existem continuam válidas sem preencher nada.
--
-- CNPJ é único quando informado (índice parcial): dois contratos para o
-- mesmo CNPJ quase sempre são cadastro duplicado, mas NULL não colide
-- com NULL, então quem não informa não é afetado.

ALTER TABLE empresas ADD COLUMN IF NOT EXISTS cnpj              text;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS responsavel       text;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS email_contato     text;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS telefone          text;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS contrato_numero   text;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS contrato_vigencia date;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS observacoes       text;

CREATE UNIQUE INDEX IF NOT EXISTS uq_empresas_cnpj
    ON empresas (cnpj) WHERE cnpj IS NOT NULL;
