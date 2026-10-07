# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Base dos repositórios (camada de acesso a dados).

Regras da camada:
- Repositório fala SQL (via ORM) e SÓ isso: nenhuma regra de negócio,
  nenhum `commit()` -- só `flush()`. Quem abre/fecha a transação é a
  sessão escopada (ver `sentinela.database.session`).
- Repositório recebe a `AsyncSession` já escopada ao tenant (ou superadmin);
  nunca abre conexão própria.
- Devolve modelos ORM (ou escalares/linhas). Quem converte para dict/JSON é
  a camada de serviço.
"""
from sqlalchemy.ext.asyncio import AsyncSession


class RepositorioBase:
    def __init__(self, sessao: AsyncSession):
        self.sessao = sessao
