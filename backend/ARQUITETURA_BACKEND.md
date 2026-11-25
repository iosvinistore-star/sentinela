# Arquitetura do backend

Backend do Sentinela SOC: **FastAPI + SQLAlchemy 2 (assíncrono, driver asyncpg) + PostgreSQL**, dividido em camadas.
Todo diálogo com o banco passa por UMA porta de entrada (`sentinela.database`) e por repositórios.

## Camadas

```
HTTP ─▶ api/ , web/         rotas: validação (Pydantic), autenticação/autorização, códigos HTTP
          │                  nunca escrevem SQL nem tocam em modelos ORM
          ▼
        services/ , siem/    regras de negócio e orquestração (transação, auditoria, criptografia, chamadas externas)
          │                  recebem uma AsyncSession já escopada; nunca abrem conexão própria
          ▼
        repositories/        acesso a dados: monta a consulta (ORM/Core), executa e devolve modelos/linhas
          │                  só `flush()`, nunca `commit()`; sem regra de negócio
          ▼
        models/              mapeamento ORM das tabelas (um módulo por domínio)
          ▼
        database/            config, engine, sessão com RLS por tenant (o ÚNICO lugar que abre conexão)
```

Regras de dependência: cada camada só chama a de baixo. `api/` não importa `repositories/`; `repositories/` não
importa `services/`.

## `sentinela/database/` — configuração e sessões

| Arquivo | Papel |
|---|---|
| `config.py` | `DatabaseSettings`: URL, tamanho do pool, timeouts, reciclagem de conexão, eco de SQL. Variáveis `SENTINELA_DB_*` (veja abaixo). Converte `postgresql://` em `postgresql+asyncpg://`. |
| `engine.py` | `criar_engine()`: `AsyncEngine` com `pool_pre_ping`. |
| `base.py` | `Base` declarativa; `Base.para_dict()` (omite colunas em `_sensiveis`, converte `inet` em `str`). |
| `sessao.py` | `Sessao`: `AsyncSession` com `populate_existing` por padrão (leitura do banco sempre vence o identity map). |
| `session.py` | `Database`: `tenant_session(empresa_id)`, `superadmin_session()`, `ping()`, `fechar()`. Vive em `app.state.db`. |

### Sessão por tenant (RLS)

```python
async with db.tenant_session(empresa_id) as sessao:     # SET LOCAL ROLE app_tenant + app.current_tenant
    ...                                                  # commit ao sair, rollback se levantar exceção
async with db.superadmin_session() as sessao:           # SET LOCAL ROLE app_superadmin (BYPASSRLS)
    ...
```

`SET LOCAL`/`set_config(..., true)` valem só dentro da transação: nada vaza para a próxima requisição que
reaproveitar a conexão do pool. Em rotas FastAPI use as dependências `conexao_tenant`, `conexao_superadmin`, etc.
(`auth/dependencies.py`), que entregam a sessão já escopada.

### Variáveis de ambiente

| Variável | Padrão | Uso |
|---|---|---|
| `DATABASE_URL` | — | DSN do role `sentinela_app` (runtime) |
| `DATABASE_URL_ADMIN` | — | DSN de superusuário (migrations / scripts) |
| `SENTINELA_DB_POOL_SIZE` | 10 | conexões permanentes |
| `SENTINELA_DB_MAX_OVERFLOW` | 10 | conexões extras sob pico |
| `SENTINELA_DB_POOL_TIMEOUT` | 30 | segundos esperando uma conexão livre |
| `SENTINELA_DB_POOL_RECYCLE` | 1800 | recicla conexões mais velhas que isso |
| `SENTINELA_DB_ECHO` | false | loga o SQL gerado |

## `sentinela/models/` — ORM

Um módulo por domínio: `tenancy` (empresas, usuários, superadmins, tokens, MFA), `licenciamento`, `agentes`,
`incidentes` (incidentes, firewall, auditoria, reputação, push), `siem`, `limitadores`.
O **schema pertence às migrations SQL** (`db/migrations`: roles, RLS, grants, índices parciais): os modelos o
espelham, não o criam. `tests/integration/test_models_schema.py` falha se divergirem.

Colunas sensíveis (`senha_hash`, `token_hash`, segredos TOTP, chaves de push) ficam em `_sensiveis` e **não saem** em
`para_dict()`.

## `sentinela/repositories/`

Um repositório por agregado (`UsuarioRepositorio`, `IncidenteRepositorio`, `LicencaRepositorio`, …), todos filhos de
`RepositorioBase(sessao)`. Convenções:

* só `flush()`; o commit é da sessão escopada;
* `UPDATE … RETURNING <Modelo>` com `synchronize_session=False` (a `Sessao` já usa `populate_existing`);
* upserts via `postgresql.insert(...).on_conflict_do_*`; predicado de índice parcial como `text("status = 'ativo'")`;
* métodos de consulta devolvem modelos ou `dict` simples (colunas públicas), nunca `Row` crua.

## Migrations

`db/migrations/*.sql` + `run_migrations.py` (asyncpg direto, DSN admin) continuam sendo o caminho de DDL: o schema
inclui roles, RLS e grants, que o autogenerate não cobre. É o único módulo fora de `database/` que abre conexão, e só
roda no deploy — nunca no processo da aplicação.

## Testes

`tests/sql_cru.py` oferece SQL cru **apenas para montar/inspecionar estado nos testes**; o código da aplicação não
tem SQL cru. Fixtures: `db` (`Database` do role `sentinela_app`) e `db_admin` (superusuário).
