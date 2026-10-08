# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Dependências FastAPI de autenticação/autorização — nomes espelhando o
vocabulário do documento de migração original (`exigir_login`,
`exigir_papel`, `exigir_superadmin`), agora implementadas de verdade sobre
JWT em cookie + Postgres/RLS.

Preserva, no nível do banco (via `conexao_tenant`/`conexao_superadmin`), a
mesma garantia que o código legado tinha no nível de rota: "nenhum atalho
de conveniência — toda rota sensível é protegida por dependência de
autorização explícita".
"""
from datetime import datetime, timezone

from fastapi import Depends, Header, HTTPException, Request

from sentinela.auth.agentes import autenticar_agente, extrair_prefixo
from sentinela.auth.enrollment import autenticar_enrollment
from sentinela.auth.enrollment import extrair_prefixo as extrair_prefixo_enrollment
from sentinela.auth.licencas import autenticar_licenca
from sentinela.auth.licencas import extrair_prefixo as extrair_prefixo_licenca
from sentinela.auth.security import decodificar_token_sessao
from sentinela.core.log_context import adicionar_contexto
from sentinela.repositories.agentes import AgenteRepositorio
from sentinela.repositories.empresas import EmpresaRepositorio
from sentinela.repositories.licencas import LicencaRepositorio
from sentinela.repositories.superadmins import SuperadminRepositorio
from sentinela.repositories.usuarios import UsuarioRepositorio
from sentinela.util import obter_ip_cliente

HEADER_TOKEN_AGENTE = "X-Sentinela-Agent-Token"
# Header dedicado -- nunca reaproveita HEADER_TOKEN_AGENTE, que autentica um
# conceito totalmente diferente (Sentinela Endpoint/EDR, não licenciamento).
HEADER_TOKEN_LICENCA = "X-Sentinela-License-Token"
# Fase D / D3 -- header dedicado para o token de ENROLLMENT (ver
# ARQUITETURA_LICENCIAMENTO.md §12) -- nunca reaproveita HEADER_TOKEN_AGENTE
# nem HEADER_TOKEN_LICENCA, família de token própria.
HEADER_TOKEN_ENROLLMENT = "X-Sentinela-Enrollment-Token"

# Fase D / D6 -- anti-replay na validação de licença (ver
# ARQUITETURA_LICENCIAMENTO.md §11 para o desenho completo, escrito ANTES
# desta implementação -- por que estes dois headers, por que não HMAC, e
# por que agora é o melhor momento para tornar isto obrigatório: não existe
# ainda nenhum cliente Agent real em produção para quebrar).
HEADER_TIMESTAMP_LICENCA = "X-Sentinela-License-Timestamp"
HEADER_NONCE_LICENCA = "X-Sentinela-License-Nonce"
JANELA_REPLAY_SEGUNDOS = 300
_NONCE_TAMANHO_MIN = 1
_NONCE_TAMANHO_MAX = 128

# Fase C (MFA, C6) -- claim usada SÓ no token intermediário emitido entre
# "senha validada" e "desafio de MFA completo" (ver api/v1/auth.py:login/
# mfa_verificar e web/routes_auth.py:submeter_login/mfa_verificar_web).
# Centralizado aqui (não duplicado em cada módulo de rota) porque
# `usuario_atual` abaixo também precisa conhecer o nome da claim para
# recusar esse token como sessão comum.
PROPOSITO_PRE_AUTH_MFA = "mfa_pendente"
PRE_AUTH_MFA_TTL_SEGUNDOS = 300

NOME_COOKIE_SESSAO = "sentinela_session"
NOME_COOKIE_REFRESH = "sentinela_refresh"
HEADER_CSRF = "X-Sentinela-CSRF"
METODOS_MUTAVEIS = {"POST", "PUT", "PATCH", "DELETE"}
ROTAS_ISENTAS_DE_CSRF = {
    "/api/v1/auth/login",
    # /login (HTML, ver web/routes_auth.py) é um <form method="post"> comum,
    # sem JS -- não tem como carregar o header customizado antes da
    # primeira sessão existir (mesmo problema do /api/v1/auth/login). Não é
    # uma regressão de segurança: SameSite=Lax já não envia NENHUM cookie
    # de sessão pré-existente numa submissão de formulário cross-site, e
    # "login CSRF" (forjar a sessão de OUTRA pessoa) é um risco bem menor
    # que os que este header mitiga em rotas que mudam dados de uma sessão
    # já autenticada.
    "/login",
    # Fase C -- POST /login/mfa (web/routes_auth.py:submeter_mfa_login) é o
    # segundo passo do MESMO formulário de login sem JS: o usuário ainda
    # não tem cookie de sessão nenhum neste ponto (só o token intermediário
    # num campo hidden), então o mesmo raciocínio de "/login" acima se
    # aplica -- não há sessão prévia da qual carregar um header customizado.
    "/login/mfa",
}


def _settings(request: Request):
    return request.app.state.settings


def _pool(request: Request):
    return request.app.state.db


async def usuario_atual(request: Request) -> dict | None:
    """Decodifica o cookie de sessão, se presente e válido. Não levanta erro — quem exige login é `exigir_login`."""
    token = request.cookies.get(NOME_COOKIE_SESSAO)
    if not token:
        return None
    try:
        payload = decodificar_token_sessao(token, _settings(request).jwt_secret)
    except Exception:
        return None
    # Fase C (MFA, C6) -- um token "pré-autenticação" (emitido depois da
    # senha, ANTES do desafio de MFA -- ver api/v1/auth.py:login/
    # mfa_verificar) carrega a claim "purpose" e NUNCA deve autenticar
    # nada por si só, mesmo tendo as mesmas claims sub/papel/empresa_id/tv
    # de um token de sessão completo (é assinado com o mesmo segredo, só
    # dura alguns minutos, e só é aceito pelo endpoint de verificação de
    # MFA, que checa essa claim explicitamente). Sem esta rejeição, alguém
    # que interceptasse a resposta JSON do primeiro passo do login
    # (contendo esse token) poderia usá-lo como cookie de sessão comum e
    # pular o segundo fator por completo.
    if payload.get("purpose"):
        return None
    # Fase E / E2 -- enriquece o contexto de correlação (ver
    # core/log_context.py) assim que uma sessão humana é resolvida, para
    # que TODA linha de log emitida no resto desta requisição (de
    # qualquer módulo) já carregue quem fez a chamada, sem precisar
    # passar isso explicitamente a cada logger.info/warning/error.
    # Cobre tanto usuário de empresa quanto superadmin (o campo que
    # identifica qual dos dois muda conforme `papel`).
    if payload.get("papel") == "superadmin":
        adicionar_contexto(superadmin_id=payload.get("sub"))
    else:
        adicionar_contexto(usuario_id=payload.get("sub"), empresa_id=payload.get("empresa_id"), papel=payload.get("papel"))
    return payload


async def exigir_login(usuario: dict | None = Depends(usuario_atual)) -> dict:
    """Exige uma sessão de USUÁRIO de empresa (admin ou analista) — superadmin não conta aqui,
    ele tem seu próprio conjunto de rotas via `exigir_superadmin`."""
    if usuario is None or usuario.get("papel") == "superadmin":
        raise HTTPException(status_code=401, detail="login necessário")
    return usuario


def exigir_papel(*papeis_permitidos: str):
    """Uso: `Depends(exigir_papel("admin"))` — encadeia sobre exigir_login."""
    async def dependencia(usuario: dict = Depends(exigir_login)) -> dict:
        if usuario["papel"] not in papeis_permitidos:
            raise HTTPException(status_code=403, detail="sem permissão para esta ação")
        return usuario
    return dependencia


async def exigir_superadmin(usuario: dict | None = Depends(usuario_atual)) -> dict:
    if usuario is None or usuario.get("papel") != "superadmin":
        raise HTTPException(status_code=401, detail="acesso de superadmin necessário")
    return usuario


async def exigir_csrf_header(request: Request):
    """
    SameSite=Lax já bloqueia POST cross-site de formulário/fetch com
    cookies. Este header é um reforço barato: um atacante cross-site não
    consegue adicionar headers customizados a uma navegação/form submit,
    então a ausência dele numa rota mutável é motivo suficiente pra recusar.
    """
    if request.method in METODOS_MUTAVEIS and request.url.path not in ROTAS_ISENTAS_DE_CSRF:
        if request.headers.get(HEADER_CSRF) != "1":
            raise HTTPException(status_code=403, detail="cabeçalho CSRF ausente")


async def conexao_tenant(usuario: dict = Depends(exigir_login), request: Request = None):
    """
    Reforça `empresas.status == 'ativa'` em TODA requisição tenant-scoped,
    não só no login -- o JWT em si não sabe se a empresa foi suspensa
    depois de emitido (dura até `sessao_horas`), então sem esta checagem
    uma sessão já aberta continuaria com acesso total a uma empresa
    suspensa até o cookie expirar por conta própria. Requer o GRANT SELECT
    em `empresas` para app_tenant (ver migrations/0008_...sql).

    Mesmo raciocínio para `usuarios.ativo`/`papel`: o JWT também carrega o
    papel de quando a sessão foi emitida. Sem esta segunda checagem, um
    admin que desativa outro usuário (ou rebaixa um admin pra analista)
    não revoga nada de verdade -- a sessão já aberta continuaria com o
    papel ANTIGO (ex.: admin) até o cookie expirar por conta própria,
    horas depois. `ativo=false` ou um `papel` diferente do que está no
    token derruba a sessão imediatamente na próxima requisição.

    Mesmo raciocínio, agora para TROCA DE SENHA: `token_version` (coluna
    "tv" no JWT, ver migrations/0011_token_version.sql) é incrementado
    toda vez que a senha do usuário muda (services/usuarios.py:
    trocar_propria_senha, services/redefinicao_senha.py:
    confirmar_redefinicao). Um "tv" no token diferente do valor atual no
    banco -- inclusive um token que nem tem a claim, emitido antes desta
    migration -- derruba a sessão aqui, do mesmo jeito que `ativo=false`.
    Sem isso, trocar a senha (ex.: porque um cookie vazou) não invalidava
    nenhuma sessão já aberta em outro dispositivo com o cookie antigo.

    E, criticamente, `AND empresa_id = $2` abaixo -- o `empresa_id` que
    escopa a conexão RLS desta requisição (via `Database.tenant_session`)
    vem direto da claim `empresa_id` do JWT, sem nunca ter sido conferido
    contra o `empresa_id` DE VERDADE do usuário (`usuarios.sub`) no banco.
    Um JWT com assinatura válida mas claim `empresa_id` adulterada (ex.:
    segredo vazado, ou um bug futuro na emissão do token) fazia esta
    função confiar cegamente na empresa alegada pelo próprio token para
    setar `app.current_tenant` -- ou seja, a policy de RLS "funcionava
    perfeitamente" só que protegendo a empresa ERRADA, permitindo leitura
    E ESCRITA cross-tenant (incidentes, bloqueios de firewall etc. criados
    nesta sessão gravariam com o `empresa_id` forjado). Adicionar
    `empresa_id = $2` à mesma query faz a claim ser conferida contra a
    empresa real do usuário -- um `empresa_id` que não bate faz `linha`
    vir `None`, caindo no mesmo 401 de "sessão inválida" de qualquer outra
    adulteração de claim.
    """
    async with _pool(request).tenant_session(usuario["empresa_id"]) as sessao:
        status = await EmpresaRepositorio(sessao).obter_status(usuario["empresa_id"])
        if status != "ativa":
            raise HTTPException(status_code=403, detail=f"empresa {status} -- acesso bloqueado")
        linha = await UsuarioRepositorio(sessao).obter_para_sessao(usuario["sub"], usuario["empresa_id"])
        if (
            linha is None
            or not linha.ativo
            or linha.papel != usuario["papel"]
            or linha.token_version != usuario.get("tv")
        ):
            raise HTTPException(status_code=401, detail="sessão inválida -- faça login novamente")
        yield sessao


async def agente_atual(
    x_sentinela_agent_token: str = Header(..., alias=HEADER_TOKEN_AGENTE), request: Request = None
) -> dict:
    """
    Exige um AGENTE (Sentinela Endpoint) autenticado por token de longa
    duração no header `X-Sentinela-Agent-Token` -- nunca um cookie de
    sessão humana. Ver auth/agentes.py:autenticar_agente para a lógica de
    verificação (BYPASSRLS + bcrypt, mesmo padrão do login de usuário).

    Rate-limitado em DUAS camadas, checadas ANTES de chamar
    `autenticar_agente` -- correção de bug encontrado em revisão crítica
    (2026-09): sem nenhum limite, toda chamada a este endpoint (token
    válido, inválido ou ausente) roda `bcrypt.checkpw` na mesma threadpool
    compartilhada da aplicação, inclusive quando nenhum agente bate com o
    prefixo do token (ver o comentário sobre comparação timing-safe contra
    `_HASH_DUMMY` em auth/agentes.py:autenticar_agente) -- um atacante sem
    token nenhum conseguia esgotar essa threadpool só de bater neste
    endpoint em volume, degradando login, troca de senha e qualquer outra
    rota que dependa da mesma threadpool, para TODOS os tenants.

    Uma primeira versão desta correção chaveava só por IP -- e criou um
    bug novo: agentes EDR tipicamente saem por uma NAT/proxy corporativo
    compartilhado (o caso comum, não uma exceção), então 5 falhas de UM
    agente (ex.: um token já revogado que continua tentando, ou um
    atacante) bloqueavam TODOS os outros agentes legítimos atrás do mesmo
    IP por 5 minutos -- exatamente o cenário mais provável de acontecer
    (um admin revoga um agente suspeito, e se aquele agente for hostil,
    continuar retentando vira uma forma de cegar o monitoramento do resto
    da frota). Correção: a camada ESPECÍFICA (`limitador_login`, mesma
    instância do `/login`) agora chaveia por (ip, PREFIXO do token) --
    `extrair_prefixo` só faz parsing de formato, sem tocar banco/bcrypt,
    então é seguro rodar antes de qualquer rate limit. Um token
    revogado/errado continua acumulando falhas e sendo bloqueado
    normalmente (mesmo prefixo sempre, já que o token não muda), mas
    agentes diferentes (prefixos diferentes) atrás do mesmo IP nunca se
    bloqueiam entre si. Tokens malformados (sem prefixo reconhecível) caem
    todos numa chave "sem-prefixo" comum por IP -- ainda protege contra
    lixo básico sem punir ninguém especificamente.

    Isso abre uma via nova: nada impede um atacante de inventar um
    prefixo de 12 hex DIFERENTE a cada tentativa (extrair_prefixo só
    valida formato) para nunca acumular falha na mesma chave e driblar
    esta camada por completo. Por isso a segunda camada,
    `app.state.limitador_agente_ip` (instância separada, teto bem mais
    folgado -- ver main.py), olha só o IP, sem prefixo: um backstop de
    volume que não deveria nunca disparar para tráfego legítimo, mas
    limita qualquer flood de verdade, prefixos forjados inclusive.

    Um agente legítimo com token válido nunca é afetado pelas duas
    camadas: `registrar_sucesso` zera o contador da chave ESPECÍFICA dele
    a cada heartbeat bem-sucedido (mesmo padrão do `/api/v1/auth/login`),
    então heartbeats normais a cada 15-30s nunca acumulam falhas. O
    backstop por IP deliberadamente NÃO é zerado por nenhum sucesso -- ele
    só existe para conter volume, então decai sozinho pela janela (60s),
    nunca é resetado por um heartbeat válido de outro agente atrás do
    mesmo IP (isso permitiria a um atacante manter um flood "vivo" só
    intercalando uma tentativa válida ocasional).
    """
    settings = _settings(request)
    limitador = request.app.state.limitador_login
    limitador_ip = request.app.state.limitador_agente_ip
    ip_cliente = obter_ip_cliente(request, settings.proxies_confiaveis)

    chave_ip = f"agente-heartbeat-ip:{ip_cliente}"
    restante_ip = await limitador_ip.reservar_tentativa(chave_ip)
    if restante_ip > 0:
        raise HTTPException(
            status_code=429, detail=f"muitas tentativas -- tente de novo em {int(restante_ip) + 1} segundos",
            headers={"Retry-After": str(int(restante_ip) + 1)},
        )

    prefixo = extrair_prefixo(x_sentinela_agent_token or "") or "sem-prefixo"
    chave = f"agente-heartbeat:{ip_cliente}:{prefixo}"
    restante = await limitador.reservar_tentativa(chave)
    if restante > 0:
        raise HTTPException(
            status_code=429, detail=f"muitas tentativas -- tente de novo em {int(restante) + 1} segundos",
            headers={"Retry-After": str(int(restante) + 1)},
        )

    resultado = await autenticar_agente(_pool(request), x_sentinela_agent_token)
    if resultado is None:
        raise HTTPException(status_code=401, detail="token de agente inválido ou revogado")
    await limitador.registrar_sucesso(chave)
    # V8.2: o backstop por IP só deve contar FALHAS -- devolve a reserva
    # desta requisição legítima (ver LimitadorTentativasCompartilhado.devolver_tentativa).
    await limitador_ip.devolver_tentativa(chave_ip)
    # Fase E / E2 -- ver o comentário equivalente em usuario_atual.
    adicionar_contexto(agente_id=resultado.get("agente_id"), empresa_id=resultado.get("empresa_id"))
    return resultado


async def conexao_tenant_agente(agente: dict = Depends(agente_atual), request: Request = None):
    """
    Espelha `conexao_tenant` (mesma checagem de `empresas.status`), mas
    para um agente em vez de um usuário humano -- e adicionalmente exige
    `agentes_endpoint_habilitado = true`: se um superadmin desligar a
    capacidade para esta empresa DEPOIS que o agente já tinha um token
    válido, o heartbeat para de ser aceito na próxima tentativa, sem
    esperar o token expirar sozinho (ele não expira -- é revogação
    explícita ou esta checagem que interrompe o acesso).

    Fase D / D2 (ver ARQUITETURA_LICENCIAMENTO.md §10 e o docstring de
    `services/agentes.py:revogar_agente`, que documentava esta lacuna como
    trabalho futuro correspondente à Fase D): até aqui, a autenticação de
    heartbeat (token de agente) e o estado da LICENÇA da empresa eram dois
    mundos completamente desconectados -- revogar/suspender uma licença
    (via `/api/v1/admin/licencas/{id}/suspender|revogar`) não tinha efeito
    NENHUM sobre agentes já instalados, que continuavam mandando heartbeat
    (e abrindo incidentes) normalmente. Isto fecha essa lacuna reusando o
    vínculo que `services/agentes.py:criar_agente` (Fase D / D1) já grava em
    `licencas_endpoints` no momento da criação do agente: a cada heartbeat,
    reconfere o status da licença que ocupa a vaga deste agente (se
    houver), da MESMA forma que já reconfere `empresas.status` acima -- uma
    licença suspensa/revogada/expirada interrompe o próximo heartbeat
    imediatamente, sem esperar nenhum token expirar (nenhum dos dois tipos
    de token expira sozinho).

    Deliberadamente NÃO bloqueia um agente sem vaga nenhuma registrada
    (`vaga is None`): agentes criados antes desta correção, ou de uma
    empresa que nunca provisionou licença nenhuma (ver docstring de
    `criar_agente` -- licenciamento continua opcional), precisam continuar
    funcionando exatamente como antes -- zero regressão. O gate só existe
    quando um vínculo Agent<->Licença de fato existe.

    Usa 403 com `detail=f"licença {status}"` -- o MESMO formato já usado por
    `api/v1/licencas.py:_status_para_http` para o Agent validar sua própria
    licença -- em vez de inventar um código novo: um detail com o prefixo
    "licença " é o sinal "distinguível" que o Agent real (D4, ainda não
    construído) vai precisar reconhecer para diferenciar isto de "empresa
    inativa"/"capacidade desligada" (mensagens diferentes, mesmo 403) e do
    401 genérico de "token de agente inválido ou revogado" (`agente_atual`
    acima -- um problema no TOKEN do agente em si, não na licença que ele
    ocupa).

    Não aplica o grace period (`planos.recursos.grace_period_dias`,
    ARQUITETURA_LICENCIAMENTO.md §6) aqui -- grace period é tolerância do
    lado do AGENT a falha de rede/indisponibilidade do backend (cache
    local), nunca leniência do backend em si; o backend continua sendo a
    única fonte de verdade, sempre em tempo real, exatamente como o
    documento de arquitetura especifica.
    """
    async with _pool(request).tenant_session(agente["empresa_id"]) as sessao:
        linha = await EmpresaRepositorio(sessao).obter_status_e_agentes(agente["empresa_id"])
        if linha is None or linha.status != "ativa":
            raise HTTPException(status_code=403, detail="empresa inativa -- acesso bloqueado")
        if not linha.agentes_endpoint_habilitado:
            raise HTTPException(status_code=403, detail="capacidade Sentinela Endpoint não está habilitada para esta empresa")
        if not await AgenteRepositorio(sessao).esta_habilitado(agente["agente_id"], agente["empresa_id"]):
            raise HTTPException(status_code=403, detail="Agent desabilitado -- kill switch ativo")

        vaga = await LicencaRepositorio(sessao).status_da_licenca_do_agente(agente["agente_id"])
        if vaga is not None:
            status_licenca = vaga.status
            # Uma licença formalmente 'ativa' mas com `expira_em` no
            # passado é tratada como 'expirada' para efeito deste gate --
            # nenhum job de expiração automática existe ainda (fora de
            # escopo aqui; ver ARQUITETURA_LICENCIAMENTO.md), então sem
            # isto uma licença vencida e nunca revogada manualmente
            # continuaria autenticando heartbeats para sempre, o mesmo gap
            # que esta correção existe para fechar.
            if status_licenca == "ativa" and vaga.expira_em is not None and vaga.expira_em < datetime.now(timezone.utc):
                status_licenca = "expirada"
            if status_licenca != "ativa":
                raise HTTPException(status_code=403, detail=f"licença {status_licenca} -- Sentinela Endpoint suspenso")

        yield sessao


async def conexao_superadmin(su: dict = Depends(exigir_superadmin), request: Request = None):
    """
    Reforço em tempo real que espelha `conexao_tenant` acima, mas para
    superadmin -- ver migrations/0013_token_version_superadmin.sql para o
    porquê disto não existir desde o início (0011_token_version.sql
    deixou superadmin de fora de propósito, na época em que esta função
    não fazia checagem nenhuma). `token_version` ("tv" no JWT) diferente
    do valor atual no banco -- inclusive um token que nem tem a claim,
    emitido antes desta migration -- derruba a sessão aqui. Sem isto, a
    conta de maior impacto do sistema (superadmin enxerga/administra TODAS
    as empresas) só perdia acesso quando o cookie expirava sozinho, sem
    NENHUMA forma de revogar uma sessão comprometida antes disso (ver
    scripts/revogar_sessao_superadmin.py para a ferramenta operacional que
    incrementa esta coluna).

    Fase C: reconfere também `superadmins.papel` (SAAS_OWNER x SAAS_ADMIN,
    ver auth/rbac.py) contra a claim `papel_saas` do JWT -- mesmo
    raciocínio do `papel` de `usuarios` em `conexao_tenant`: se um Owner
    rebaixa outro superadmin de saas_owner para saas_admin (ou vice-versa),
    uma sessão já aberta com o nível ANTIGO não deve continuar valendo até
    o cookie expirar sozinho. Uma claim ausente (token emitido antes da
    Fase C) é tratada como 'saas_owner' -- mesma regra de compatibilidade
    de `auth/rbac.py:resolver_papel_conceitual`.
    """
    async with _pool(request).superadmin_session() as sessao:
        linha = await SuperadminRepositorio(sessao).obter_para_sessao(su["sub"])
        papel_saas_no_token = su.get("papel_saas") or "saas_owner"
        if (
            linha is None
            or linha.token_version != su.get("tv")
            or linha.papel != papel_saas_no_token
        ):
            raise HTTPException(status_code=401, detail="sessão inválida -- faça login novamente")
        yield sessao


def _timestamp_replay_valido(valor: str, agora: float) -> bool:
    """Fase D / D6 -- só parsing + aritmética, nenhum acesso a banco: roda
    ANTES de qualquer rate limit/bcrypt, mesmo raciocínio de
    `extrair_prefixo` já rodar antes das camadas caras. Um valor que não
    parseia como número, ou fora da janela de tolerância de clock skew
    (`JANELA_REPLAY_SEGUNDOS`, ver ARQUITETURA_LICENCIAMENTO.md §11), é
    tratado como inválido -- nunca levanta exceção aqui, quem chama decide
    o HTTPException."""
    try:
        timestamp = float(valor)
    except (TypeError, ValueError):
        return False
    return abs(agora - timestamp) <= JANELA_REPLAY_SEGUNDOS


async def _registrar_nonce_ou_recusar(db, licenca_id, nonce: str) -> bool:
    """
    Fase D / D6 -- registra `nonce` como usado para `licenca_id` (nunca
    global -- ver ARQUITETURA_LICENCIAMENTO.md §11) e devolve True na
    PRIMEIRA vez que aquele par aparece, False numa reapresentação (replay).
    `INSERT ... ON CONFLICT DO NOTHING RETURNING id` é atômico -- não há
    janela de corrida entre "checar se já existe" e "gravar" como haveria
    com um SELECT seguido de INSERT separado.

    A limpeza (`DELETE ... WHERE criado_em < now() - janela`) roda aqui,
    oportunisticamente, a cada chamada -- uma entrada mais velha que a
    própria janela de replay não tem mais nenhum uso (uma reapresentação
    daquele nonce já seria recusada pelo TIMESTAMP antes de chegar aqui, ver
    `_timestamp_replay_valido`), então não precisa de um job agendado à
    parte para a tabela não crescer sem limite.
    """
    async with db.superadmin_session() as sessao:
        repo = LicencaRepositorio(sessao)
        await repo.limpar_nonces_antigos(JANELA_REPLAY_SEGUNDOS)
        return await repo.registrar_nonce(licenca_id, nonce)


async def licenca_atual(
    x_sentinela_license_token: str = Header(..., alias=HEADER_TOKEN_LICENCA),
    x_sentinela_license_timestamp: str = Header(..., alias=HEADER_TIMESTAMP_LICENCA),
    x_sentinela_license_nonce: str = Header(..., alias=HEADER_NONCE_LICENCA),
    request: Request = None,
) -> dict:
    """
    Exige uma LICENÇA (Sentinela SaaS) autenticada por token de longa
    duração no header `X-Sentinela-License-Token` -- espelha `agente_atual`
    linha a linha (mesmo rate limiting em duas camadas, mesmo motivo -- ver
    o docstring de `agente_atual` para a análise completa de por que as duas
    camadas existem), mas para o conceito de licença, não de agente EDR.
    Usa instâncias PRÓPRIAS de limitador (`limitador_licenca`/
    `limitador_licenca_ip`, ver main.py) -- nunca reaproveita
    `limitador_login`/`limitador_agente_ip`, para que um token de licença
    ruim em loop não consuma o orçamento de tentativas de login humano nem
    do heartbeat de agentes, e vice-versa.

    Ao contrário de `autenticar_agente` (que já filtra `status = 'ativo'`
    na query), `autenticar_licenca` resolve o token independentemente do
    `status` da licença -- ver docstring de auth/licencas.py:
    autenticar_licenca para o porquê: o Agent precisa conseguir DISTINGUIR
    "token não existe" (401) de "licença suspensa" (403, com o status no
    corpo), então quem decide isso é a rota, não esta dependência.

    Fase D / D6 (ver ARQUITETURA_LICENCIAMENTO.md §11 para o desenho
    completo e por que HMAC não era viável aqui): exige também os headers
    `X-Sentinela-License-Timestamp`/`X-Sentinela-License-Nonce` em TODA
    chamada -- as 4 rotas de licença (`activate`/`validate`/`status`/
    `deactivate`) passam por aqui, então o gate de anti-replay vive num
    único lugar. Ordem das checagens (barato antes de caro, mesmo padrão já
    usado nas duas camadas de rate limit abaixo):

    1. Rate limiting (IP+prefixo, depois backstop por IP) -- já existia.
    2. Formato/janela do timestamp -- só parsing, sem tocar banco.
    3. `autenticar_licenca` (bcrypt) -- só depois disso sabemos `licenca_id`.
    4. Nonce não repetido PARA ESTA licença -- só pode rodar depois do
       passo 3, porque é escopado por `licenca_id`, nunca global.

    Um timestamp fora da janela ou um nonce já usado devolvem 401 -- mesmo
    código de "token inválido" já usado para as outras falhas de
    autenticação desta função (não vale a pena um código HTTP dedicado só
    para isto: do ponto de vista de quem chama, "sua requisição não foi
    aceita" é a mensagem certa nos três casos).
    """
    settings = _settings(request)
    limitador = request.app.state.limitador_licenca
    limitador_ip = request.app.state.limitador_licenca_ip
    ip_cliente = obter_ip_cliente(request, settings.proxies_confiaveis)

    chave_ip = f"licenca-ip:{ip_cliente}"
    restante_ip = await limitador_ip.reservar_tentativa(chave_ip)
    if restante_ip > 0:
        raise HTTPException(
            status_code=429, detail=f"muitas tentativas -- tente de novo em {int(restante_ip) + 1} segundos",
            headers={"Retry-After": str(int(restante_ip) + 1)},
        )

    prefixo = extrair_prefixo_licenca(x_sentinela_license_token or "") or "sem-prefixo"
    chave = f"licenca:{ip_cliente}:{prefixo}"
    restante = await limitador.reservar_tentativa(chave)
    if restante > 0:
        raise HTTPException(
            status_code=429, detail=f"muitas tentativas -- tente de novo em {int(restante) + 1} segundos",
            headers={"Retry-After": str(int(restante) + 1)},
        )

    agora = datetime.now(timezone.utc).timestamp()
    if not _timestamp_replay_valido(x_sentinela_license_timestamp, agora):
        raise HTTPException(status_code=401, detail="timestamp de anti-replay inválido ou fora da janela")
    if not (_NONCE_TAMANHO_MIN <= len(x_sentinela_license_nonce) <= _NONCE_TAMANHO_MAX):
        raise HTTPException(status_code=401, detail="nonce de anti-replay inválido")

    resultado = await autenticar_licenca(_pool(request), x_sentinela_license_token)
    if resultado is None:
        raise HTTPException(status_code=401, detail="token de licença inválido")
    await limitador.registrar_sucesso(chave)

    if not await _registrar_nonce_ou_recusar(_pool(request), resultado["licenca_id"], x_sentinela_license_nonce):
        raise HTTPException(status_code=401, detail="nonce já utilizado -- possível replay")

    # Fase E / E2 -- ver o comentário equivalente em usuario_atual.
    adicionar_contexto(licenca_id=resultado.get("licenca_id"), empresa_id=resultado.get("empresa_id"))
    return resultado


async def conexao_tenant_licenca(licenca: dict = Depends(licenca_atual), request: Request = None):
    """
    Espelha `conexao_tenant_agente`: reforça `empresas.status == 'ativa'` em
    toda requisição de licença -- se a EMPRESA (não a licença) estiver
    suspensa/cancelada, nenhuma rota de licenciamento deveria funcionar,
    independente do status da própria licença. Ao contrário de
    `conexao_tenant_agente`, não exige nenhuma flag de opt-in adicional --
    licenciamento não é uma capacidade que uma empresa liga/desliga, é
    inerente a toda empresa existir sob algum plano.
    """
    async with _pool(request).tenant_session(licenca["empresa_id"]) as sessao:
        status_empresa = await EmpresaRepositorio(sessao).obter_status(licenca["empresa_id"])
        if status_empresa != "ativa":
            raise HTTPException(status_code=403, detail=f"empresa {status_empresa} -- acesso bloqueado")
        yield sessao


async def enrollment_atual(
    x_sentinela_enrollment_token: str = Header(..., alias=HEADER_TOKEN_ENROLLMENT), request: Request = None
) -> dict:
    """
    Exige um TOKEN DE ENROLLMENT (Fase D / D3, ver
    ARQUITETURA_LICENCIAMENTO.md §12) válido no header
    `X-Sentinela-Enrollment-Token` -- espelha `agente_atual`/`licenca_atual`
    no padrão de rate limiting em duas camadas (mesmo motivo, ver o
    docstring de `agente_atual`), mas para a troca de enrollment por
    identidade de agente, não para heartbeat nem validação de licença. Usa
    instâncias PRÓPRIAS de limitador (`limitador_enrollment`/
    `limitador_enrollment_ip`, ver main.py) -- nunca reaproveita as de
    agente/licença, mesmo raciocínio de isolamento de orçamento já aplicado
    às outras duas famílias de token.

    Ao contrário de `autenticar_agente` (que já filtra `status = 'ativo'`
    na query) e igual a `autenticar_licenca`, `autenticar_enrollment`
    resolve o token independentemente do status/janela/teto de usos -- quem
    decide o HTTPException é `services/enrollment.py:trocar_por_agente`
    (403 com o motivo específico), não esta dependência (só 401 para "este
    token não corresponde a nenhum registro").
    """
    settings = _settings(request)
    limitador = request.app.state.limitador_enrollment
    limitador_ip = request.app.state.limitador_enrollment_ip
    ip_cliente = obter_ip_cliente(request, settings.proxies_confiaveis)

    chave_ip = f"enrollment-ip:{ip_cliente}"
    restante_ip = await limitador_ip.reservar_tentativa(chave_ip)
    if restante_ip > 0:
        raise HTTPException(
            status_code=429, detail=f"muitas tentativas -- tente de novo em {int(restante_ip) + 1} segundos",
            headers={"Retry-After": str(int(restante_ip) + 1)},
        )

    prefixo = extrair_prefixo_enrollment(x_sentinela_enrollment_token or "") or "sem-prefixo"
    chave = f"enrollment:{ip_cliente}:{prefixo}"
    restante = await limitador.reservar_tentativa(chave)
    if restante > 0:
        raise HTTPException(
            status_code=429, detail=f"muitas tentativas -- tente de novo em {int(restante) + 1} segundos",
            headers={"Retry-After": str(int(restante) + 1)},
        )

    resultado = await autenticar_enrollment(_pool(request), x_sentinela_enrollment_token)
    if resultado is None:
        raise HTTPException(status_code=401, detail="token de enrollment inválido")
    await limitador.registrar_sucesso(chave)
    # Fase E / E2 -- ver o comentário equivalente em usuario_atual.
    adicionar_contexto(enrollment_id=resultado.get("enrollment_id"), empresa_id=resultado.get("empresa_id"))
    return resultado


async def conexao_tenant_enrollment(enrollment: dict = Depends(enrollment_atual), request: Request = None):
    """
    Espelha `conexao_tenant_agente`: reforça `empresas.status == 'ativa'` E
    `agentes_endpoint_habilitado = true` -- um instalador recebe o 403 na
    hora da troca, não uma sequência confusa de "instalação disse OK, mas o
    agente nunca aparece ativo" descoberta só no primeiro heartbeat (ver
    ARQUITETURA_LICENCIAMENTO.md §12).
    """
    async with _pool(request).tenant_session(enrollment["empresa_id"]) as sessao:
        linha = await EmpresaRepositorio(sessao).obter_status_e_agentes(enrollment["empresa_id"])
        if linha is None or linha.status != "ativa":
            raise HTTPException(status_code=403, detail="empresa inativa -- acesso bloqueado")
        if not linha.agentes_endpoint_habilitado:
            raise HTTPException(status_code=403, detail="capacidade Sentinela Endpoint não está habilitada para esta empresa")
        yield sessao
