# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Camada assíncrona sobre `core.firewall` (ipset/iptables via subprocess,
síncrono -- roda em `asyncio.to_thread`), sincronizando o resultado com a
tabela Postgres `bloqueios_firewall`.

LIMITAÇÃO CONHECIDA (ver README): o bloqueio em si (ipset/iptables) é a
nível de HOST, não de tenant -- bloquear um IP para a Empresa A bloqueia
esse IP para TODAS as empresas que compartilham este host/processo.
`bloqueios_firewall.empresa_id` identifica só quem pediu e pode
gerenciar/ver o pedido, não o limite real de enforcement. Por isso as
rotas que chamam `registrar_bloqueio`/`remover_bloqueio` são
admin-only (ver api/v1/firewall.py e web/routes_firewall.py).

Isolar de verdade por tenant exigiria network namespace/host por tenant
(fora de escopo enquanto o deploy for um único host/container -- mesmo
gatilho dos outros itens "fica no roadmap" do README). O que DÁ para
corrigir sem essa mudança maior -- e que `remover_bloqueio` abaixo faz --
é fechar dois jeitos de uma empresa mexer no bloqueio de OUTRA por causa
desse compartilhamento: desbloquear um IP que nunca foi bloqueio seu, ou
desbloquear no kernel um IP que outra empresa ainda precisa que continue
bloqueado. Ver o docstring de `remover_bloqueio`.
"""
import asyncio
import datetime

from sentinela.core import firewall as core_firewall
from sentinela.repositories.firewall import FirewallRepositorio
from sentinela.services import auditoria as servico_auditoria
from sentinela.services import automacao as servico_automacao
from sentinela.util import ip_valido, parse_datetime_iso

_STATUS_KERNEL_QUE_VIRAM_LINHA_ATIVA = {"bloqueado", "ja_bloqueado"}


async def registrar_bloqueio(sessao, empresa_id, ip: str, motivo: str, whitelist=None,
                               dry_run: bool = False, duracao_horas=24, origem: str = "api",
                               usuario_id=None, incidente_id=None):
    """
    `incidente_id` (item 10 do plano de endurecimento -- "rastreabilidade
    completa de bloqueio -> incidente que o originou") é opcional: None
    para um bloqueio manual (POST /api/v1/firewall/bloqueios), preenchido
    por services/resposta_incidentes.py quando o bloqueio veio de resposta
    automática a um incidente já criado.

    Capacidade 4 do modo autônomo (curadoria de `ips_protegidos`, ver
    services/automacao.py e migrations/0014_...sql): antes de tocar o
    kernel, mescla a whitelist persistida DESTE tenant (manual +
    auto-curada) com a `whitelist` recebida por chamada -- assim um IP que
    já foi protegido (manual ou automaticamente) nunca é bloqueado de
    novo, mesmo que o chamador não tenha se lembrado de passá-lo
    explicitamente."""
    # Correção de bug encontrado em revisão crítica (2026-09, achado 4):
    # TOCTOU cross-tenant entre este INSERT e a checagem+mutação de kernel
    # de `remover_bloqueio` para o MESMO IP -- ver o docstring de
    # `remover_bloqueio` abaixo para o cenário completo. O
    # `pg_advisory_xact_lock` aqui é chaveado só pelo IP (não por empresa
    # nem por linha específica -- de propósito: o enforcement do kernel é
    # HOST-WIDE, então a serialização também precisa ser host-wide, entre
    # QUALQUER tenant que mexa neste mesmo IP), e é mantido até o fim da
    # transação já aberta em `conn` (o mesmo padrão de
    # `LimitadorUploadsCompartilhado.reservar_volume`, ver
    # db/limitadores_compartilhados.py) -- garante que um `remover_bloqueio`
    # concorrente para este IP, de QUALQUER empresa, ou espera este INSERT
    # commitar (e enxerga a linha nova na sua checagem "outra empresa
    # depende"), ou já commitou antes deste INSERT começar.
    repo = FirewallRepositorio(sessao)
    await repo.travar_ip(ip)

    whitelist_persistida = await servico_automacao.listar_ips_protegidos_para_whitelist(sessao, empresa_id)
    whitelist_efetiva = list(whitelist or []) + whitelist_persistida

    resultado_kernel = await asyncio.to_thread(
        core_firewall.bloquear_ip, ip, motivo, whitelist_efetiva, dry_run, duracao_horas, origem, True,
    )

    if resultado_kernel["status"] in _STATUS_KERNEL_QUE_VIRAM_LINHA_ATIVA:
        expira_em = parse_datetime_iso(resultado_kernel.get("expira_em"))
        await repo.registrar_ativo(empresa_id, ip, motivo, origem, expira_em, usuario_id, incidente_id)
        await servico_auditoria.registrar_evento(
            sessao, empresa_id, "firewall.bloqueio_registrado",
            {"ip": ip, "motivo": motivo, "origem": origem, "status_kernel": resultado_kernel["status"],
             "incidente_id": incidente_id},
            ator_usuario_id=usuario_id,
        )

    return {"empresa_id": str(empresa_id), "ip": ip, "incidente_id": incidente_id, **resultado_kernel}


async def remover_bloqueio(sessao, db, empresa_id, ip: str, origem: str = "api", usuario_id=None):
    """
    `pool` (além de `sessao`, tenant-scoped) é necessário por causa da mesma
    LIMITAÇÃO CONHECIDA do topo do arquivo -- o enforcement no kernel é
    HOST-WIDE, compartilhado por todas as empresas, mas `sessao` (RLS) só
    enxerga as linhas da PRÓPRIA empresa. Duas checagens cross-tenant foram
    adicionadas aqui, ambas fechando um cenário em que uma empresa
    desfazia, sem saber, a proteção de OUTRA:

    1. Só chega a mexer no kernel se a PRÓPRIA empresa tiver um bloqueio
       'ativo' registrado para este IP -- antes, `DELETE
       /api/v1/firewall/bloqueios/{ip}` desbloqueava QUALQUER IP no host,
       mesmo um que esta empresa nunca bloqueou (ela só precisava
       adivinhar/enumerar o endereço). `test_remover_bloqueio_de_ip_sem_registro_proprio_nao_toca_kernel`
       cobre isso.
    2. Antes de desbloquear de fato, confere (via conexão superadmin,
       BYPASSRLS -- só ela enxerga bloqueios_firewall de TODAS as
       empresas) se alguma OUTRA empresa também tem este mesmo IP como
       'ativo'. Se tiver, a remoção só é aplicada à linha desta empresa no
       Postgres -- o kernel NÃO é tocado, porque a outra empresa ainda
       depende daquele bloqueio continuar valendo (duas empresas
       coincidindo em bloquear o mesmo IP -- ex.: um scanner conhecido --
       não é incomum). Sem isto, a primeira empresa a "desistir" do
       bloqueio destruía a proteção da segunda, que nunca pediu nada.
       `test_remover_bloqueio_nao_desbloqueia_kernel_se_outra_empresa_depende`
       cobre isso.

    Correção de bug encontrado em revisão crítica (2026-09, achado 4): a
    checagem #2 acima ("alguma outra empresa depende deste IP?") e a
    mutação de kernel que vem depois NÃO eram atômicas entre si em relação
    a uma chamada CONCORRENTE de `registrar_bloqueio` de outra empresa para
    o MESMO IP -- um TOCTOU clássico: tenant A lê "ninguém mais depende",
    tenant B COMMITA um novo bloqueio bem no meio disso (depois da leitura
    de A, antes do desbloqueio de A), e tenant A segue e desbloqueia o
    kernel de qualquer forma -- resultado: a linha do Postgres de B diz
    status='ativo', mas o enforcement real (kernel) já foi embora. O
    `pg_advisory_xact_lock` logo abaixo (mesma chave/IP que
    `registrar_bloqueio` usa) fecha isso: as duas operações para o mesmo IP,
    de qualquer tenant, agora serializam de verdade -- uma só começa depois
    que a outra commitou (ou nunca aconteceram, se não colidirem em IP).
    """
    # Valida ANTES de tocar o kernel ou o Postgres: sem isso, um `ip`
    # inválido (ex.: `DELETE /api/v1/firewall/bloqueios/xxx`) seguia direto
    # para o UPDATE abaixo -- coluna `bloqueios_firewall.ip` é `inet`, que
    # rejeita qualquer valor não-IP com uma exceção crua (500), mesmo
    # `desbloquear_ip` já tendo devolvido `status: "erro"` de forma limpa.
    if ip_valido(ip) is None:
        return {"empresa_id": str(empresa_id), "ip": ip, "status": "erro", "motivo": "endereço IP inválido"}

    # Ver o comentário acima e o de `registrar_bloqueio` -- mesma chave
    # (só o IP), pega ANTES de qualquer leitura cross-tenant ou mutação de
    # kernel, mantida até o fim da transação já aberta em `conn`.
    repo = FirewallRepositorio(sessao)
    await repo.travar_ip(ip)

    if not await repo.tem_ativo_proprio(empresa_id, ip):
        return {
            "empresa_id": str(empresa_id), "ip": ip, "status": "erro",
            "motivo": "nenhum bloqueio ativo desta empresa para este IP",
        }

    async with db.superadmin_session() as sessao_su:
        outra_empresa_depende = await FirewallRepositorio(sessao_su).outra_empresa_depende(empresa_id, ip)

    if outra_empresa_depende:
        resultado_kernel = {
            "ip": ip, "status": "removido_apenas_do_registro",
            "motivo": "IP continua bloqueado no host -- outra empresa também depende deste bloqueio",
        }
    else:
        resultado_kernel = await asyncio.to_thread(core_firewall.desbloquear_ip, ip, origem, "manual", True)

    linha = await repo.marcar_removido(empresa_id, ip)
    await servico_auditoria.registrar_evento(
        sessao, empresa_id, "firewall.bloqueio_removido",
        {"ip": ip, "origem": origem, "outra_empresa_ainda_bloqueia": bool(outra_empresa_depende)},
        ator_usuario_id=usuario_id,
    )

    # Capacidade 4 do modo autônomo: um HUMANO revertendo um bloqueio
    # AUTOMÁTICO (incidente_id não nulo) rápido demais é um sinal forte de
    # falso positivo -- protege o IP automaticamente para que a automação
    # não repita o mesmo erro contra ele. Reversão MANUAL de um bloqueio
    # manual (incidente_id nulo) não dispara isto: aí é só um admin
    # mudando de ideia sobre uma ação que ele mesmo tomou, não a automação
    # errando.
    if linha is not None and linha.incidente_id is not None:
        tempo_ativo = linha.removido_em - linha.bloqueado_em
        if tempo_ativo < datetime.timedelta(hours=servico_automacao.REVERSAO_RAPIDA_HORAS):
            await servico_automacao.adicionar_ip_protegido(
                sessao, empresa_id, ip,
                motivo="bloqueio automático revertido rapidamente por um humano (possível falso positivo)",
                origem="automatico", criado_por_usuario_id=usuario_id,
            )

    return {"empresa_id": str(empresa_id), "ip": ip, **resultado_kernel}


async def listar_bloqueios(sessao, empresa_id):
    """
    Interseção entre a verdade do kernel (quem está de fato bloqueado agora
    -- pode incluir IPs bloqueados por OUTRAS empresas, já que o bloqueio é
    host-wide) e as linhas que ESTA empresa registrou como 'ativo' no
    Postgres. Uma empresa só vê/gerencia os bloqueios que ela mesma pediu,
    mesmo que o enforcement real seja compartilhado.
    """
    ativos_kernel = await asyncio.to_thread(core_firewall.listar_bloqueios_ativos)
    linhas = await FirewallRepositorio(sessao).listar_ativos(empresa_id)
    resultado = []
    for linha in linhas:
        d = linha.para_dict()
        ip_str = d["ip"]  # `para_dict` já normaliza `inet` para str
        info_kernel = ativos_kernel.get(ip_str, {})
        d["ip"] = ip_str
        d["empresa_id"] = str(d["empresa_id"])
        d["ainda_ativo_no_kernel"] = ip_str in ativos_kernel
        d["timeout_restante_segundos"] = info_kernel.get("timeout_restante_segundos")
        resultado.append(d)
    return resultado


async def sincronizar_bloqueios_expirados(db, origem: str = "limpeza_automatica"):
    """
    O kernel expira IPs sozinho (timeout nativo do ipset). Esta função:
    1. deixa core.firewall sincronizar seus próprios metadados locais (JSON) --
       mesmo comportamento de antes da rearquitetura;
    2. sincroniza a tabela Postgres CROSS-TENANT (por isso usa uma conexão
       superadmin -- nenhuma empresa isolada teria visão de todos os
       bloqueios pra fazer essa comparação sozinha).

    Pensado para rodar periodicamente (cron/scheduler), não por requisição
    de usuário.
    """
    metadados_removidos = await asyncio.to_thread(core_firewall.limpar_bloqueios_expirados, origem)
    ativos_kernel = await asyncio.to_thread(core_firewall.listar_bloqueios_ativos)
    ips_ainda_ativos = list(ativos_kernel.keys())

    async with db.superadmin_session() as sessao:
        linhas_expiradas = await FirewallRepositorio(sessao).expirar_fora_do_kernel(ips_ainda_ativos)

    return {
        "metadados_kernel_removidos": metadados_removidos,
        "linhas_expiradas_no_postgres": linhas_expiradas,
    }
