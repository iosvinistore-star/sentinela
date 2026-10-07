# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Módulo de resposta automática a incidentes: bloqueio de IPs via ipset + iptables/ip6tables.

ATENÇÃO — este módulo executa comandos REAIS no firewall por padrão (dry_run=False).
Requisitos:
    - Linux com iptables, ip6tables e ipset instalados
    - Privilégios de root (rodar com sudo)

Como funciona (desde esta versão): em vez de uma regra `iptables -A` por IP
bloqueado — que faz o kernel percorrer a lista inteira, regra por regra, a
cada pacote (custo O(n)) — mantemos dois conjuntos ipset, um para IPv4 e um
para IPv6, e uma ÚNICA regra em cada tabela apontando pro conjunto
(`-m set --match-set ... -j DROP`). Adicionar/remover um IP vira uma
operação de hash O(1) no kernel, e uma lista com centenas de milhares de
IPs bloqueados não degrada o desempenho do servidor.

Bônus real de usar ipset: ele suporta expiração nativa por entrada
(`ipset add <set> <ip> timeout <segundos>`) — o próprio kernel remove o IP
quando o prazo vence, sem depender de nenhum job externo (cron) pra isso
acontecer. `limpar_bloqueios_expirados()` deixou de precisar calcular prazo
sozinha: o papel dela agora é só manter nosso arquivo de metadados (motivo,
origem) sincronizado com o que o kernel já expirou de verdade.

Proteções incluídas para reduzir o risco de autobloqueio / bloqueio indevido:
    - Redes privadas/loopback/link-local (IPv4 e IPv6) nunca são bloqueadas
    - Suporte a whitelist de IPs adicionais (ex.: seu próprio IP de administração)
    - Toda ação é registrada em bloqueios_firewall.log e auditoria.jsonl
    - Existe desbloquear_ip() para reverter um bloqueio manualmente
"""
import datetime
import ipaddress
import json
import os
import shutil
import subprocess

from sentinela.core.redacao import mascarar_dados, mascarar_texto
from sentinela.core.segredos import obter_segredo
from sentinela.util import ip_valido

# SENTINELA_ESTADO_DIR (padrão "." -- preserva o comportamento de sempre
# para quem não define a variável, incluindo os testes, que sobrescrevem
# estas três constantes diretamente via monkeypatch em
# tests/conftest.py:isolar_arquivos_de_estado). Em Docker, setado para
# /app/data (ver Dockerfile/docker-compose.yml) -- conserta um bug
# pré-existente em que o bind mount ./data:/app/data do projeto Streamlit
# original nunca era usado por nada, e esses três arquivos (estado dos
# bloqueios, log e auditoria do firewall) morriam junto com o container.
_DIR_ESTADO = os.environ.get("SENTINELA_ESTADO_DIR", ".")

ARQUIVO_LOG_BLOQUEIOS = os.path.join(_DIR_ESTADO, "bloqueios_firewall.log")
ARQUIVO_AUDITORIA = os.path.join(_DIR_ESTADO, "auditoria.jsonl")
ARQUIVO_ESTADO = os.path.join(_DIR_ESTADO, "bloqueios_estado.json")
# Caminhos de sistema (iptables-persistent/ipset) -- não fazem parte do bug
# do bind mount acima, continuam fixos no host.
ARQUIVO_REGRAS_PERSISTIDAS = "/etc/iptables/rules.v4"
ARQUIVO_REGRAS_PERSISTIDAS_V6 = "/etc/iptables/rules.v6"
ARQUIVO_IPSET_PERSISTIDO = "/etc/ipset.conf"

IPSET_V4 = "analisador_bloqueios_v4"
IPSET_V6 = "analisador_bloqueios_v6"

REDES_PROTEGIDAS = [
    # IPv4
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    # IPv6
    ipaddress.ip_network("::1/128"),        # loopback
    ipaddress.ip_network("fc00::/7"),       # unique local (equivalente ao 10.x/192.168.x)
    ipaddress.ip_network("fe80::/10"),      # link-local
]


def _carregar_whitelist_protegida_do_ambiente():
    """
    Parseia `SENTINELA_FIREWALL_WHITELIST_PROTEGIDA` (IPs/CIDRs separados
    por vírgula) uma vez, na importação do módulo. Entradas malformadas são
    ignoradas silenciosamente (validação de configuração é responsabilidade
    de quem faz o deploy, não algo para derrubar o processo inteiro na
    inicialização por causa de uma vírgula sobrando).
    """
    bruto = obter_segredo("SENTINELA_FIREWALL_WHITELIST_PROTEGIDA", "") or ""
    redes = []
    for item in bruto.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            redes.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return redes


# Item 9 do plano de endurecimento pós-auditoria: "whitelist que a
# automação nunca pode remover ou burlar" (IP do admin, faixa de VPN,
# gateway, servidores DNS/críticos). Ao contrário do parâmetro `whitelist`
# de `bloquear_ip`/`ip_e_protegido` abaixo -- que é passado POR CHAMADA e
# que a automação (services/resposta_incidentes.py) podia simplesmente
# nunca preencher -- esta lista é uma CONSTANTE do módulo, carregada uma
# única vez do ambiente do processo na importação. Nenhum código da
# aplicação (automático ou não) tem como alterar ou contornar isto em
# tempo de execução; só um redeploy com uma variável de ambiente diferente
# muda a lista -- exatamente a mesma garantia de REDES_PROTEGIDAS acima,
# só que configurável por quem faz o deploy em vez de fixa no código.
REDE_PROTEGIDA_OPERADOR = _carregar_whitelist_protegida_do_ambiente()


def _conjunto_para_ip(ip):
    """Retorna o nome do ipset correto (v4 ou v6) para o IP informado."""
    endereco = ip_valido(ip)
    if endereco is None:
        raise ValueError(f"'{ip}' não é um endereço IP válido")
    return IPSET_V4 if endereco.version == 4 else IPSET_V6


def ip_e_protegido(ip, whitelist=None):
    """True se o IP não deve ser bloqueado (rede privada, loopback ou whitelist) — vale para IPv4 e IPv6."""
    whitelist = whitelist or []
    if ip in whitelist:
        return True
    # `ip_valido` (não `ipaddress.ip_address` direto) também rejeita a
    # notação de zone-id do IPv6 -- ver sentinela/util.py.
    endereco = ip_valido(ip)
    if endereco is None:
        return True  # não é um IP válido -> por segurança, não mexe
    # Endereço IPv4 mapeado em IPv6 (::ffff:a.b.c.d) representa o mesmo host
    # que o IPv4 equivalente -- sem resolver isso primeiro, ::ffff:127.0.0.1
    # ou ::ffff:10.0.0.5 não batiam com nenhuma rede de REDES_PROTEGIDAS
    # (comparação entre um IPv6Address e redes IPv4Network nunca dá match),
    # e um endereço de loopback/rede privada podia acabar sendo bloqueado.
    mapeado = getattr(endereco, "ipv4_mapped", None)
    if mapeado is not None:
        endereco = mapeado
    if any(endereco in rede for rede in REDES_PROTEGIDAS):
        return True
    # REDE_PROTEGIDA_OPERADOR -- ver o comentário longo acima de onde ela é
    # definida. Checada incondicionalmente, igual REDES_PROTEGIDAS: um
    # chamador (automação inclusive) não passa isto como argumento, então
    # não tem como "esquecer" de proteger essas entradas.
    return any(endereco in rede for rede in REDE_PROTEGIDA_OPERADOR)


def _tem_privilegios_root():
    """
    Item 20 do plano de endurecimento pós-auditoria: antes desta correção,
    esta função só checava `os.geteuid() == 0` -- verdadeiro sempre que o
    processo inteiro roda como root. Como o container agora roda a
    aplicação como usuário SEM privilégio (ver backend/Dockerfile),
    `os.geteuid()` nunca mais é 0 em produção, e as duas chamadoras desta
    função (`bloquear_ip`/`desbloquear_ip`) passariam a recusar TODO
    bloqueio com "requer root/sudo" -- mesmo que o comando `ipset`/
    `iptables` fosse, na prática, capaz de funcionar.

    A abordagem escolhida (ver Dockerfile) foi conceder CAP_NET_ADMIN +
    CAP_NET_RAW direto nos BINÁRIOS via `setcap`, não ao processo Python --
    o kernel concede essas capabilities ao processo FILHO (ipset/iptables)
    no momento do `exec()`, a partir do atributo estendido do próprio
    arquivo, independente de qualquer capability que o processo pai
    (Python/uvicorn) tenha. Ou seja: `os.geteuid()`/capabilities do
    processo Python NUNCA refletem se o comando vai funcionar nesse
    cenário -- só o próprio arquivo sabe.

    Em vez de decodificar o bitmask exato de capabilities do xattr
    `security.capability` (formato binário específico do kernel, frágil de
    parsear sem uma lib externa tipo python-prctl/pycapng, que este
    projeto não depende), checamos só a PRESENÇA desse atributo no binário
    `ipset` -- suficiente pra distinguir "alguém rodou setcap nisto" (o
    único jeito sancionado de chegar aqui, ver comentário no Dockerfile)
    de "binário comum, sem capability nenhuma". Um falso positivo aqui não
    é perigoso: se o setcap não cobriu a capability certa, ou o container
    não recebeu `cap_add: [NET_ADMIN, NET_RAW]` (ver docker-compose.yml),
    o comando `ipset`/`iptables` de verdade ainda falha logo em seguida, e
    esse erro real já é capturado (CalledProcessError, ver
    bloquear_ip/desbloquear_ip) e devolvido como status "erro" -- esta
    função é só um atalho pra uma mensagem mais clara no caso comum
    (totalmente sem privilégio nenhum, nem root nem capability), não a
    única linha de defesa.
    """
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return True
    if not hasattr(os, "getxattr"):
        return False  # plataforma sem suporte a xattr (não-Linux) -- nunca é o caso em produção
    caminho_ipset = shutil.which("ipset")
    if not caminho_ipset:
        return False
    try:
        os.getxattr(caminho_ipset, "security.capability")
        return True
    except OSError:
        return False


def _registrar(mensagem):
    # Item 16 do plano de endurecimento -- mensagem é texto livre (pode
    # conter, por exemplo, um motivo de bloqueio composto a partir de dados
    # de entrada); mascarar_texto só reconhece o FORMATO de um Bearer/JWT
    # solto dentro dela, então isto é defesa em profundidade barata.
    linha = f"{datetime.datetime.now().isoformat()} - {mascarar_texto(mensagem)}\n"
    try:
        with open(ARQUIVO_LOG_BLOQUEIOS, "a", encoding="utf-8") as f:
            f.write(linha)
    except OSError:
        pass
    print(linha.strip())


def _registrar_auditoria(evento):
    """Grava um evento estruturado em JSON Lines para auditoria (quem/quando/o quê/por quê)."""
    # Item 16 -- mesma lógica de services/auditoria.py:registrar_evento:
    # mascarar aqui, no único ponto de entrada deste arquivo de auditoria,
    # protege contra qualquer chamador futuro que inclua sem querer um
    # campo sensível em `evento`.
    evento_completo = {"timestamp": datetime.datetime.now().isoformat(), **mascarar_dados(evento)}
    try:
        with open(ARQUIVO_AUDITORIA, "a", encoding="utf-8") as f:
            f.write(json.dumps(evento_completo, ensure_ascii=False) + "\n")
    except OSError:
        pass


def _carregar_estado():
    if not os.path.exists(ARQUIVO_ESTADO):
        return {}
    try:
        with open(ARQUIVO_ESTADO, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _salvar_estado(estado):
    try:
        with open(ARQUIVO_ESTADO, "w", encoding="utf-8") as f:
            json.dump(estado, f, indent=2, ensure_ascii=False)
    except OSError:
        pass


def garantir_ipsets():
    """
    Cria os conjuntos ipset (v4/v6) e a regra em iptables/ip6tables que os
    referencia, se ainda não existirem. Idempotente — seguro chamar toda vez.
    """
    resultados = {}
    especificacoes = [
        (IPSET_V4, "inet", "iptables"),
        (IPSET_V6, "inet6", "ip6tables"),
    ]
    for nome_set, familia, binario_iptables in especificacoes:
        try:
            subprocess.run(
                ["ipset", "create", nome_set, "hash:ip", "family", familia, "timeout", "0", "-exist"],
                check=True, capture_output=True, text=True,
            )
            existe = subprocess.run(
                [binario_iptables, "-C", "INPUT", "-m", "set", "--match-set", nome_set, "src", "-j", "DROP"],
                capture_output=True,
            )
            if existe.returncode != 0:
                subprocess.run(
                    [binario_iptables, "-A", "INPUT", "-m", "set", "--match-set", nome_set, "src", "-j", "DROP"],
                    check=True, capture_output=True, text=True,
                )
            resultados[nome_set] = {"status": "ok"}
        except FileNotFoundError as e:
            resultados[nome_set] = {"status": "erro", "detalhe": f"binário não encontrado: {e}"}
        except subprocess.CalledProcessError as e:
            resultados[nome_set] = {"status": "erro", "detalhe": e.stderr}
    return resultados


def ip_ja_bloqueado(ip):
    """Verifica se o IP já está no conjunto ipset correspondente."""
    try:
        resultado = subprocess.run(
            ["ipset", "test", _conjunto_para_ip(ip), ip],
            capture_output=True,
        )
        return resultado.returncode == 0
    except (FileNotFoundError, ValueError):
        return False


def bloquear_ip(ip, motivo="", whitelist=None, dry_run=False, duracao_horas=24, origem="script", persistir=True):
    """
    Bloqueia um IP (IPv4 ou IPv6) adicionando ao conjunto ipset correto.

    duracao_horas: o próprio kernel expira a entrada depois desse prazo
        (via `timeout` do ipset) — não depende de nenhum job externo. Use
        None (ou 0) para bloqueio permanente (sem timeout).
    origem: identifica quem pediu o bloqueio (ex.: "cli", "dashboard") para
        o log de auditoria.

    Retorna um dict descrevendo o resultado: bloqueado / simulado / ignorado
    / erro.
    """
    duracao_horas = duracao_horas or None

    # Validar ANTES de qualquer _registrar()/_registrar_auditoria(): `ip`
    # aqui pode vir de um endpoint admin (`POST /api/v1/firewall/bloqueios`)
    # sem validação prévia de formato. `_registrar` escreve texto plano
    # sem nenhum escaping -- um valor com "\n" embutido conseguia forjar
    # linhas falsas em bloqueios_firewall.log (log forging). Cortando aqui,
    # a string bruta nunca chega a ser interpolada numa linha de log; o
    # `repr()` abaixo (só usado quando já sabemos que é inválido) neutraliza
    # quebras de linha/aspas para o caso de ainda assim precisarmos citar o
    # valor rejeitado.
    if ip_valido(ip) is None:
        _registrar(f"ERRO: {ip!r} não é um endereço IP válido")
        _registrar_auditoria({"acao": "erro", "ip": None, "origem": origem, "motivo": "endereço IP inválido"})
        return {"ip": ip, "status": "erro", "motivo": "endereço IP inválido"}

    if ip_e_protegido(ip, whitelist):
        _registrar(f"IGNORADO (protegido/whitelist): {ip}")
        _registrar_auditoria({"acao": "ignorado", "ip": ip, "origem": origem, "motivo": "IP protegido ou em whitelist"})
        return {"ip": ip, "status": "ignorado", "motivo": "IP protegido ou em whitelist"}

    conjunto = _conjunto_para_ip(ip)  # já validado acima, não deve levantar

    agora = datetime.datetime.now()
    expira_em = (agora + datetime.timedelta(hours=duracao_horas)).isoformat() if duracao_horas else None
    timeout_segundos = int(duracao_horas * 3600) if duracao_horas else 0  # 0 = sem expiração no ipset

    comando = ["ipset", "add", conjunto, ip, "timeout", str(timeout_segundos), "-exist"]

    if dry_run:
        _registrar(f"[DRY-RUN] comando não executado: {' '.join(comando)} (motivo: {motivo}; expiraria em: {expira_em or 'nunca'})")
        _registrar_auditoria({"acao": "simulado", "ip": ip, "origem": origem, "motivo": motivo, "expira_em": expira_em})
        return {"ip": ip, "status": "simulado", "comando": " ".join(comando), "expira_em": expira_em}

    if not _tem_privilegios_root():
        _registrar(f"ERRO: privilégios de root necessários para bloquear {ip}")
        _registrar_auditoria({"acao": "erro", "ip": ip, "origem": origem, "motivo": "requer root/sudo"})
        return {"ip": ip, "status": "erro", "motivo": "requer root/sudo"}

    ja_existia = ip_ja_bloqueado(ip)

    try:
        garantir_ipsets()
        subprocess.run(comando, check=True, capture_output=True, text=True)
        acao_log = "atualizado (expiração renovada)" if ja_existia else "bloqueado"
        _registrar(f"{acao_log.upper()}: {ip} (motivo: {motivo}; expira em: {expira_em or 'nunca'})")
        _registrar_auditoria({"acao": "bloqueio", "ip": ip, "origem": origem, "motivo": motivo, "expira_em": expira_em})

        estado = _carregar_estado()
        estado[ip] = {
            "bloqueado_em": agora.isoformat(),
            "expira_em": expira_em,
            "motivo": motivo,
            "origem": origem,
            "conjunto": conjunto,
        }
        _salvar_estado(estado)

        resultado_persistencia = persistir_regras() if persistir else {"status": "pulado"}

        return {
            "ip": ip,
            "status": "ja_bloqueado" if ja_existia else "bloqueado",
            "comando": " ".join(comando),
            "expira_em": expira_em,
            "persistencia": resultado_persistencia,
        }
    except FileNotFoundError:
        _registrar("ERRO: comando ipset não encontrado neste sistema")
        _registrar_auditoria({"acao": "erro", "ip": ip, "origem": origem, "motivo": "ipset não encontrado"})
        return {"ip": ip, "status": "erro", "motivo": "ipset não encontrado"}
    except subprocess.CalledProcessError as e:
        _registrar(f"ERRO ao bloquear {ip}: {e.stderr}")
        _registrar_auditoria({"acao": "erro", "ip": ip, "origem": origem, "motivo": e.stderr})
        return {"ip": ip, "status": "erro", "motivo": e.stderr}


def desbloquear_ip(ip, origem="script", motivo="manual", persistir=True):
    """Remove um IP do conjunto ipset (reverte um bloqueio, mesmo antes do prazo expirar)."""
    # Mesma validação de entrada de `bloquear_ip` -- ver o comentário lá.
    # Sem isso, `services/firewall.py:remover_bloqueio` seguia direto para
    # o UPDATE em Postgres (coluna `ip` do tipo `inet`) mesmo com um valor
    # inválido, quebrando com uma exceção crua (500) em vez de um erro
    # limpo -- e um valor com "\n" chegava a `_registrar` abaixo.
    if ip_valido(ip) is None:
        return {"ip": ip, "status": "erro", "motivo": "endereço IP inválido"}
    if not _tem_privilegios_root():
        return {"ip": ip, "status": "erro", "motivo": "requer root/sudo"}
    try:
        conjunto = _conjunto_para_ip(ip)
        subprocess.run(["ipset", "del", conjunto, ip, "-exist"], check=True, capture_output=True, text=True)
        _registrar(f"DESBLOQUEADO: {ip} (motivo: {motivo})")
        _registrar_auditoria({"acao": "desbloqueio", "ip": ip, "origem": origem, "motivo": motivo})

        estado = _carregar_estado()
        estado.pop(ip, None)
        _salvar_estado(estado)

        if persistir:
            persistir_regras()

        return {"ip": ip, "status": "desbloqueado"}
    except FileNotFoundError:
        return {"ip": ip, "status": "erro", "motivo": "ipset não encontrado"}
    except subprocess.CalledProcessError as e:
        _registrar(f"ERRO ao desbloquear {ip}: {e.stderr}")
        _registrar_auditoria({"acao": "erro", "ip": ip, "origem": origem, "motivo": e.stderr})
        return {"ip": ip, "status": "erro", "motivo": e.stderr}


def _listar_membros_ipset(nome_set):
    """Consulta o kernel (fonte da verdade) por quem está bloqueado agora em um conjunto."""
    try:
        resultado = subprocess.run(["ipset", "list", nome_set, "-output", "plain"], capture_output=True, text=True)
    except FileNotFoundError:
        return {}
    if resultado.returncode != 0:
        return {}

    membros = {}
    em_secao_membros = False
    for linha in resultado.stdout.splitlines():
        if linha.strip() == "Members:":
            em_secao_membros = True
            continue
        if not em_secao_membros or not linha.strip():
            continue
        partes = linha.split()
        ip = partes[0]
        timeout_restante = None
        if "timeout" in partes:
            try:
                timeout_restante = int(partes[partes.index("timeout") + 1])
            except (ValueError, IndexError):
                pass
        membros[ip] = {"timeout_restante_segundos": timeout_restante}
    return membros


def listar_bloqueios_ativos():
    """
    Retorna os IPs realmente bloqueados agora, direto do kernel (ipset é a
    fonte da verdade), enriquecidos com o motivo/origem guardados em
    bloqueios_estado.json quando disponíveis.
    """
    ativos = {}
    metadados = _carregar_estado()
    for nome_set in (IPSET_V4, IPSET_V6):
        for ip, info_kernel in _listar_membros_ipset(nome_set).items():
            entrada = dict(metadados.get(ip, {}))
            entrada.update(info_kernel)
            entrada.setdefault("conjunto", nome_set)
            ativos[ip] = entrada
    return ativos


def limpar_bloqueios_expirados(origem="limpeza_automatica"):
    """
    O kernel já expira os IPs sozinho (timeout nativo do ipset) — esta
    função só sincroniza bloqueios_estado.json, removendo metadados de IPs
    que não estão mais de fato bloqueados. Ainda vale rodar periodicamente
    (cron) para manter o arquivo de metadados enxuto, mas a proteção em si
    não depende mais disso.
    """
    ativos = listar_bloqueios_ativos()
    estado = _carregar_estado()
    removidos = []

    for ip in list(estado.keys()):
        if ip not in ativos:
            estado.pop(ip)
            removidos.append({"ip": ip, "status": "metadado_removido"})
            _registrar_auditoria({"acao": "sincronizacao", "ip": ip, "origem": origem, "motivo": "expirado no kernel"})

    _salvar_estado(estado)
    return removidos


def persistir_regras():
    """
    Salva o conteúdo dos conjuntos ipset e as regras iptables/ip6tables em
    disco (best-effort) para sobreviver a um reboot. Requer root.

    Atenção operacional: no boot, o conteúdo do ipset precisa ser restaurado
    ANTES das regras que o referenciam serem aplicadas (senão o `-m set
    --match-set` falha por o conjunto ainda não existir). No Debian/Ubuntu,
    o pacote `ipset-persistent` (ou um serviço systemd que rode
    `ipset restore < /etc/ipset.conf` antes do `netfilter-persistent`)
    cuida dessa ordem — não é algo que este script controla.
    """
    resultado = {}

    try:
        saida_ipset = subprocess.run(["ipset", "save"], capture_output=True, text=True, check=True)
        with open(ARQUIVO_IPSET_PERSISTIDO, "w", encoding="utf-8") as f:
            f.write(saida_ipset.stdout)
        resultado["ipset"] = {"status": "ok", "arquivo": ARQUIVO_IPSET_PERSISTIDO}
    except FileNotFoundError:
        resultado["ipset"] = {"status": "erro", "detalhe": "ipset não encontrado"}
    except (subprocess.CalledProcessError, OSError) as e:
        resultado["ipset"] = {"status": "erro", "detalhe": str(e)}

    for binario, caminho in ((["iptables-save"], ARQUIVO_REGRAS_PERSISTIDAS), (["ip6tables-save"], ARQUIVO_REGRAS_PERSISTIDAS_V6)):
        try:
            saida = subprocess.run(binario, capture_output=True, text=True, check=True)
            os.makedirs(os.path.dirname(caminho), exist_ok=True)
            with open(caminho, "w", encoding="utf-8") as f:
                f.write(saida.stdout)
            resultado[binario[0]] = {"status": "ok", "arquivo": caminho}
        except FileNotFoundError:
            resultado[binario[0]] = {"status": "erro", "detalhe": f"{binario[0]} não encontrado"}
        except (subprocess.CalledProcessError, OSError) as e:
            resultado[binario[0]] = {"status": "erro", "detalhe": str(e)}

    status_geral = "ok" if all(r["status"] == "ok" for r in resultado.values()) else "erro"
    return {"status": status_geral, "detalhe": resultado}
