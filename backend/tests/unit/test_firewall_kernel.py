# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Testes do módulo de firewall (firewall.py) — versão baseada em ipset, com
suporte a IPv4 e IPv6.

IMPORTANTE: nenhum teste aqui chama o ipset/iptables de verdade. Todo
subprocess.run é mockado — os testes validam a LÓGICA (quem é protegido, o
que vai pro estado, o que é persistido, o que o kernel diz que está
bloqueado), não o comportamento real do kernel. Esse comportamento real é
validado à parte, manualmente, fora da suíte automatizada (ver sessão de
demonstração). A fixture `isolar_arquivos_de_estado` (em conftest.py)
redireciona os arquivos de estado/log/auditoria para um diretório temporário.
"""
import ipaddress
from unittest.mock import MagicMock, patch

from sentinela.core import firewall


def _resultado(returncode=0, stdout=""):
    r = MagicMock()
    r.returncode = returncode
    r.stdout = stdout
    return r


def _fake_subprocess_run(ja_bloqueado=False):
    """
    Substituto de subprocess.run que responde de forma coerente pros
    diferentes comandos que firewall.py dispara (ipset test/add/del/save/create,
    iptables/ip6tables -C/-A/-save), sem tocar o sistema real.
    """
    def _run(cmd, **kwargs):
        if cmd[:2] == ["ipset", "test"]:
            return _resultado(returncode=0 if ja_bloqueado else 1)
        if cmd[:2] == ["ipset", "save"]:
            return _resultado(stdout="# ipset mock\n")
        if cmd and cmd[0] in ("iptables-save", "ip6tables-save"):
            return _resultado(stdout="# regras mock\n")
        if len(cmd) >= 2 and cmd[1] == "-C":
            return _resultado(returncode=0)  # regra já existe -> não precisa -A
        return _resultado()
    return _run


# ---------------------------------------------------------------------------
# ip_e_protegido (IPv4 + IPv6)
# ---------------------------------------------------------------------------

def test_redes_privadas_ipv4_sao_protegidas():
    for ip in ["10.0.0.5", "192.168.1.1", "127.0.0.1", "172.16.5.5", "169.254.1.1"]:
        assert firewall.ip_e_protegido(ip) is True


def test_redes_privadas_ipv6_sao_protegidas():
    for ip in ["::1", "fe80::1", "fc00::1", "fd12:3456:789a::1"]:
        assert firewall.ip_e_protegido(ip) is True


def test_ip_publico_v4_nao_e_protegido_por_padrao():
    assert firewall.ip_e_protegido("203.0.113.5") is False


def test_ipv4_mapeado_em_ipv6_e_reconhecido_como_protegido():
    """
    Regressão: ::ffff:a.b.c.d representa o MESMO host que o IPv4 a.b.c.d --
    antes da correção, esse formato não batia com nenhuma rede de
    REDES_PROTEGIDAS (comparar um IPv6Address direto com uma IPv4Network
    nunca dá match), então um loopback/rede privada nessa notação podia
    ser bloqueado por engano.
    """
    assert firewall.ip_e_protegido("::ffff:127.0.0.1") is True   # loopback
    assert firewall.ip_e_protegido("::ffff:10.0.0.5") is True    # rede privada (10/8)
    assert firewall.ip_e_protegido("::ffff:192.168.1.1") is True  # rede privada (192.168/16)


def test_ipv4_mapeado_em_ipv6_publico_nao_e_protegido():
    """O mapeamento não deve virar um bypass de proteção ao contrário: um IP
    público mapeado em IPv6 continua bloqueável normalmente."""
    assert firewall.ip_e_protegido("::ffff:8.8.8.8") is False


def test_ip_publico_v6_nao_e_protegido_por_padrao():
    assert firewall.ip_e_protegido("2001:db8::1") is False


def test_ip_em_whitelist_e_protegido():
    assert firewall.ip_e_protegido("203.0.113.5", whitelist=["203.0.113.5"]) is True


def test_ip_invalido_e_tratado_como_protegido_por_seguranca():
    assert firewall.ip_e_protegido("nao-e-um-ip") is True


# ---------------------------------------------------------------------------
# REDE_PROTEGIDA_OPERADOR -- item 9 do plano de endurecimento ("whitelist
# que a automação nunca pode remover ou burlar", ver o comentário longo em
# core/firewall.py de onde ela é definida).
# ---------------------------------------------------------------------------

def test_parse_whitelist_protegida_aceita_ips_e_cidrs(monkeypatch):
    monkeypatch.setenv("SENTINELA_FIREWALL_WHITELIST_PROTEGIDA", "203.0.113.9, 198.51.100.0/24")
    redes = firewall._carregar_whitelist_protegida_do_ambiente()
    assert len(redes) == 2
    assert str(redes[0]) == "203.0.113.9/32"
    assert str(redes[1]) == "198.51.100.0/24"


def test_parse_whitelist_protegida_ignora_entradas_malformadas(monkeypatch):
    monkeypatch.setenv("SENTINELA_FIREWALL_WHITELIST_PROTEGIDA", "isso-nao-e-um-ip, 203.0.113.9")
    redes = firewall._carregar_whitelist_protegida_do_ambiente()
    assert len(redes) == 1
    assert str(redes[0]) == "203.0.113.9/32"


def test_parse_whitelist_protegida_vazia_por_padrao(monkeypatch):
    monkeypatch.delenv("SENTINELA_FIREWALL_WHITELIST_PROTEGIDA", raising=False)
    assert firewall._carregar_whitelist_protegida_do_ambiente() == []


def test_ip_na_rede_protegida_do_operador_e_protegido(monkeypatch):
    """Ao contrário do parâmetro `whitelist` (por chamada), esta lista é
    checada incondicionalmente -- nem precisa (nem pode) ser passada pelo
    chamador."""
    monkeypatch.setattr(firewall, "REDE_PROTEGIDA_OPERADOR", [ipaddress.ip_network("203.0.113.9/32")])
    assert firewall.ip_e_protegido("203.0.113.9") is True
    assert firewall.ip_e_protegido("203.0.113.10") is False


def test_bloquear_ip_na_whitelist_protegida_do_operador_e_ignorado(monkeypatch):
    monkeypatch.setattr(firewall, "REDE_PROTEGIDA_OPERADOR", [ipaddress.ip_network("203.0.113.9/32")])
    with patch.object(firewall.subprocess, "run") as run_mock:
        resultado = firewall.bloquear_ip("203.0.113.9", motivo="tentativa de bloquear IP protegido pelo operador")
    assert resultado["status"] == "ignorado"
    run_mock.assert_not_called()


# ---------------------------------------------------------------------------
# _tem_privilegios_root -- item 20 do plano de endurecimento (container
# não-root + capabilities de arquivo via setcap, ver backend/Dockerfile)
# ---------------------------------------------------------------------------

def test_tem_privilegios_root_verdadeiro_quando_euid_zero():
    with patch.object(firewall.os, "geteuid", return_value=0, create=True):
        assert firewall._tem_privilegios_root() is True


def test_tem_privilegios_root_verdadeiro_quando_binario_tem_capability_de_arquivo():
    """Não-root (euid != 0), mas o binário `ipset` tem o xattr
    security.capability -- o cenário real de produção depois desta
    correção (ver Dockerfile: setcap cap_net_admin,cap_net_raw+ep nos
    binários, container roda com USER sentinela)."""
    with patch.object(firewall.os, "geteuid", return_value=1000, create=True), \
         patch.object(firewall.shutil, "which", return_value="/usr/sbin/ipset"), \
         patch.object(firewall.os, "getxattr", return_value=b"qualquer-coisa", create=True):
        assert firewall._tem_privilegios_root() is True


def test_tem_privilegios_root_falso_sem_euid_zero_e_sem_capability():
    with patch.object(firewall.os, "geteuid", return_value=1000, create=True), \
         patch.object(firewall.shutil, "which", return_value="/usr/sbin/ipset"), \
         patch.object(firewall.os, "getxattr", side_effect=OSError("no such attribute"), create=True):
        assert firewall._tem_privilegios_root() is False


def test_tem_privilegios_root_falso_quando_ipset_nao_esta_no_path():
    with patch.object(firewall.os, "geteuid", return_value=1000, create=True), \
         patch.object(firewall.shutil, "which", return_value=None):
        assert firewall._tem_privilegios_root() is False


# ---------------------------------------------------------------------------
# bloquear_ip
# ---------------------------------------------------------------------------

def test_bloquear_ip_protegido_nao_toca_subprocess():
    with patch.object(firewall.subprocess, "run") as run_mock:
        resultado = firewall.bloquear_ip("10.0.0.5", motivo="teste")
    assert resultado["status"] == "ignorado"
    run_mock.assert_not_called()


def test_bloquear_ip_dry_run_nao_executa_comando_real():
    with patch.object(firewall.subprocess, "run") as run_mock:
        resultado = firewall.bloquear_ip("203.0.113.9", motivo="teste", dry_run=True, duracao_horas=2)
    assert resultado["status"] == "simulado"
    assert resultado["expira_em"] is not None
    assert "ipset add" in resultado["comando"]
    run_mock.assert_not_called()


def test_bloquear_ip_sem_privilegios_root_retorna_erro():
    with patch.object(firewall, "_tem_privilegios_root", return_value=False), \
         patch.object(firewall.subprocess, "run") as run_mock:
        resultado = firewall.bloquear_ip("203.0.113.9", motivo="teste", dry_run=False)
    assert resultado["status"] == "erro"
    assert "root" in resultado["motivo"]
    run_mock.assert_not_called()


def test_bloquear_ip_ipv4_sucesso_usa_conjunto_v4(tmp_path):
    with patch.object(firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(firewall.subprocess, "run", side_effect=_fake_subprocess_run(ja_bloqueado=False)):
        resultado = firewall.bloquear_ip(
            "203.0.113.9", motivo="6 ataques detectados", dry_run=False, duracao_horas=2, origem="teste-pytest"
        )

    assert resultado["status"] == "bloqueado"
    assert resultado["expira_em"] is not None
    assert f"ipset add {firewall.IPSET_V4}" in resultado["comando"]
    assert resultado["persistencia"]["status"] == "ok"

    estado = firewall._carregar_estado()
    assert estado["203.0.113.9"]["conjunto"] == firewall.IPSET_V4


def test_bloquear_ip_ipv6_sucesso_usa_conjunto_v6():
    with patch.object(firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(firewall.subprocess, "run", side_effect=_fake_subprocess_run(ja_bloqueado=False)):
        resultado = firewall.bloquear_ip("2001:db8::dead", motivo="teste", dry_run=False, duracao_horas=1)

    assert resultado["status"] == "bloqueado"
    assert f"ipset add {firewall.IPSET_V6}" in resultado["comando"]
    estado = firewall._carregar_estado()
    assert estado["2001:db8::dead"]["conjunto"] == firewall.IPSET_V6


def test_bloquear_ip_permanente_usa_timeout_zero():
    with patch.object(firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(firewall.subprocess, "run", side_effect=_fake_subprocess_run(ja_bloqueado=False)):
        resultado = firewall.bloquear_ip("203.0.113.9", motivo="permanente", dry_run=False, duracao_horas=0)
    assert resultado["expira_em"] is None
    assert "timeout 0" in resultado["comando"]


def test_bloquear_ip_ja_bloqueado_atualiza_expiracao_sem_erro():
    with patch.object(firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(firewall.subprocess, "run", side_effect=_fake_subprocess_run(ja_bloqueado=True)):
        resultado = firewall.bloquear_ip("203.0.113.9", motivo="renovando", dry_run=False, duracao_horas=4)
    assert resultado["status"] == "ja_bloqueado"


def test_bloquear_ip_endereco_invalido_e_rejeitado_com_seguranca():
    # bloquear_ip() valida com util.ip_valido ANTES de qualquer outra coisa
    # (inclusive antes de ip_e_protegido) -- o bloqueio nunca chega a tentar
    # montar um comando ipset com lixo, e o motivo agora é "erro" (não mais
    # "ignorado", que sugeria "é um IP válido só que protegido/whitelist").
    resultado = firewall.bloquear_ip("nao-e-ip-valido-9999", motivo="teste", dry_run=False)
    assert resultado["status"] == "erro"
    assert resultado["motivo"] == "endereço IP inválido"


def test_bloquear_ip_com_zone_id_ipv6_e_rejeitado():
    """ipaddress.ip_address() sozinho aceita a notação de zone-id do IPv6
    (RFC 4007, ex. "fe80::1%eth0"), mas o Postgres `inet` não entende essa
    sintaxe -- util.ip_valido() precisa rejeitar isso antes que chegue lá."""
    resultado = firewall.bloquear_ip("2606:4700:4700::1111%eth0", motivo="teste", dry_run=False)
    assert resultado["status"] == "erro"
    assert resultado["motivo"] == "endereço IP inválido"


# ---------------------------------------------------------------------------
# desbloquear_ip
# ---------------------------------------------------------------------------

def test_desbloquear_ip_remove_do_estado():
    firewall._salvar_estado({"203.0.113.9": {"bloqueado_em": "x", "expira_em": None, "motivo": "y", "origem": "z"}})
    with patch.object(firewall, "_tem_privilegios_root", return_value=True), \
         patch.object(firewall.subprocess, "run", side_effect=_fake_subprocess_run()):
        resultado = firewall.desbloquear_ip("203.0.113.9", origem="teste-pytest")

    assert resultado["status"] == "desbloqueado"
    assert "203.0.113.9" not in firewall._carregar_estado()


def test_desbloquear_ip_sem_root_retorna_erro():
    with patch.object(firewall, "_tem_privilegios_root", return_value=False):
        resultado = firewall.desbloquear_ip("203.0.113.9")
    assert resultado["status"] == "erro"


# ---------------------------------------------------------------------------
# ip_ja_bloqueado
# ---------------------------------------------------------------------------

def test_ip_ja_bloqueado_true_quando_presente_no_ipset():
    with patch.object(firewall.subprocess, "run", side_effect=_fake_subprocess_run(ja_bloqueado=True)):
        assert firewall.ip_ja_bloqueado("203.0.113.9") is True


def test_ip_ja_bloqueado_false_quando_ausente_no_ipset():
    with patch.object(firewall.subprocess, "run", side_effect=_fake_subprocess_run(ja_bloqueado=False)):
        assert firewall.ip_ja_bloqueado("203.0.113.9") is False


def test_ip_ja_bloqueado_false_quando_ipset_ausente():
    with patch.object(firewall.subprocess, "run", side_effect=FileNotFoundError):
        assert firewall.ip_ja_bloqueado("203.0.113.9") is False


# ---------------------------------------------------------------------------
# listar_bloqueios_ativos (consulta o "kernel" mockado, não o arquivo)
# ---------------------------------------------------------------------------

def test_listar_bloqueios_ativos_le_do_ipset_e_enriquece_com_metadados():
    firewall._salvar_estado({"203.0.113.9": {"motivo": "ataques", "origem": "cli", "conjunto": firewall.IPSET_V4}})

    saida_ipset_v4 = "Name: analisador_bloqueios_v4\nMembers:\n203.0.113.9 timeout 3599\n"
    saida_ipset_v6 = "Name: analisador_bloqueios_v6\nMembers:\n"

    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["ipset", "list"] and cmd[2] == firewall.IPSET_V4:
            return _resultado(stdout=saida_ipset_v4)
        if cmd[:2] == ["ipset", "list"] and cmd[2] == firewall.IPSET_V6:
            return _resultado(stdout=saida_ipset_v6)
        return _resultado()

    with patch.object(firewall.subprocess, "run", side_effect=fake_run):
        ativos = firewall.listar_bloqueios_ativos()

    assert "203.0.113.9" in ativos
    assert ativos["203.0.113.9"]["motivo"] == "ataques"
    assert ativos["203.0.113.9"]["timeout_restante_segundos"] == 3599


def test_listar_bloqueios_ativos_nao_mostra_ip_que_ja_expirou_no_kernel():
    firewall._salvar_estado({"203.0.113.9": {"motivo": "expirado", "origem": "cli"}})

    with patch.object(firewall.subprocess, "run", return_value=_resultado(stdout="Members:\n")):
        ativos = firewall.listar_bloqueios_ativos()

    assert "203.0.113.9" not in ativos


# ---------------------------------------------------------------------------
# limpar_bloqueios_expirados (agora sincroniza metadados com o kernel)
# ---------------------------------------------------------------------------

def test_limpar_bloqueios_expirados_remove_metadado_orfao():
    firewall._salvar_estado({
        "203.0.113.1": {"motivo": "expirado no kernel", "origem": "teste"},
        "203.0.113.2": {"motivo": "ainda ativo", "origem": "teste"},
    })

    saida_v4 = "Members:\n203.0.113.2 timeout 100\n"  # só .2 continua no kernel

    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["ipset", "list"] and cmd[2] == firewall.IPSET_V4:
            return _resultado(stdout=saida_v4)
        return _resultado(stdout="Members:\n")

    with patch.object(firewall.subprocess, "run", side_effect=fake_run):
        removidos = firewall.limpar_bloqueios_expirados()

    assert [r["ip"] for r in removidos] == ["203.0.113.1"]
    estado_final = firewall._carregar_estado()
    assert "203.0.113.1" not in estado_final
    assert "203.0.113.2" in estado_final


# ---------------------------------------------------------------------------
# persistir_regras / garantir_ipsets
# ---------------------------------------------------------------------------

def test_persistir_regras_sucesso_escreve_os_tres_arquivos():
    with patch.object(firewall.subprocess, "run", side_effect=_fake_subprocess_run()):
        resultado = firewall.persistir_regras()

    assert resultado["status"] == "ok"
    with open(firewall.ARQUIVO_IPSET_PERSISTIDO, encoding="utf-8") as f:
        assert "ipset mock" in f.read()
    with open(firewall.ARQUIVO_REGRAS_PERSISTIDAS, encoding="utf-8") as f:
        assert "regras mock" in f.read()
    with open(firewall.ARQUIVO_REGRAS_PERSISTIDAS_V6, encoding="utf-8") as f:
        assert "regras mock" in f.read()


def test_persistir_regras_sem_ipset_retorna_status_erro():
    with patch.object(firewall.subprocess, "run", side_effect=FileNotFoundError):
        resultado = firewall.persistir_regras()
    assert resultado["status"] == "erro"


def test_garantir_ipsets_cria_v4_e_v6():
    with patch.object(firewall.subprocess, "run", side_effect=_fake_subprocess_run()) as run_mock:
        resultado = firewall.garantir_ipsets()

    assert resultado[firewall.IPSET_V4]["status"] == "ok"
    assert resultado[firewall.IPSET_V6]["status"] == "ok"
    comandos_create = [c.args[0] for c in run_mock.call_args_list if c.args[0][:2] == ["ipset", "create"]]
    assert any(firewall.IPSET_V4 in c for c in comandos_create)
    assert any(firewall.IPSET_V6 in c for c in comandos_create)
