# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
from sentinela.siem.servico import normalizar_syslog
from sentinela.siem.modelos import EventoSIEMEntrada


def test_normalizar_syslog_prioridade():
    e = normalizar_syslog('<34>host sshd: Failed password', 'syslog-udp', '10.0.0.5')
    assert e['source_type'] == 'syslog'
    assert e['severity'] == 'CRITICAL'
    assert e['source_ip'] == '10.0.0.5'


def test_evento_normalizado():
    e = EventoSIEMEntrada(source='nginx', source_type='nginx', message='GET /')
    n = e.normalizado('00000000-0000-0000-0000-000000000000')
    assert n['severity'] == 'INFO'
    assert n['raw_event'] == 'GET /'
