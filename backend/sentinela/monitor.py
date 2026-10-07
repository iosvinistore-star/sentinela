# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Monitoramento simples em tempo real de um arquivo de log."""
import time
from sentinela.core.analisador_logs import analisar_linha_log

def monitorar(caminho, intervalo=1):
    with open(caminho, 'r', encoding='utf-8') as f:
        f.seek(0,2)
        while True:
            linha=f.readline()
            if not linha:
                time.sleep(intervalo); continue
            alerta=analisar_linha_log(linha.rstrip())
            if alerta and not alerta.get('nao_reconhecida'):
                print(f"[ALERTA] {alerta['tipo_ataque']} | IP={alerta['ip']} | {alerta['requisicao']}")
if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(description='Sentinela SOC - Monitor em tempo real')
    p.add_argument('arquivo'); p.add_argument('--intervalo',type=float,default=1)
    a=p.parse_args(); monitorar(a.arquivo,a.intervalo)
