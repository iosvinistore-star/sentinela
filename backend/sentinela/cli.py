# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
CLI do Sentinela SOC — equivalente ao antigo `analisador_logs.py --main--`,
agora falando com Postgres multi-tenant em vez de SQLite. Como a CLI não
tem uma sessão de usuário logado, `--empresa-id` é obrigatório sempre que a
operação grava dados (analisar com --verificar-reputacao/--bloquear);
`--limpar-expirados` é a exceção -- é uma operação cross-tenant (sincroniza
o estado do kernel com TODAS as empresas), por isso não pede empresa_id.

Uso:
    python -m sentinela.cli --arquivo servidor.log --empresa-id <uuid>
    python -m sentinela.cli --arquivo servidor.log --empresa-id <uuid> \\
        --limite 5 --verificar-reputacao --bloquear
    python -m sentinela.cli --limpar-expirados
"""
import argparse
import asyncio
import json
import os

from sentinela.config import carregar_settings
from sentinela.core.analisador_logs import processar_arquivo_logs
from sentinela.database import Database, DatabaseSettings
from sentinela.services.firewall import sincronizar_bloqueios_expirados
from sentinela.services.resposta_incidentes import responder_a_incidentes


def _construir_parser():
    parser = argparse.ArgumentParser(description="Sentinela SOC — CLI de análise de logs (multi-tenant)")
    parser.add_argument("--arquivo", default="servidor.log", help="Caminho do arquivo de log a analisar")
    parser.add_argument("--empresa-id", default=None, help="UUID da empresa dona deste log (obrigatório exceto com --limpar-expirados)")
    parser.add_argument("--limite", type=int, default=5, help="Nº de ataques a partir do qual um IP é considerado perigoso")
    parser.add_argument("--verificar-reputacao", action="store_true", help="Consulta AbuseIPDB/VirusTotal para os IPs perigosos")
    parser.add_argument("--bloquear", action="store_true", help="Bloqueia via iptables os IPs que ultrapassarem o limite")
    parser.add_argument("--dry-run", action="store_true", help="Com --bloquear, apenas simula o comando iptables (não executa)")
    parser.add_argument("--whitelist", default="", help="IPs separados por vírgula que nunca devem ser bloqueados")
    parser.add_argument(
        "--duracao-bloqueio", type=float, default=24,
        help="Horas até o bloqueio expirar automaticamente; use 0 para bloqueio permanente (padrão: 24)",
    )
    parser.add_argument("--limpar-expirados", action="store_true", help="Sincroniza bloqueios expirados (kernel + Postgres, todas as empresas) e encerra")
    parser.add_argument("--saida-json", default=None, help="Caminho para salvar o relatório completo em JSON")
    return parser


async def _executar(args):
    settings = carregar_settings()
    settings.validar()
    db = Database.conectar(DatabaseSettings.de_settings(settings))
    try:
        if args.limpar_expirados:
            resultado = await sincronizar_bloqueios_expirados(db, origem="cli")
            print(json.dumps(resultado, indent=4, ensure_ascii=False, default=str))
            return

        if not args.empresa_id:
            raise SystemExit("--empresa-id é obrigatório (exceto com --limpar-expirados)")

        whitelist = [ip.strip() for ip in args.whitelist.split(",") if ip.strip()]
        duracao_horas = args.duracao_bloqueio or None

        if args.arquivo == "servidor.log" and not os.path.exists("servidor.log"):
            logs_teste = [
                '192.168.1.50 - - [26/Aug/2026:10:00:00] "GET /index.html HTTP/1.1" 200 1024\n',
                '203.0.113.5 - - [26/Aug/2026:10:01:00] "GET /vulneravel.php?id=1\'%20UNION%20SELECT%20null,username,password%20FROM%20users HTTP/1.1" 200 4500\n',
                '198.51.100.12 - - [26/Aug/2026:10:02:00] "GET /?busca=<script>alert(1)</script> HTTP/1.1" 200 2300\n',
            ]
            with open("servidor.log", "w") as f:
                f.writelines(logs_teste)

        relatorio = processar_arquivo_logs(args.arquivo)
        print(json.dumps(relatorio, indent=4, ensure_ascii=False))

        if args.verificar_reputacao or args.bloquear:
            async with db.tenant_session(args.empresa_id) as sessao:
                respostas = await responder_a_incidentes(
                    sessao, args.empresa_id, relatorio,
                    limite_ataques=args.limite,
                    verificar_reputacao=args.verificar_reputacao,
                    bloquear=args.bloquear,
                    whitelist=whitelist,
                    dry_run=args.dry_run,
                    duracao_horas=duracao_horas,
                    origem="cli",
                )
            print("\n=== Resposta a incidentes ===")
            print(json.dumps(respostas, indent=4, ensure_ascii=False, default=str))
            relatorio["respostas_incidentes"] = respostas

        if args.saida_json:
            with open(args.saida_json, "w", encoding="utf-8") as f:
                json.dump(relatorio, f, indent=4, ensure_ascii=False, default=str)
    finally:
        await db.fechar()


def main():
    args = _construir_parser().parse_args()
    asyncio.run(_executar(args))


if __name__ == "__main__":
    main()
