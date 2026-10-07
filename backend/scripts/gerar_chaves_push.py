# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Gera o par de chaves VAPID da notificação de alerta no celular.

Uso:
    python -m scripts.gerar_chaves_push            # imprime as linhas do .env
    python -m scripts.gerar_chaves_push --env .env # acrescenta ao arquivo

Os instaladores já fazem isto sozinhos em instalação nova; este script é
para quem já tinha o Sentinela rodando antes da notificação existir.

ATENÇÃO: gerar um par NOVO em um sistema que já tinha um invalida, em
silêncio, todas as inscrições feitas nos aparelhos -- os celulares param
de receber alerta e ninguém é avisado disso. Por isso o modo --env recusa
sobrescrever um par existente.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinela.services.push import gerar_par_vapid  # noqa: E402

CHAVES = ("SENTINELA_VAPID_PUBLIC_KEY", "SENTINELA_VAPID_PRIVATE_KEY")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--env", help="arquivo .env onde acrescentar as linhas (não sobrescreve par existente)")
    ap.add_argument("--subject", default="mailto:suporte@sentinela.local",
                    help="contato do responsável pelo servidor, informado ao serviço de push")
    args = ap.parse_args()

    publica, privada = gerar_par_vapid()
    linhas = (
        f"SENTINELA_VAPID_PUBLIC_KEY={publica}\n"
        f"SENTINELA_VAPID_PRIVATE_KEY={privada}\n"
        f"SENTINELA_VAPID_SUBJECT={args.subject}\n"
    )

    if not args.env:
        print(linhas, end="")
        return 0

    caminho = Path(args.env)
    atual = caminho.read_text(encoding="utf-8") if caminho.exists() else ""
    if any(f"{c}=" in atual for c in CHAVES):
        print(f"{caminho} já tem chaves VAPID. Trocá-las derruba as notificações já ligadas "
              f"nos celulares -- apague as linhas à mão se for mesmo isso que você quer.", file=sys.stderr)
        return 1
    with caminho.open("a", encoding="utf-8") as f:
        if atual and not atual.endswith("\n"):
            f.write("\n")
        f.write("\n# Notificação de alerta no celular (ver services/push.py).\n")
        f.write(linhas)
    print(f"Chaves acrescentadas em {caminho}. Reinicie o Sentinela para a notificação ficar disponível.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
