# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""Métricas operacionais do dashboard SOC, sempre tenant-scoped."""
from sentinela.repositories.incidentes import IncidenteRepositorio



async def obter_dashboard(sessao, empresa_id):
    """
    `empresa_id` é redundante com a RLS de `conexao_tenant` (que já faz
    `SET LOCAL ROLE app_tenant` + `set_config('app.current_tenant', ...)`
    antes de qualquer query rodar) -- mas filtrar explicitamente aqui é
    defesa em profundidade barata: se esta função um dia for chamada com
    uma conexão superadmin-scoped (BYPASSRLS) por engano, ou se a RLS for
    removida/quebrada numa migration futura, as métricas de UMA empresa
    não vazam nem se misturam com as de outra.
    """
    repo = IncidenteRepositorio(sessao)
    counts = await repo.contagens(empresa_id)
    bloqueios = await repo.contagem_bloqueios(empresa_id)
    return {
        "metricas": {k: int(v or 0) for k, v in counts.items()},
        "firewall": {k: int(v or 0) for k, v in bloqueios.items()},
        "top_ips": await repo.top_ips_24h(empresa_id),
        "recentes": await repo.recentes(empresa_id),
    }
