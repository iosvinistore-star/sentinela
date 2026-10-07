# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Cache de reputação de IP em Postgres (tabela `reputacao_cache`,
tenant-scoped com RLS desde migrations/0007_reputacao_cache_tenant.sql --
NÃO é mais global/sem RLS como um comentário antigo deste arquivo dizia;
ver migrations/0001_tabelas.sql para o desenho original que foi
substituído). Substitui o cache em memória sem TTL de `core.reputacao`
quando chamado através desta camada; `core.reputacao._cache` continua
existindo (usado por quem chama o core diretamente, ex.: um script
standalone), mas o caminho normal da aplicação passa por aqui.

As chamadas de rede em si (`core.reputacao.consultar_reputacao_ip`) são
síncronas (usam `requests`) — rodam em `asyncio.to_thread` para não
bloquear o event loop.
"""
import asyncio
from datetime import datetime, timedelta, timezone

from sentinela.core import reputacao as core_reputacao
from sentinela.repositories.reputacao import ReputacaoRepositorio
from sentinela.util import ip_valido


def _linha_para_resultado(registro, ip):
    resultado = dict(registro.dados)
    resultado["ip"] = ip
    resultado["classificacao"] = registro.classificacao
    return resultado


async def consultar_reputacao_ip(sessao, empresa_id, ip: str, ttl_horas: int = 24, usar_cache: bool = True,
                                   abuseipdb_key=None, vt_key=None):
    # Defesa em profundidade: os chamadores (api/v1/reputacao.py,
    # services/resposta_incidentes.py via candidatos já filtrados por
    # analisador_logs.py) já validam, mas esta é a camada que efetivamente
    # grava em `reputacao_cache.ip` (coluna `inet`) -- um valor que passasse
    # por engano (ex.: zone-id de IPv6, que `ipaddress` aceita mas `inet`
    # não) quebraria o INSERT com uma exceção crua em vez de um erro limpo.
    if ip_valido(ip) is None:
        return {"ip": ip, "erro": "IP inválido", "classificacao": "BAIXO RISCO / DESCONHECIDO"}

    repo = ReputacaoRepositorio(sessao)
    if usar_cache:
        registro = await repo.obter(empresa_id, ip)
        if registro is not None:
            expira_em = registro.consultado_em + timedelta(hours=ttl_horas)
            if datetime.now(timezone.utc) < expira_em:
                return _linha_para_resultado(registro, ip)

    resultado = await asyncio.to_thread(
        core_reputacao.consultar_reputacao_ip, ip, False, abuseipdb_key, vt_key
    )

    await repo.salvar(empresa_id, ip, resultado, resultado["classificacao"])
    return resultado
