# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Log de auditoria (tabela `auditoria`, RLS-scoped por empresa — ver
0003_rls.sql). `registrar_evento` é chamado de DENTRO de outras funções de
`services/*.py` que executam ações administrativas sensíveis (bloqueio de
firewall, gestão de usuários, gestão de empresas), usando a MESMA conexão/
transação da ação em si — assim o registro de auditoria é atômico com a
ação (ou os dois acontecem, ou nenhum), nunca fica um sem o outro por causa
de uma falha no meio do caminho.
"""
from sentinela.core.redacao import mascarar_dados
from sentinela.repositories.auditoria import AuditoriaRepositorio


def _publico(registro):
    if registro is None:
        return None
    d = registro.para_dict()
    d["id"] = str(d["id"])
    if d.get("empresa_id") is not None:
        d["empresa_id"] = str(d["empresa_id"])
    if d.get("ator_usuario_id") is not None:
        d["ator_usuario_id"] = str(d["ator_usuario_id"])
    if d.get("ator_superadmin_id") is not None:
        d["ator_superadmin_id"] = str(d["ator_superadmin_id"])
    return d


async def registrar_evento(sessao, empresa_id, acao: str, detalhes: dict | None = None,
                             ator_usuario_id=None, ator_superadmin_id=None):
    registro = await AuditoriaRepositorio(sessao).inserir(
        empresa_id, acao, mascarar_dados(detalhes or {}),
        ator_usuario_id=ator_usuario_id, ator_superadmin_id=ator_superadmin_id,
    )
    return _publico(registro)


async def listar_auditoria(sessao, limite: int = 100):
    """Sessão tenant-scoped -> RLS já filtra pra empresa do chamador."""
    return [_publico(r) for r in await AuditoriaRepositorio(sessao).listar_recentes(limite)]
