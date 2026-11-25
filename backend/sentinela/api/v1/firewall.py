# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
GET/POST/DELETE /api/v1/firewall/bloqueios -- listar é permitido a qualquer
usuário logado da empresa; bloquear/desbloquear é admin-only, porque a ação
em si é host-wide, não escopada de verdade por tenant (ver LIMITAÇÃO
CONHECIDA em services/firewall.py e no README).
"""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from sentinela.auth.dependencies import conexao_tenant, exigir_csrf_header, exigir_login, exigir_papel
from sentinela.services import automacao as servico_automacao
from sentinela.services import firewall as servico

router = APIRouter(prefix="/firewall", tags=["firewall"])


class ProtegerIpRequest(BaseModel):
    ip: str
    motivo: str = Field(default="", max_length=500)


class BloquearRequest(BaseModel):
    ip: str
    # `motivo` é `text` no banco (sem teto) -- limite de aplicação evita um
    # payload de tamanho arbitrário indo pro log de auditoria/firewall.
    motivo: str = Field(max_length=500)
    # max_length no item (uma entrada de whitelist é um IP/CIDR, nunca
    # precisa de mais que isso) e max_length na lista (evita um array
    # gigante de milhares de entradas, que services/firewall.py teria que
    # iterar uma a uma).
    whitelist: list[Annotated[str, Field(max_length=100)]] = Field(default=[], max_length=200)
    dry_run: bool = False
    # None = bloqueio permanente (sem expiração). Um valor <= 0 chegava sem
    # validação até core/firewall.py:bloquear_ip, onde virava um
    # `timeout_segundos` negativo/zero passado direto pro `ipset` -- na
    # prática um "bloqueio" que ou expirava instantaneamente ou tinha
    # comportamento indefinido no kernel, dependendo da versão do ipset.
    # `gt=0` fecha essa lacuna; o teto de 8760h (1 ano) é só uma salvaguarda
    # contra valores absurdos digitados por engano (não havia limite nenhum
    # antes).
    duracao_horas: float | None = Field(default=24, gt=0, le=8760)


@router.get("/bloqueios")
async def listar_bloqueios(usuario: dict = Depends(exigir_login), sessao=Depends(conexao_tenant)):
    return {"bloqueios": await servico.listar_bloqueios(sessao, usuario["empresa_id"])}


@router.post("/bloqueios", dependencies=[Depends(exigir_csrf_header)])
async def registrar_bloqueio(dados: BloquearRequest, usuario: dict = Depends(exigir_papel("admin")),
                               sessao=Depends(conexao_tenant)):
    resultado = await servico.registrar_bloqueio(
        sessao, usuario["empresa_id"], dados.ip, dados.motivo,
        whitelist=dados.whitelist, dry_run=dados.dry_run, duracao_horas=dados.duracao_horas,
        origem="api", usuario_id=usuario["sub"],
    )
    return {"resultado": resultado}


@router.delete("/bloqueios/{ip}", dependencies=[Depends(exigir_csrf_header)])
async def remover_bloqueio(ip: str, request: Request, usuario: dict = Depends(exigir_papel("admin")),
                             sessao=Depends(conexao_tenant)):
    resultado = await servico.remover_bloqueio(
        sessao, request.app.state.db, usuario["empresa_id"], ip, origem="api", usuario_id=usuario["sub"],
    )
    return {"resultado": resultado}


# Capacidade 4 do modo autônomo (curadoria de IPs protegidos -- ver
# services/automacao.py e migrations/0014_autonomia_operacional.sql).
# Transparente e reversível de propósito: um admin sempre consegue ver e
# remover qualquer entrada, mesmo as adicionadas automaticamente.
@router.get("/ips-protegidos")
async def listar_ips_protegidos(usuario: dict = Depends(exigir_login), sessao=Depends(conexao_tenant)):
    return {"ips_protegidos": await servico_automacao.listar_ips_protegidos(sessao, usuario["empresa_id"])}


@router.post("/ips-protegidos", dependencies=[Depends(exigir_csrf_header)])
async def adicionar_ip_protegido(dados: ProtegerIpRequest, usuario: dict = Depends(exigir_papel("admin")),
                                   sessao=Depends(conexao_tenant)):
    ip_protegido = await servico_automacao.adicionar_ip_protegido(
        sessao, usuario["empresa_id"], dados.ip, motivo=dados.motivo, origem="manual",
        criado_por_usuario_id=usuario["sub"],
    )
    return {"ip_protegido": ip_protegido}


@router.delete("/ips-protegidos/{ip}", dependencies=[Depends(exigir_csrf_header)])
async def remover_ip_protegido(ip: str, usuario: dict = Depends(exigir_papel("admin")), sessao=Depends(conexao_tenant)):
    removido = await servico_automacao.remover_ip_protegido(sessao, usuario["empresa_id"], ip, usuario_id=usuario["sub"])
    if not removido:
        raise HTTPException(status_code=404, detail="IP protegido não encontrado")
    return {"status": "removido"}
