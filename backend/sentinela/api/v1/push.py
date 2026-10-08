# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
/api/v1/push/... -- inscrição do aparelho para receber alerta no celular.

Fluxo, do lado do telefone (ver frontend-react/src/pwa/notificacoes.ts):
  1. GET  /push/config          -> pega a chave pública VAPID
  2. navegador pede permissão e gera a inscrição
  3. POST /push/inscricoes      -> guarda o aparelho
  4. DELETE /push/inscricoes    -> desliga (ao sair ou a pedido)

Tudo aqui exige login e escopo de tenant: um aparelho só pode se inscrever
para receber os alertas da PRÓPRIA empresa de quem está logado. O endpoint
vem do navegador, então é entrada não-confiável -- limitado em tamanho e
restrito a https, para que a tabela não vire um relay de requisições
arbitrárias saindo do servidor.
"""
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from sentinela.auth.dependencies import conexao_tenant, exigir_csrf_header, exigir_login
from sentinela.services import push as servico_push

router = APIRouter(prefix="/push", tags=["push"])

# Endpoints reais têm ~200 caracteres; o teto existe só para impedir que
# alguém use a coluna como armazenamento arbitrário.
_MAX_ENDPOINT = 1000


class InscricaoRequest(BaseModel):
    endpoint: str = Field(min_length=10, max_length=_MAX_ENDPOINT)
    p256dh: str = Field(min_length=10, max_length=255)
    auth: str = Field(min_length=6, max_length=255)
    aparelho: str | None = Field(default=None, max_length=120)


class CancelarRequest(BaseModel):
    endpoint: str = Field(min_length=10, max_length=_MAX_ENDPOINT)


def _endpoint_aceitavel(endpoint: str) -> bool:
    """Só HTTPS e só com host. O servidor vai fazer uma requisição para
    esta URL mais tarde; aceitar http:// ou um host vazio transformaria a
    inscrição em um vetor de requisição forjada a partir do servidor."""
    try:
        u = urlparse(endpoint)
    except ValueError:
        return False
    return u.scheme == "https" and bool(u.netloc)


@router.get("/config")
async def config_push(request: Request, usuario: dict = Depends(exigir_login)):
    """A chave pública VAPID e se a notificação está disponível neste servidor."""
    settings = request.app.state.settings
    return {
        "disponivel": servico_push.configurado(settings),
        "chave_publica": settings.vapid_public_key or None,
        "severidades": sorted(servico_push.SEVERIDADES_QUE_NOTIFICAM),
    }


@router.post("/inscricoes", dependencies=[Depends(exigir_csrf_header)], status_code=201)
async def inscrever(dados: InscricaoRequest, request: Request,
                    usuario: dict = Depends(exigir_login), sessao=Depends(conexao_tenant)):
    if not servico_push.configurado(request.app.state.settings):
        raise HTTPException(status_code=503, detail="notificação não configurada neste servidor")
    if not _endpoint_aceitavel(dados.endpoint):
        raise HTTPException(status_code=422, detail="endpoint de notificação inválido")
    criada = await servico_push.inscrever(
        sessao, dados.endpoint, dados.p256dh, dados.auth, dados.aparelho,
        empresa_id=usuario["empresa_id"], usuario_id=usuario["sub"],
    )
    return {"inscricao": criada}


@router.delete("/inscricoes", dependencies=[Depends(exigir_csrf_header)])
async def cancelar(dados: CancelarRequest, usuario: dict = Depends(exigir_login),
                   sessao=Depends(conexao_tenant)):
    # A RLS já garante que só some inscrição da própria empresa.
    return {"removida": await servico_push.cancelar(sessao, dados.endpoint)}


@router.get("/inscricoes")
async def listar(usuario: dict = Depends(exigir_login), sessao=Depends(conexao_tenant)):
    return {"aparelhos": await servico_push.listar_da_empresa(sessao, usuario["empresa_id"])}


@router.post("/teste", dependencies=[Depends(exigir_csrf_header)])
async def enviar_teste(request: Request, usuario: dict = Depends(exigir_login)):
    """Manda uma notificação de teste para os aparelhos da empresa.

    Existe porque "liguei e não sei se funciona" é a dúvida imediata de
    quem acabou de ativar -- e esperar um incidente real para descobrir
    que a permissão ficou negada no sistema é o pior jeito de descobrir.
    """
    settings = request.app.state.settings
    if not servico_push.configurado(settings):
        raise HTTPException(status_code=503, detail="notificação não configurada neste servidor")
    entregues = await servico_push.notificar_empresa(
        request.app.state.db, settings, usuario["empresa_id"],
        {"titulo": "Sentinela SOC", "corpo": "Notificação de teste — está funcionando.",
         "gravidade": "INFO", "tag": "teste", "url": "/app/"},
    )
    return {"entregues": entregues}
