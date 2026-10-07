# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
GET /health e GET /ready -- ponto 8 do review de hardening pós-auditoria:
observabilidade básica de produção. Sem estes dois endpoints, um
orquestrador (Kubernetes, ECS, um load balancer com health check) não tem
como saber, de fora, se o processo está vivo e se pode receber tráfego --
a única forma de descobrir era mandar tráfego de verdade e ver se falha.

Deliberadamente FORA de /api/v1 (sem prefixo, sem autenticação, sem CSRF) --
um health check de infraestrutura precisa ser alcançável sem sessão nem
cookie (o orquestrador não faz login), e o padrão em toda a indústria
(Kubernetes liveness/readinessProbe, ALB/NLB health check, etc.) é uma rota
simples e estável na raiz.

Dois endpoints, dois papéis diferentes (nomenclatura Kubernetes):

  GET /health -- LIVENESS. "O processo está vivo e respondendo?" Não toca
      NENHUMA dependência externa (nem o Postgres) de propósito: um
      orquestrador usa liveness para decidir se deve MATAR e reiniciar o
      processo. Se /health dependesse do Postgres, uma queda do banco (que
      reiniciar o processo Python não resolve) causaria um reinício em
      loop de TODOS os workers, sem nunca ajudar -- e ainda derrubaria a
      capacidade de servir requisições que NÃO precisam do banco.

  GET /ready -- READINESS. "Este processo pode receber tráfego AGORA?"
      Checa o Postgres (`SELECT 1` com timeout curto) porque é a única
      dependência externa real da aplicação. Um orquestrador usa readiness
      para decidir se deve rotear tráfego para esta réplica -- uma réplica
      "viva mas não pronta" (ex.: Postgres temporariamente inacessível)
      fica de fora da rotação sem ser reiniciada à toa, e volta sozinha
      assim que o banco responder de novo.
"""
import asyncio

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(tags=["saude"])

TIMEOUT_CHECAGEM_BANCO_SEGUNDOS = 3.0


@router.get("/health")
async def liveness():
    return {"status": "ok"}


@router.get("/ready")
async def readiness(request: Request):
    pool = getattr(request.app.state, "pool", None)
    if pool is None:
        # Lifespan ainda não terminou de criar o pool (só deveria acontecer
        # numa janela minúscula logo no boot) -- "não pronto" é a resposta
        # correta, não um erro.
        return JSONResponse(status_code=503, content={"status": "not_ready", "detail": "pool de conexões ainda não inicializado"})
    try:
        await asyncio.wait_for(pool.ping(), timeout=TIMEOUT_CHECAGEM_BANCO_SEGUNDOS)
    except Exception as exc:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "detail": f"Postgres inacessível: {exc.__class__.__name__}"},
        )
    return {"status": "ok"}
