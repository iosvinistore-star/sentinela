# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
/api/v1/setup/... -- PRIMEIRO ACESSO da plataforma.

Antes disto, a primeira conta de gestão (SAAS_OWNER) só nascia por script
de linha de comando: quem subia o Sentinela abria o navegador, via uma
tela de login e não tinha nenhuma credencial para digitar. Este módulo
existe para que a instalação termine no navegador, como qualquer produto:
a primeira visita cai em /primeiro-acesso, cria-se o dono, e a rota se
fecha para sempre.

Fechar direito é o ponto delicado -- uma rota que cria um superusuário sem
autenticação é, por definição, a porta mais valiosa do sistema. Três
travas, todas obrigatórias:

1. Só funciona enquanto NÃO existir nenhum superadmin. Depois do primeiro,
   responde 409 e não olha mais o corpo da requisição.
2. A origem tem de ser confiável: ou a requisição vem do próprio host
   (loopback -- quem instalou está no console da máquina), ou traz o
   `SENTINELA_SETUP_TOKEN` que o instalador sorteou e imprimiu. Sem uma
   das duas, 403.
3. Advisory lock no Postgres: duas requisições simultâneas não criam dois
   donos -- a segunda espera, vê que já existe um, e recebe 409.
"""
import hmac
import ipaddress

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from sentinela.services import auditoria as servico_auditoria
from sentinela.services import superadmins as servico_superadmins

router = APIRouter(prefix="/setup", tags=["setup"])


async def conexao_setup(request: Request):
    """Conexão com BYPASSRLS SEM exigir login -- a única do sistema.

    É o que torna o primeiro acesso possível: não existe conta nenhuma
    ainda, logo não existe sessão para autenticar. As três travas
    descritas no topo do módulo são o que substitui a autenticação aqui;
    nenhuma rota fora deste módulo pode usar esta dependência.
    """
    async with request.app.state.db.superadmin_session() as sessao:
        yield sessao

# Chave arbitrária mas fixa do advisory lock ("SENT" em ASCII). Só precisa
# não colidir com outro lock do próprio sistema -- ver
# services/retencao.py, que usa uma faixa diferente.
_LOCK_PRIMEIRO_ACESSO = 0x53454E54

_SENHA_MAX_LENGTH = 72  # limite físico do bcrypt -- ver services/usuarios.py


class PrimeiroAcessoRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    senha: str = Field(min_length=12, max_length=_SENHA_MAX_LENGTH)
    token_setup: str | None = Field(default=None, max_length=200)


async def _ja_configurado(sessao) -> bool:
    return await servico_superadmins.existe_algum_superadmin(sessao)


def _origem_loopback(request: Request) -> bool:
    """True quando a requisição chegou da própria máquina.

    Usa SÓ o peer real da conexão (`request.client`), nunca
    X-Forwarded-For: atrás de um proxy, o cabeçalho é escolhido por quem
    chama, e aceitá-lo aqui transformaria a trava em enfeite. Em produção
    (atrás do Caddy) o peer é o proxy, não é loopback, e o caminho válido
    passa a ser o token -- que é exatamente o desenho pretendido.
    """
    cliente = request.client
    if cliente is None or not cliente.host:
        return False
    try:
        return ipaddress.ip_address(cliente.host).is_loopback
    except ValueError:
        return False


def _token_confere(request: Request, informado: str | None) -> bool:
    esperado = (request.app.state.settings.setup_token or "").strip()
    if not esperado:
        return False
    candidato = (informado or request.headers.get("X-Sentinela-Setup-Token") or "").strip()
    if not candidato:
        return False
    return hmac.compare_digest(candidato, esperado)


@router.get("/status")
async def status_setup(request: Request, sessao=Depends(conexao_setup)):
    """Quem a tela de login chama para saber se deve mandar o usuário para
    /primeiro-acesso. Não revela nada além do fato de haver ou não uma
    conta de gestão -- que é observável de qualquer forma."""
    configurado = await _ja_configurado(sessao)
    return {
        "configurado": configurado,
        "precisa_configurar": not configurado,
        # Só para a tela saber se precisa PEDIR o token ao usuário.
        "exige_token": not configurado and not _origem_loopback(request),
    }


@router.post("/primeiro-acesso", status_code=201)
async def primeiro_acesso(dados: PrimeiroAcessoRequest, request: Request, sessao=Depends(conexao_setup)):
    """Cria a primeira conta de gestão (SAAS_OWNER) da plataforma."""
    if await _ja_configurado(sessao):
        raise HTTPException(status_code=409, detail="a plataforma já está configurada -- use a tela de login")
    if not _origem_loopback(request) and not _token_confere(request, dados.token_setup):
        raise HTTPException(
            status_code=403,
            detail="primeiro acesso remoto exige o token de instalação (SENTINELA_SETUP_TOKEN)",
        )

    async with sessao.begin_nested():
        # Serializa contra outra requisição simultânea; o lock cai junto
        # com a transação.
        await servico_superadmins.travar_primeiro_acesso(sessao, _LOCK_PRIMEIRO_ACESSO)
        if await _ja_configurado(sessao):
            raise HTTPException(status_code=409, detail="a plataforma já está configurada -- use a tela de login")
        try:
            conta = await servico_superadmins.criar_saas_admin(
                sessao, dados.email, dados.senha, "saas_owner", ator_superadmin_id=None,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if conta is None:  # pragma: no cover -- impossível com a tabela vazia
            raise HTTPException(status_code=409, detail="já existe uma conta com este e-mail")
        await servico_auditoria.registrar_evento(
            sessao, None, "plataforma.primeiro_acesso",
            {"email": conta["email"], "origem": "loopback" if _origem_loopback(request) else "token"},
            ator_superadmin_id=conta["id"],
        )
    return {"conta": conta, "proximo_passo": "faça login e cadastre o primeiro cliente"}
