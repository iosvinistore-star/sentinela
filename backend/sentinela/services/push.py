# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
"""
Notificação de alerta no celular (Web Push, RFC 8030 + VAPID RFC 8292).

Como funciona, em três frases: o navegador do usuário pede uma "inscrição"
ao serviço de push do próprio fabricante (Google para Chrome/Android,
Apple para Safari/iPhone, Mozilla para Firefox); essa inscrição é uma URL
opaca mais duas chaves; o Sentinela guarda isso (migrations/
0032_push_notificacoes.sql) e, quando nasce um incidente grave, manda a
mensagem cifrada para aquela URL. O servidor do Sentinela nunca fala com o
aparelho diretamente e não precisa de conta em nenhuma loja.

VAPID é o par de chaves que identifica ESTE servidor para os serviços de
push. A chave pública vai para o navegador na hora de se inscrever; a
privada assina cada envio. Elas têm de ser ESTÁVEIS: trocar o par invalida
todas as inscrições existentes (os aparelhos param de receber, em
silêncio), por isso ficam no .env junto dos outros segredos e não são
geradas a cada início.

Envio é BEST-EFFORT e nunca pode derrubar quem chamou: um incidente que
deixou de ser gravado porque a Apple estava fora do ar seria um defeito
muito pior do que uma notificação perdida.
"""
import asyncio
import json
import logging

from sentinela.db.pool import superadmin_scoped_connection

log = logging.getLogger(__name__)

# Acima disto o endpoint é considerado morto e removido. Os serviços de
# push respondem 404/410 para inscrição cancelada, e esses casos removem na
# hora; o contador existe para a falha INTERMITENTE (rede, 5xx), que não
# deve apagar um aparelho bom no primeiro tropeço.
MAX_FALHAS = 5

# Severidades que acordam o telefone. Um alerta que toca para tudo vira
# ruído e é desligado pelo usuário na primeira semana -- aí não sobra
# alerta nenhum quando importa.
SEVERIDADES_QUE_NOTIFICAM = {"HIGH", "CRITICAL"}


class PushNaoConfigurado(RuntimeError):
    """Sem par de chaves VAPID no ambiente. Não é erro fatal: o produto
    inteiro funciona sem notificação, só a tela de "ligar notificações"
    fica indisponível e diz o porquê."""


def configurado(settings) -> bool:
    return bool(settings.vapid_public_key and settings.vapid_private_key)


def gerar_par_vapid() -> tuple[str, str]:
    """Par de chaves VAPID novo, como (pública, privada) em base64url sem
    padding -- o formato que o navegador e a pywebpush esperam.

    Usado pelos instaladores (deploy/instalar.sh, local-windows/
    configurar_local.py) para escrever o .env UMA vez. Gerar por início
    invalidaria toda inscrição existente a cada reinício.
    """
    import base64

    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    chave = ec.generate_private_key(ec.SECP256R1())
    publica = chave.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    privada = chave.private_numbers().private_value.to_bytes(32, "big")

    def b64(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).decode().rstrip("=")

    return b64(publica), b64(privada)


# ---------------------------------------------------------------------------
# Inscrições
# ---------------------------------------------------------------------------

async def inscrever(conn, endpoint: str, p256dh: str, auth: str, aparelho: str | None,
                    empresa_id=None, usuario_id=None, superadmin_id=None) -> dict:
    """Grava (ou renova) a inscrição de um aparelho.

    ON CONFLICT no endpoint: o navegador renova a inscrição por conta
    própria de tempos em tempos e reenvia o MESMO endpoint com chaves
    novas. Sem o upsert, isso viraria linha duplicada e notificação em
    dobro -- ou erro de unicidade, dependendo da ordem.
    """
    row = await conn.fetchrow(
        """
        INSERT INTO push_inscricoes (empresa_id, usuario_id, superadmin_id, endpoint,
                                     chave_p256dh, chave_auth, aparelho)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (endpoint) DO UPDATE
           SET chave_p256dh = EXCLUDED.chave_p256dh,
               chave_auth   = EXCLUDED.chave_auth,
               aparelho     = EXCLUDED.aparelho,
               empresa_id   = EXCLUDED.empresa_id,
               usuario_id   = EXCLUDED.usuario_id,
               superadmin_id = EXCLUDED.superadmin_id,
               falhas_seguidas = 0
        RETURNING id, criada_em
        """,
        empresa_id, usuario_id, superadmin_id, endpoint, p256dh, auth, aparelho,
    )
    return {"id": str(row["id"]), "criada_em": row["criada_em"].isoformat()}


async def cancelar(conn, endpoint: str) -> bool:
    apagadas = await conn.execute("DELETE FROM push_inscricoes WHERE endpoint = $1", endpoint)
    return apagadas.endswith(" 1")


async def listar_da_empresa(conn, empresa_id) -> list[dict]:
    rows = await conn.fetch(
        "SELECT id, aparelho, criada_em, usada_em FROM push_inscricoes WHERE empresa_id = $1 ORDER BY criada_em",
        empresa_id,
    )
    return [
        {"id": str(r["id"]), "aparelho": r["aparelho"],
         "criada_em": r["criada_em"].isoformat(),
         "usada_em": r["usada_em"].isoformat() if r["usada_em"] else None}
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Envio
# ---------------------------------------------------------------------------

def _enviar_uma(settings, inscricao: dict, carga: dict) -> tuple[bool, int | None]:
    """Envio bloqueante de UMA notificação. Roda em thread (ver `_disparar`).

    Devolve (entregue, status_http). O status importa: 404/410 significam
    "esta inscrição não existe mais", e aí o certo é apagar, não tentar de
    novo para sempre.
    """
    from pywebpush import WebPushException, webpush

    try:
        webpush(
            subscription_info={
                "endpoint": inscricao["endpoint"],
                "keys": {"p256dh": inscricao["chave_p256dh"], "auth": inscricao["chave_auth"]},
            },
            data=json.dumps(carga, ensure_ascii=False),
            vapid_private_key=settings.vapid_private_key,
            vapid_claims={"sub": settings.vapid_subject},
            ttl=3600,
        )
        return True, 200
    except WebPushException as exc:
        status = getattr(getattr(exc, "response", None), "status_code", None)
        return False, status
    except Exception:  # noqa: BLE001 -- rede/DNS/TLS: falha, mas não derruba o chamador
        return False, None


async def _registrar_resultado(conn, inscricao_id, entregue: bool, status: int | None):
    if entregue:
        await conn.execute(
            "UPDATE push_inscricoes SET usada_em = now(), falhas_seguidas = 0 WHERE id = $1", inscricao_id,
        )
        return
    # 404/410: o serviço de push afirma que a inscrição não existe mais
    # (app desinstalado, dados limpos). Insistir nunca vai funcionar.
    if status in (404, 410):
        await conn.execute("DELETE FROM push_inscricoes WHERE id = $1", inscricao_id)
        return
    await conn.execute(
        "UPDATE push_inscricoes SET falhas_seguidas = falhas_seguidas + 1 WHERE id = $1", inscricao_id,
    )
    await conn.execute("DELETE FROM push_inscricoes WHERE id = $1 AND falhas_seguidas >= $2",
                       inscricao_id, MAX_FALHAS)


async def notificar_empresa(pool, settings, empresa_id, carga: dict) -> int:
    """Manda `carga` para todos os aparelhos inscritos da empresa.

    Usa conexão de superadmin própria (não a do chamador): o envio é
    assíncrono e lento (uma requisição HTTP por aparelho), e segurar a
    transação de quem criou o incidente por causa disso seria travar a
    ingestão em cima de um serviço de terceiro.
    """
    if not configurado(settings):
        return 0
    async with superadmin_scoped_connection(pool) as conn:
        inscricoes = await conn.fetch(
            "SELECT id, endpoint, chave_p256dh, chave_auth FROM push_inscricoes WHERE empresa_id = $1",
            empresa_id,
        )
        if not inscricoes:
            return 0
        entregues = 0
        for r in inscricoes:
            entregue, status = await asyncio.to_thread(_enviar_uma, settings, dict(r), carga)
            await _registrar_resultado(conn, r["id"], entregue, status)
            entregues += int(entregue)
    return entregues


# Referência à app, registrada no lifespan (ver main.py). Existe para que
# `services/incidentes.py` possa disparar a notificação sem receber `app`
# como argumento: os dois caminhos que criam incidente (rede e endpoint)
# estão fundo na camada de serviço e não têm -- nem deveriam ter -- o
# objeto FastAPI em mãos.
_app = None


def registrar_app(app) -> None:
    global _app  # noqa: PLW0603 -- registro único, no start da aplicação
    _app = app


def agendar_alerta_incidente(empresa_id, incidente: dict) -> None:
    """Dispara a notificação de um incidente SEM esperar por ela.

    Chamada de dentro do caminho de ingestão (services/incidentes.py). Tudo
    aqui é defensivo de propósito: sem app registrada, sem loop, sem push
    configurado, ou severidade que não merece alerta -- não faz nada e não
    levanta. Gravar o incidente é o que não pode falhar.
    """
    severidade = (incidente or {}).get("severidade")
    if severidade not in SEVERIDADES_QUE_NOTIFICAM:
        return
    settings = getattr(getattr(_app, "state", None), "settings", None)
    pool = getattr(getattr(_app, "state", None), "pool", None)
    if settings is None or pool is None or not configurado(settings):
        return

    ataques = incidente.get("ataques") or []
    if isinstance(ataques, str):
        try:
            ataques = json.loads(ataques)
        except ValueError:
            ataques = []
    resumo = ", ".join(str(a) for a in ataques[:2]) or "atividade suspeita"
    carga = {
        "titulo": f"{severidade}: {incidente.get('ip', 'origem desconhecida')}",
        "corpo": f"{resumo} — risco {incidente.get('pontuacao_risco', '?')}",
        "gravidade": severidade,
        "incidente_id": str(incidente.get("incident_id") or incidente.get("id") or ""),
        "url": f"/app/incidentes/{incidente.get('id', '')}",
    }

    async def _tarefa():
        try:
            await notificar_empresa(pool, settings, empresa_id, carga)
        except Exception:  # noqa: BLE001
            log.warning("push: falha ao notificar incidente", exc_info=True)

    try:
        asyncio.get_running_loop().create_task(_tarefa())
    except RuntimeError:
        # Sem loop rodando (chamada de script/CLI): simplesmente não notifica.
        pass
