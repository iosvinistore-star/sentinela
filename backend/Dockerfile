# syntax=docker/dockerfile:1

# ---- estágio 1: build do React SPA -----------------------------------------
FROM node:22-slim AS frontend-build
WORKDIR /frontend
COPY frontend-react/package.json frontend-react/package-lock.json* ./
RUN npm ci
COPY frontend-react/ ./
RUN npm run build

# ---- estágio 2: imagem final (FastAPI + build do React já embutido) -------
FROM python:3.12-slim AS backend
WORKDIR /app

# Item 20 do plano de endurecimento pós-auditoria: o processo da aplicação
# (uvicorn/FastAPI) passa a rodar como um usuário SEM privilégio (ver `USER
# sentinela` no fim deste arquivo), não mais como root (o padrão implícito
# de toda imagem Docker que nunca chama `USER`). Isso reduz o raio de
# alcance de uma RCE na aplicação (uma dependência Python comprometida, um
# bug de deserialização futuro etc.) de "root dentro do container" -- de
# onde escalar para o host costuma ser uma questão de encontrar A PRÓXIMA
# falha, não mais uma -- para "um usuário comum, só com acesso ao que ele
# mesmo precisa".
#
# EXCEÇÃO DELIBERADA, com cuidado (é o motivo deste comentário ser longo):
# core/firewall.py chama `ipset`/`iptables`/`ip6tables` via subprocess para
# bloquear IPs -- comandos que mexem em netfilter e por padrão só
# funcionam como root, ou (mais preciso) com as capabilities Linux
# CAP_NET_ADMIN + CAP_NET_RAW. Em vez de manter o processo INTEIRO como
# root só por causa desses três binários, usamos `setcap` abaixo para
# conceder essas duas capabilities DIRETO nos binários -- um usuário
# comum que execute um binário com essa capability DE ARQUIVO ganha só
# essas duas capabilities para aquele processo específico, nunca o resto
# do que root poderia fazer (diferença crucial de "rodar o processo
# inteiro como root"). Isso só funciona de fato se o CONTAINER também
# tiver essas duas capabilities no seu próprio conjunto -- por isso
# docker-compose.yml agora declara `cap_add: [NET_ADMIN, NET_RAW]` no
# serviço `backend` (ver lá; sem isso os comandos falham com "Operation
# not permitted" mesmo com o setcap feito aqui). O código já tratava essa
# falha como recuperável antes desta mudança (garantir_ipsets/
# registrar_bloqueio capturam CalledProcessError/FileNotFoundError e
# devolvem {"status": "erro", ...} em vez de derrubar a aplicação -- ver
# core/firewall.py), então um ambiente que não conceda essas capabilities
# ao container continua de pé, só com bloqueio automático inoperante --
# o mesmo estado "degradado, não quebrado" de antes desta mudança.
#
# `persistir_regras()` (core/firewall.py) é uma exceção que este `setcap`
# NÃO cobre, de propósito: ela grava em /etc/iptables/rules.v4, .../rules.v6
# e /etc/ipset.conf -- caminhos de sistema que só root deveria escrever. A
# própria função já documenta "Requer root" na docstring e já falha de
# forma graciosa (devolve status "erro" por arquivo, nunca lança) --
# operadores que precisem dela rodam como root pontualmente
# (`docker compose exec -u root backend ...`), não como parte do runtime
# normal da aplicação.
#
# `setcap` exige a capability CAP_SETFCAP durante o BUILD da imagem --
# presente por padrão em `docker build`/BuildKit convencional (a etapa de
# build roda como root, sem capabilities restritas); só relevante numa
# pipeline que já restrinja isso deliberadamente.
RUN apt-get update && apt-get install -y --no-install-recommends \
        iptables ipset libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# `readlink -f` resolve o alvo REAL de iptables/ip6tables -- no Debian eles
# costumam ser symlinks geridos por `update-alternatives` (apontando para
# um binário "legacy" ou "nft" multi-chamada); aplicar `setcap` num symlink
# não tem efeito nenhum, precisa ser no arquivo de verdade por trás dele.
RUN for bin in ipset iptables ip6tables; do \
        alvo="$(readlink -f "$(command -v "$bin")")" && \
        setcap cap_net_admin,cap_net_raw+ep "$alvo"; \
    done

# UID/GID fixos (não deixados para o daemon Docker escolher) -- previsível
# para quem for conferir/ajustar permissões de volume por fora (ex.: o
# bind mount `./data:/app/data` do docker-compose.yml).
RUN groupadd --gid 1000 sentinela \
    && useradd --uid 1000 --gid sentinela --create-home --shell /usr/sbin/nologin sentinela

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .
# _montar_react_se_existir (sentinela/main.py) procura o build em
# frontend-react/dist relativo à raiz do projeto -- ou seja, um nível acima
# de sentinela/ dentro de /app.
COPY --from=frontend-build /frontend/dist ./frontend-react/dist

# Estado do firewall (bloqueios_estado.json, log e auditoria locais -- ver
# core/firewall.py:_DIR_ESTADO) persistido via bind mount (ver
# docker-compose.yml) -- não mais um diretório "./data" morto como no
# projeto Streamlit original, onde nada escrevia lá. `chown -R` de /app
# inteiro (não só /app/data): o usuário `sentinela` precisa conseguir ler
# o código-fonte/dependências copiados acima, que vieram com dono root do
# `COPY`.
RUN mkdir -p /app/data && chown -R sentinela:sentinela /app
ENV SENTINELA_ESTADO_DIR=/app/data

USER sentinela

EXPOSE 8000
CMD ["uvicorn", "sentinela.main:app", "--host", "0.0.0.0", "--port", "8000"]
