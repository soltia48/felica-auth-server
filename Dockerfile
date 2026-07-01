# syntax=docker/dockerfile:1
#
# felica-auth-server depends on the git crate `felica-rs`, fetched over SSH at
# build time. Build with BuildKit and forward your SSH agent:
#
#   DOCKER_BUILDKIT=1 docker build --ssh default -t felica-auth-server .
#
# (or `docker compose build`, which forwards the agent via compose.yaml).

FROM rust:1-slim AS builder
RUN --mount=type=cache,target=/var/lib/apt/,sharing=locked \
    --mount=type=cache,target=/var/cache/apt/,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends git openssh-client ca-certificates \
    && mkdir -p -m 0700 /root/.ssh \
    && ssh-keyscan github.com >> /root/.ssh/known_hosts
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
WORKDIR /src
COPY . .
RUN --mount=type=ssh \
    cargo build --release \
    && cp target/release/felica-auth-server /usr/local/bin/felica-auth-server

FROM debian:stable-slim
RUN --mount=type=cache,target=/var/lib/apt/,sharing=locked \
    --mount=type=cache,target=/var/cache/apt/,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && useradd -m -u 1000 app
COPY --from=builder /usr/local/bin/felica-auth-server /usr/local/bin/felica-auth-server
USER app
ENV FELICA_HOST=0.0.0.0 \
    FELICA_PORT=8000 \
    FELICA_KEYS=/keys.jsonl
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/felica-auth-server"]
