# syntax=docker/dockerfile:1

FROM rust:1-slim AS builder
RUN --mount=type=cache,target=/var/lib/apt/,sharing=locked \
    --mount=type=cache,target=/var/cache/apt/,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates
WORKDIR /src
COPY . .
RUN cargo build --release \
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
