# Build stage
FROM rust:1.87-slim-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build -p haltchain-api --release --bin haltchain-api \
    && cp /app/target/release/haltchain-api /tmp/haltchain-api

# Runtime
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /tmp/haltchain-api ./haltchain-api

# The sidecar listens on 8787 so the main application port (8080) stays free.
ENV PORT=8787

EXPOSE 8787

# Required environment variables (injected via K8s secret / env):
#   HALTCHAIN_API_KEYS     — comma-separated API keys agents must present
#   HALTCHAIN_ADMIN_KEYS   — comma-separated admin keys for the admin API
#   DATABASE_URL           — optional Postgres DSN for persistence
#   JWT_SECRET             — secret for short-lived JWT tokens

CMD ["./haltchain-api"]
