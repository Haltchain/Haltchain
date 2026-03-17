#Build stage 
FROM rust:latest AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY src ./src
RUN cargo build -p haltchain-api --release --bin haltchain-api

# Runtime
FROM debian:stable-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/haltchain-api .

# The sidecar listens on 8787 so the main application port (8080) stays free.
ENV PORT=8787

EXPOSE 8787

# Required environment variables (injected via K8s secret / env):
#   HALTCHAIN_API_KEYS     — comma-separated API keys agents must present
#   HALTCHAIN_ADMIN_KEYS   — comma-separated admin keys for the admin API
#   DATABASE_URL           — optional Postgres DSN for persistence
#   JWT_SECRET             — secret for short-lived JWT tokens

CMD ["./haltchain-api"]
