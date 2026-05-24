FROM rust:1.87-slim-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY haltchain-operator ./haltchain-operator
COPY src ./src
RUN cargo build -p haltchain-api --release --bin haltchain-api \
    && cp target/release/haltchain-api /tmp/haltchain-api

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /tmp/haltchain-api ./haltchain-api
COPY demo/baseline.json ./demo/baseline.json

ENV PORT=8787
ENV HALTCHAIN_MCP_BASELINE_PATH=/app/demo/baseline.json
ENV HALTCHAIN_API_KEYS=dev-key
ENV HALTCHAIN_SQLITE_PATH=/tmp/haltchain.db
ENV RUST_LOG=info

EXPOSE 8787
CMD ["./haltchain-api", "--profile", "standalone"]
