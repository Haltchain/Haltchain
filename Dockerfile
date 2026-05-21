FROM rust:1.87-slim-bookworm AS builder

WORKDIR /app
# Copy lockfiles/manifests first so dependency resolution can be cached.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
	--mount=type=cache,target=/usr/local/cargo/git \
	--mount=type=cache,target=/app/target \
	cargo build -p haltchain-api --release --bin haltchain-api \
	&& cp /app/target/release/haltchain-api /tmp/haltchain-api

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /tmp/haltchain-api ./haltchain-api

EXPOSE 8080
CMD ["./haltchain-api"]
