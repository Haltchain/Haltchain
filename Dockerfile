FROM rust:latest AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY src ./src
RUN cargo build -p haltchain-api --release --bin haltchain-api

FROM debian:stable-slim

WORKDIR /app
COPY --from=builder /app/target/release/haltchain-api .
COPY fly.toml .

EXPOSE 8080
CMD ["./haltchain-api"]
