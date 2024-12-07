FROM rust:1.81 AS base

RUN mkdir /app
WORKDIR /app

RUN cargo install cargo-chef --locked

FROM base AS planner
WORKDIR /app
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM base AS builder

COPY --from=planner /app/recipe.json recipe.json

RUN cargo chef cook --release --recipe-path recipe.json
COPY . .

RUN cargo build --release

FROM debian:bookworm-slim AS runner

RUN apt-get update && apt-get install -y ca-certificates libssl-dev

RUN mkdir /app
WORKDIR /app

COPY --from=builder /app/target/release/pinbot /app/pinbot

CMD ["/app/pinbot"]

EXPOSE 3000