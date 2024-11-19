FROM rust:1.70

WORKDIR /zkp-server

COPY . .

RUN apt update
RUN apt-get install -y protobuf-compiler

RUN cargo build --release --bin server --bin client

