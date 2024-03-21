_default:
    @just --list

build-linux:
    cargo build --release --target x86_64-unknown-linux-musl
