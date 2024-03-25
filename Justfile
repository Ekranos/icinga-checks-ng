_default:
    @just --list

build-linux:
    cargo build -q --release --target x86_64-unknown-linux-musl
