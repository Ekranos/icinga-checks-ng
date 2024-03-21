# icinga-checks-ng

Just some icinga checks I had to or wanted to build or rebuild. I try to
stay compatible with older versions of these, but use at your own risk.

Also there are basically no docs except the help messages.

# Build

Install Rust and Cargo.

    # Build for your current platform
    cargo build --release
    # or to build statically linked binaries for Linux via musl
    just build-linux

# License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  http://opensource.org/licenses/MIT)

at your option.
