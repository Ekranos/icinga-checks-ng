# icinga-checks-ng

Just some icinga checks I had to or wanted to build or rebuild. I try to
stay compatible with older versions of these, but use at your own risk.

Also there are basically no docs except the help messages.

# Build

Install Rust and Cargo.

    cargo build --release

You can now find the final binaries in `target/release/`. You may want to
`strip` them to save some space.

# License

This project is licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or
  http://opensource.org/licenses/MIT)

at your option.
