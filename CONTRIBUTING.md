# Contributing

Bug reports, questions and pull requests are welcome.

## Report a problem

- A bug or a question: open an [issue](https://github.com/theogbob/finalwisp/issues). The bug form asks for the
  output of `finalwisp --version` and of `finalwisp YOUR-OPTIONS --show-config`, which prints the settings in effect
  and what the host allows. It hides the user name and the password of an `--upstream` URL.
- A security problem: do not open an issue. See [SECURITY.md](SECURITY.md).

## Build and test

You need Linux on x86_64, rustup (the toolchain is pinned in `rust-toolchain.toml`) and gcc.

```sh
cd server
cargo build --release
cargo test --release
cargo fmt --check
cargo clippy --release --all-targets -- -D warnings
```

The checks that run on every pull request are in [`.github/workflows/ci.yml`](.github/workflows/ci.yml): the last
three commands above, clippy with the `pooltest` feature, the tests of the load generator in `bench/`, and the release
build. `bench/README.md` describes the protocol tests (`bench/wst compat`) and the benchmark tools.

The release binary is built with `bench/release.sh`. It is reproducible: see
[build it yourself](docs/getting-started.md#build-it-yourself).

## What a change needs

- New behaviour is off by default, or it comes with numbers that show why it should be on.
- A new option has a row in the [configuration reference](docs/configuration.md), a line in `finalwisp --help`, and
  works in a config file. `python3 bench/tools/doccheck.py` fails when an option is missing from the reference or
  when a link in the documentation does not resolve.
- A statement about speed or memory names what was measured and how. [Benchmarking](docs/benchmarking.md) has the
  tools.
- Documentation uses short sentences and common words. Each page starts with what it gets you and a block to copy.

Contributions are under the [Apache License 2.0](LICENSE), like the rest of the repository.
