# Contributing

Thanks for helping. Before opening a pull request:

1. `cargo fmt --all`, `cargo clippy --locked --all-targets -- -D warnings` and
   `cargo test --locked` pass (CI runs them on Linux, macOS and Windows).
2. New behaviour has tests; anything that parses data from the host (log lines, journal JSON,
   event XML) also has tests with hostile input.
3. No `unsafe` outside `src/os/windows` modules, and every `unsafe` block has a `SAFETY:` note.
4. No new dependency without a reason in the PR; `cargo deny check` must pass (no OpenSSL,
   no native-tls, permissive licences only).
5. Commits follow [Conventional Commits](https://www.conventionalcommits.org/), for example
   `fix(collectors): handle journal cursor reset`.
6. Examples and fixtures use fictional values only (`example.com`, `192.0.2.0/24`, `web-01`).

Australian English in docs, comments and messages.

For security issues, see [SECURITY.md](SECURITY.md) instead.
