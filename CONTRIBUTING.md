# Contributing

## Before pushing

Run exactly what CI runs, or CI will find what you didn't:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings   # --all-targets matters: it lints test code too
cargo test --lib

maturin develop --release
cd /tmp && python -m pytest <repo>/tests -v  # run from outside the source tree
```

Two of these are easy to get wrong:

- **`--all-targets`** on clippy. Without it, lints inside `#[cfg(test)]` modules are invisible
  locally and fail in CI.
- **Running pytest from outside the repository.** From inside, `python/pcapracer/` shadows the
  installed package and a packaging mistake stays hidden.

## Adding a protocol dissector

1. Write it in `rust/src/dissect/app/`. Signature is
   `fn parse(payload: &[u8], ctx: &mut Ctx) -> DResult<()>`.
2. Read **only** through `bytes::Cur`. Never index a slice directly — the whole
   no-panics-on-hostile-input property rests on that.
3. Add the fields to `packet_schema!` in `rust/src/schema/wide.rs`, prefixed with your
   protocol name. The prefix is what wires the field into split mode automatically.
4. If the prefix is new, add a `ProtoTable` entry in `rust/src/schema/split.rs`. A test
   asserts every declared prefix matches at least one real column.
5. Register the port in `app::by_port`, and a content signature in `app::sniff` if the
   protocol has a recognisable magic.
6. Tests are not optional, and one of them must feed truncated input:

```rust
#[test]
fn truncated_input_never_panics() {
    let full = valid_message();
    for n in 0..full.len() {
        let mut p = Packet::default();
        let mut ctx = Ctx::new(&mut p);
        let _ = parse(&full[..n], &mut ctx);
    }
}
```

Any dissector with a loop driven by a length field from the packet needs an iteration guard.
Every existing one has a test proving a malicious length cannot make it spin — see
`dns::compression_pointer_loop_terminates` and `tunnel::gtp_extension_chain_cannot_loop`.

## Fuzzing

```bash
cargo install cargo-fuzz
cargo fuzz run dissect_frame
```

A panic or a hang is a bug. See `fuzz/README.md`.

## Invariants worth not breaking

- **Output is byte-identical at any thread count.** Anything that makes dissection depend on
  shared mutable state breaks this. `pipeline::tests::thread_count_does_not_change_the_output`
  is the guard.
- **The wide schema is the only schema.** Split mode projects from it. Do not hand-write a
  second column list.
- **Nothing is dropped silently.** If a cap or limit discards data, add a counter to
  `RunStats` and a line to `_warn_about_limits` in the CLI.
