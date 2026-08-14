# Fuzzing

`pcapracer` parses hostile input by definition — a capture can contain anything an attacker
chose to put on the wire. The dissect tree is `#![forbid(unsafe_code)]` and every read goes
through the bounds-checked cursor in `rust/src/bytes.rs`, so the property being fuzzed is
*termination and absence of panics*, not memory safety.

```bash
cargo install cargo-fuzz
cargo fuzz run dissect_frame
```

`fuzz_targets/dissect_frame.rs` feeds arbitrary bytes through every link type. Any panic,
hang, or unbounded allocation is a bug.
