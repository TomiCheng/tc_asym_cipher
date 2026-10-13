# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Rules

- Comments and documentation are written in English only — doc comments,
  README, changelog, and inline comments alike.
- Never wire a README into rustdoc (`#![doc = include_str!("../README.md")]`).
  The README's badges and relative links do not survive rustdoc rendering.
  Crate documentation lives in `//!` and `///` comments; the README repeats what
  a reader on crates.io needs.
- No breaking changes. Public API work is additive: adding items, trait
  implementations, or default methods. If a change cannot be made additively,
  stop and raise it rather than altering an existing signature or behavior.
- Every crate README opens with the badge block: crates.io, docs.rs, CI,
  license, and rustc.
- Crate READMEs are short and written for crates.io: the badge block, a
  sentence or two on what the crate is, the "Types", "Traits" and "Features"
  lists, a usage example of ten lines or fewer, a short security note and the
  license. Behaviour belongs in the rustdoc, and validation and release
  commands in the root README.
- Crate READMEs use no Markdown tables; crates.io renders them badly. Traits,
  types and features are flat one-line bullets (`` `Item` — what it does. ``). Benchmark results
  and how to reproduce them live in the crate's `BENCHES.md`, which is in the
  `include` list, and the README links to it. `BENCHES.md` is read on GitHub,
  so its results may use tables.

The crate list and workspace-wide checks live in the root
[README.md](README.md); read it rather than restating it here. Every crate is
`no_std`. `tc_asym_cipher` needs no allocator; `tc_rsa` turns its `alloc`
feature on by default and keeps its fixed-width engines without it; the
encodings always use `alloc` for their block buffers.

The crates follow Bouncy Castle's asymmetric classes and keep their names
where they fit. `tc_asym_cipher` holds the contracts alone:
`AsymmetricBlockCipher` and `AsymmetricBlockCipherInit<P>`, after
`IAsymmetricBlockCipher`, `KeyPairGenerator` and `KeyPairGeneratorInit<P>`,
after `IAsymmetricCipherKeyPairGenerator`, `AsymmetricKeyParams`, through
which an encoding learns whether a key is private, and `CipherDirection`.
Initialization and processing are separate traits, the cipher's `init` takes
its key by reference, and the generator's takes its parameters by value, since
they carry the random source. The traits make no timing promise. The crate
has no dependencies.

`tc_rsa` holds the engines, each an `AsymmetricBlockCipher`: RSA without the
CRT and with it, over `FixedBigUint` with no allocator and over
`PaddedBigUint` with `alloc`, and, behind `rustcrypto`, over the RustCrypto
`rsa` crate. Every engine writes the whole of its output block, leading zeros
kept, and leaves trimming to the padding, so the length of a decryption shows
nothing; the CRT engines check each result by raising it back to `e`.
`RsaBlindedEngine` blinds the private operation of any engine that implements
`RsaBlinding`. With `alloc`, `RsaKey` holds a key over `PaddedBigUint`,
`RsaEngine` runs it on the engine the key and the features suit best, and
`RsaKeyGenerator` generates pairs of it; `RsaKeyPairGenerator` generates into
the caller's integer types, and the blinding engine, factor generator and
parameters serve blind signatures. Keys validate once, as Bouncy Castle's
`RsaKeyParameters` does, and owned keys wipe themselves on drop. The engines
are constant time in the input and the private key; the public exponent and
the outcome of range and key checks show. Key generation is variable time.
`tests/engines_agree.rs` runs every engine on the same Wycheproof key, and
`tests/generated_keys.rs` runs the keys of each generator on the engines of
the other.

`tc_asym_encoding` holds `Pkcs1Encoding` and `OaepEncoding`, each an
asymmetric block cipher over any engine, and `EncodingError`, which wraps the
engine's error. PKCS#1 v1.5 takes the block type from whether the key is
private; with `with_plaintext_length` it gives back random bytes in place of a
bad block, against Bleichenbacher's attack. OAEP runs MGF1 over a `tc_digest`
digest and reports every bad block as one `InvalidBlock`, found after the
whole block is checked. Both are constant time in the message and the block,
apart from the engine and the digest. ISO 9796-1 reads the modulus of an RSA
key, so it lives in `tc_asym_iso9796`, over a blinded `RsaEngine`, not here.

`tc_asym_iso9796` holds `Iso9796d1Encoding` and `Iso9796Error`. It turns down
the moduli, messages and blocks on which Bouncy Castle reads out of bounds,
cuts short or loops, and is variable time, only for public values. Part 2,
`Iso9796d2Signer`, is not implemented; its crate documentation says so.

Each crate but `tc_asym_cipher` has a `tests/documentation.rs` that requires
its declarations to say "constant time" or "variable time", exactly one,
matched without case and across wrapped lines. `tc_rsa`'s reads every file
under `src` and holds every public function and every trait implementation
with a method to it, in the implementation's doc or in each method's; the
encodings' read the files they name and the declarations they list. A mixed
contract names one classification and describes the other part without the
phrase, as "constant time in the input and the private key; the public
exponent shows". Keep the timing contract of each item stated in its doc
comment.

`unsafe` code is forbidden at every crate root.

Rust 1.85 is guaranteed for every build but one. Besides `tc_*` crates, the
libraries depend on `num-traits` and `rand_core`, and both build on 1.85;
dev-dependencies such as `criterion` and `rand` are exempt. The exception is
the default-off `rustcrypto` feature of `tc_rsa`, which `tc_asym_iso9796`
forwards: it brings in `rsa`, pinned to one release candidate, with `zeroize`,
and follows the Rust version they and their dependencies require. The MSRV
job therefore runs `cargo check` on 1.85 on the default build, which turns
every other feature on, and on `tc_rsa` without default features; tests run
on stable. `.cargo/config.toml` sets `incompatible-rust-versions = "allow"` so
`Cargo.lock` tracks the latest releases and stable CI tests what current
toolchains resolve. Adding another third-party dependency to a default build
or a first-party feature hands the 1.85 guarantee to that crate; raise it
before doing so.

A crate depends on a workspace sibling through `path` plus `version`, so the
workspace builds and tests against the local crate while the published package
requires the release. When a change needs a sibling API that is not released
yet, raise the `version` requirement to the release that adds it; that release
has to be published first.

## Conventions

Each crate ships its own `README.md`, `CHANGELOG.md`, `LICENSE-MIT`,
`LICENSE-APACHE`, and an explicit `include` list in `Cargo.toml`. Changelog
entries are written as `## <version> - Unreleased` and dated in a separate
commit at release, with `### Added` and `### Compatibility` sections.

Adding a crate to the workspace means five edits beyond the crate itself: the
`members` list, a `-p <crate>` on the single `cargo package --locked` step in
the CI `quality` job (the only place package archives are verified; packaging
the crates in one invocation checks each against its siblings' local sources
rather than their releases), a `cargo tree` check of its dependency set in the
CI `portable` job, a row in the root `README.md`, and
workspace inheritance for `edition`, `rust-version`, `license`, and
`repository`. A missing `rust-version` also leaves clippy suggesting APIs newer
than 1.85.

Documentation is part of the contract: crates use `#![deny(missing_docs)]`,
doctests carry the executable examples, and CI runs `cargo doc` with
`RUSTDOCFLAGS: -D warnings`, with and without `--all-features`. Doc links to
feature-gated items break the build without that feature, so name them in plain
code spans. An additive public API change belongs in the crate README's
contract lists — "Types", "Traits" and "Features" in
each crate's `README.md` — and in the changelog, not only in the code.

Work happens on `feat/*` branches off `develop`; pull requests target `develop`,
which merges to `main`. Commit messages use an imperative subject and a wrapped
body that explains the reasoning, not a bullet list of the diff.

Note: the root `Cargo.toml` uses CRLF line endings while the rest of the tree
uses LF. Tools that rewrite whole files will flip it and produce a noisy diff.
