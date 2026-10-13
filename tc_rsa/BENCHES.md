# tc_rsa benchmarks

## Results

Measured on 2026-10-13 on the local Windows x86-64 host, an 11th Gen Intel
Core i7-1185G7 at 3.00 GHz, using Rust 1.98.0 and Cargo's optimized bench
profile, so a limb is 64 bits. These results describe this host and run, not a
cross-platform ranking.

Each engine case used Criterion with a 3-second warm-up, a 15-second
measurement window and 100 samples; each key generation case used 10 samples.
Criterion widened the window where the samples did not fit in it. Values below
are Criterion's central time estimates.

Every engine runs the first key of Wycheproof's `rsa_pkcs1_2048_test.json`,
a 2048-bit modulus with the public exponent 65537, on one 256-byte block. Keys,
engines and buffers are set up before the timing starts, so a case times
`process_block` alone. Key generation times one 2048-bit pair from a fresh
generator, each drawing from `StdRng` seeded anew.

**Time per operation; lower is better.**

| Operation | Fixed width | Padded | RustCrypto `rsa` |
| --- | ---: | ---: | ---: |
| Public key, `x^e mod n` | 355.6 µs | 712.7 µs | 145.8 µs |
| Private key without the CRT, `x^d mod n` | 15.00 ms | 14.16 ms | — |
| Private key with the CRT, checked | 4.53 ms | 8.70 ms | 4.08 ms |
| 2048-bit key pair generation | 504 ms | 551 ms | 80 ms |

The fixed-width engines run at `FixedBigUint` of 2048 bits, and the CRT one at
1024 bits for the primes; the padded engines run at the width of the modulus
and of each prime. `rsa` has no engine for a private key without its CRT
values, which is why that cell is empty.

The engines of this crate raise a private exponent in constant time, over
every bit of its width. The CRT engines check each result by raising it back
to `e`, which the CRT row includes for all three. With the CRT, the fixed-width
engine is within about 10% of `rsa`; with a public key, `rsa` is about 2.4
times as fast. The padded engines allocate their working values, which shows
most on the short public operation, and the padded CRT engine takes about
twice as long as the fixed-width one.

Key generation draws candidates at random until two primes are found, so its
time varies widely from one pair to the next: the confidence intervals of the
fixed and padded generators span from about 340 to 690 ms. The generators of
this crate test candidates after Bouncy Castle's `RsaKeyPairGenerator`, in
variable time, as Bouncy Castle's do.

Some samples were outliers; system load and CPU behaviour can affect small
differences.

## Running the benchmarks

The benchmark compares against the RustCrypto `rsa` crate, so it needs the
`rustcrypto` feature. Run every case with windows of at least 15 seconds,
which keep the noise down:

```powershell
cargo bench -p tc_rsa --features rustcrypto --bench rsa2048 --locked -- --warm-up-time 3 --measurement-time 15
```

Run one group, for example the private operation with the CRT:

```powershell
cargo bench -p tc_rsa --features rustcrypto --bench rsa2048 --locked -- '^private_crt/'
```

The full suite takes roughly 5 minutes plus compilation and analysis time. For
a smoke test without performance measurement:

```powershell
cargo bench -p tc_rsa --features rustcrypto --bench rsa2048 --locked -- --test
```
