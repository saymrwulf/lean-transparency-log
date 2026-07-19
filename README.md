# Lean Transparency Log — published mirror

This repository is the **git-published face** of a transparency log of
formal-verification attestations: signed statements that the Lean 4 proofs
of specific software, at specific git commits, re-check with exactly their
documented assumptions. Its first twelve leaves attest four cryptographic
Rust libraries (Ed25519 implementations); as of **entry 13 (2026-07-16)**
the log also attests **its own accumulator machinery** — a kernel-checked
mechanization of the log's security analysis, so the log carries
kernel-checked proofs *about the accumulator model* underlying its own
inclusion and consistency reasoning, as one of its own entries (subject
[`ltl-accumulator-verified`](https://github.com/saymrwulf/ltl-accumulator-verified);
scoped to the mechanized model — it does not prove operator honesty,
signing, or execution provenance). Current head: tree size 13, root
`3488a2d0…`.

Layout:

| Path | Content |
|---|---|
| `entries/NNNNNN.json` | one log leaf per file, append-only (git history mirrors log history) |
| `entries/<component>.attestation.json` | the newest attestation per library, for convenience |
| `receipts/<component>.receipt.json` | inclusion proof binding that attestation to the latest signed head |
| `sth-history.jsonl` | **every** Signed Tree Head ever issued — the witness channel: all cloners see the same heads |
| `latest-sth.json` | the current head |
| `provider.ed25519.pub` | the provider's public key — the sole cryptographic identity anchor; each statement's truth additionally rests on the assumptions stated in its leaf |
| `verify.py` | standalone verifier (Python stdlib + the `openssl` binary; fails closed without them; `--all` covers every published receipt) |
| `verify_selftest.py` | adversarial self-test: proves the verifier's fail-closed paths reject mutated receipts |

Verify everything locally, no installation:

```bash
python3 verify.py --all
python3 verify.py --receipt receipts/dalek-ed25519-verified.receipt.json
```

The online service (same data, live endpoints + customer documentation):
**https://ltl.zkdefi.org**

The provider tooling, agent tooling, and course materials:
**https://github.com/saymrwulf/proof-aware-crypto-tooling-agent**

Honesty notes, always in force: attestations cover Rust **source** at a
pinned commit (clone it — the commit identifies the committed git tree,
not dependencies or toolchains — and build it yourself; compilers are
declared trusted base). The log deliberately
retains early leaves recording a **failed** audit run: an append-only
trust ledger keeps its history. Tree heads are signed by the merkleized,
proof-attested Ed25519 library itself, and each signature embeds the
provider's own Merkle self-check of that library's leaf.
