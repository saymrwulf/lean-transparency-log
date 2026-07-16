# Lean Transparency Log — published mirror

This repository is the **git-published face** of a transparency log of
formal-verification attestations: signed statements that the Lean 4 proofs
of specific software, at specific git commits, re-check with exactly their
documented assumptions. Its first twelve leaves attest four cryptographic
Rust libraries (Ed25519 implementations); as of **entry 13 (2026-07-16)**
the log also attests **its own accumulator machinery** — a kernel-checked
mechanization of the log's own security analysis, making this the first
deployed transparency log to carry proofs of its own honesty as one of
its own entries (subject
[`ltl-accumulator-verified`](https://github.com/saymrwulf/ltl-accumulator-verified);
scoped to the mechanized model). Current head: tree size 13, root
`3488a2d0…`.

Layout:

| Path | Content |
|---|---|
| `entries/NNNNNN.json` | one log leaf per file, append-only (git history mirrors log history) |
| `entries/<component>.attestation.json` | the newest attestation per library, for convenience |
| `receipts/<component>.receipt.json` | inclusion proof binding that attestation to the latest signed head |
| `sth-history.jsonl` | **every** Signed Tree Head ever issued — the witness channel: all cloners see the same heads |
| `latest-sth.json` | the current head |
| `provider.ed25519.pub` | the provider's public key (the sole trust anchor) |
| `verify.py` | standalone verifier, Python standard library only |

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
pinned commit (clone it — the git hash is the content hash — and build it
yourself; compilers are declared trusted base). The log deliberately
retains early leaves recording a **failed** audit run: an append-only
trust ledger keeps its history. Tree heads are signed by the merkleized,
proof-attested Ed25519 library itself, and each signature embeds the
provider's own Merkle self-check of that library's leaf.
