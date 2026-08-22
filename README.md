# Lean Transparency Log — published mirror

This repository is the **git-published face** of a transparency log of
formal-verification attestations: signed statements that the Lean 4 proofs
of specific software, at specific git commits, re-check with exactly their
documented assumptions. Its first twelve leaves attest four cryptographic
Rust libraries (Ed25519 implementations); as of **its thirteenth entry (leaf index 12, 2026-07-16)**
the log also attests **its own accumulator machinery** — a kernel-checked
mechanization of the log's security analysis, so the log carries
kernel-checked proofs *about the accumulator model* underlying its own
inclusion and consistency reasoning, as one of its own entries (subject
[`ltl-accumulator-verified`](https://github.com/saymrwulf/ltl-accumulator-verified);
scoped to the mechanized model — it does not prove operator honesty,
signing, or execution provenance). As of **2026-08** the log also attests
the **SLH-DSA (FIPS 205) verify-path proofs** (leaf 18)
([`fips205-slhdsa-verified`](https://github.com/saymrwulf/fips205-slhdsa-verified))
and its heads carry a **second, post-quantum SLH-DSA-SHA2-128s signature**
beside the required Ed25519 one. The current head is `latest-sth.json` —
this README deliberately names no tree size, so it cannot go stale.

Layout:

| Path | Content |
|---|---|
| `entries/NNNNNN.json` | one log leaf per file, append-only (git history mirrors log history) |
| `entries/<component>.attestation.json` | the newest attestation per library, for convenience |
| `receipts/<component>.receipt.json` | inclusion proof binding that attestation to the latest signed head |
| `sth-history.jsonl` | **every** Signed Tree Head ever issued — the witness channel: all cloners see the same heads |
| `latest-sth.json` | the current head |
| `provider.ed25519.pub` | the provider's Ed25519 public key — the REQUIRED identity anchor; each statement's truth additionally rests on the assumptions stated in its leaf |
| `provider.slhdsa.pub` | the provider's SLH-DSA-SHA2-128s public key (FIPS 205) — checks the ADDITIVE post-quantum head signature; needs OpenSSL >= 3.5, and verify.py degrades honestly below that |
| `verify.py` | standalone verifier (Python stdlib + the `openssl` binary; fails closed without them; `--all` covers every published receipt) |
| `verify_selftest.py` | adversarial self-test: proves the verifier's fail-closed paths reject mutated receipts |

Verify everything locally, no installation:

```bash
python3 verify.py --all
python3 verify.py --receipt receipts/dalek-ed25519-verified.receipt.json
```

The online service (same data, live endpoints + customer documentation):
**https://ltl.zkdefi.org**

The design and its security analysis:
**https://ltl.zkdefi.org/paper** (DOI [10.5281/zenodo.22057482](https://doi.org/10.5281/zenodo.22057482))

The provider tooling, agent tooling, and course materials:
**https://github.com/saymrwulf/proof-aware-crypto-tooling-agent**

Honesty notes, always in force: attestations cover Rust **source** at a
pinned commit (clone it — the commit identifies the committed git tree,
not dependencies or toolchains — and build it yourself; compilers are
declared trusted base). The log deliberately
retains early leaves recording a **failed** audit run: an append-only
trust ledger keeps its history. Tree heads are signed by the merkleized,
proof-attested Ed25519 library itself, and each signature embeds the
provider's own Merkle self-check of that library's leaf. Heads additionally
carry a **deterministic SLH-DSA-SHA2-128s signature** over the same payload:
strictly additional, so Ed25519 remains the signature a consumer must check, and honest
about scope — the estate's certificates cover the *verification* path of both
algorithms; no signing operation is proven for either, and leaves themselves
are Ed25519-signed at issuance only. Heads published before 2026-08 have no
SLH-DSA signature and verify.py reports them as `slh_dsa:ABSENT`, which is
allowed — an append-only log keeps its history.
