#!/usr/bin/env python3
"""Standalone verifier for the published Lean Transparency Log.

Pure Python 3 standard library for hashing and structure; Ed25519
signature checking shells out to the `openssl` binary. Verifies, from the
files in this repository alone:

  1. every entry's leaf hash,
  2. every historical Signed Tree Head against the recomputed prefix root
     (a split view or tampered entry fails here),
  3. every STH Ed25519 signature,
  4. a receipt as a FULL transparency receipt (--receipt FILE): its STH
     signature, key fingerprint, log id, tree-size agreement, that its
     leaf hash matches the named entry, that its STH is present in the
     published history, and its inclusion proof.

FAIL-CLOSED: if signature checking is unavailable (no `openssl`, or the
public key is missing), the run FAILS — signatures are load-bearing and a
"couldn't check" is not a pass. Use --structural-only to explicitly ask
for hashes/structure without signatures (it prints, and exits, as a
reduced check, never as full verification).

Usage:
  python3 verify.py --all
  python3 verify.py --receipt receipts/dalek-ed25519-verified.receipt.json
  python3 verify.py --all --structural-only   # explicit reduced check
"""
import argparse
import base64
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaves):
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaf_hash(leaves[0])
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return node_hash(merkle_root(leaves[:split]), merkle_root(leaves[split:]))


def verify_inclusion(leaf: bytes, index: int, size: int, proof, root: bytes) -> bool:
    if index >= size:
        return False
    fn, sn = index, size - 1
    node = leaf_hash(leaf)
    for sibling in proof:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            node = node_hash(sibling, node)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn //= 2
                    sn //= 2
        else:
            node = node_hash(node, sibling)
        fn //= 2
        sn //= 2
    return sn == 0 and node == root


def canonical_json(document) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def load_leaves():
    leaves, problems = [], []
    for position, path in enumerate(sorted((HERE / "entries").glob("[0-9]*.json"))):
        record = json.loads(path.read_text())
        data = canonical_json(record["leaf"])
        if record.get("index") != position:
            problems.append(f"{path.name}: index {record.get('index')} at position {position}")
        if leaf_hash(data).hex() != record.get("leaf_hash"):
            problems.append(f"{path.name}: leaf_hash mismatch (tampered entry)")
        leaves.append(data)
    return leaves, problems


def signatures_available() -> bool:
    return bool(shutil.which("openssl")) and (HERE / "provider.ed25519.pub").exists()


def key_fingerprint() -> str:
    return hashlib.sha256((HERE / "provider.ed25519.pub").read_bytes()).hexdigest()


def check_sth_signature(head) -> str:
    """VALID / INVALID / UNAVAILABLE. UNAVAILABLE is a FAILURE at the
    caller unless the run is explicitly --structural-only."""
    openssl = shutil.which("openssl")
    key = HERE / "provider.ed25519.pub"
    if not openssl or not key.exists():
        return "UNAVAILABLE"
    signatures = head.get("signatures") or {}
    ed = signatures.get("ed25519") or {}
    payload = canonical_json({k: v for k, v in head.items() if k != "signatures"})
    with tempfile.TemporaryDirectory() as tmp:
        payload_path = Path(tmp) / "p"
        signature_path = Path(tmp) / "s"
        payload_path.write_bytes(payload)
        signature_path.write_bytes(base64.b64decode(ed.get("signature_base64", "")))
        result = subprocess.run(
            [openssl, "pkeyutl", "-verify", "-pubin", "-inkey", str(key), "-rawin",
             "-in", str(payload_path), "-sigfile", str(signature_path)],
            capture_output=True,
        )
    return "VALID" if result.returncode == 0 else "INVALID"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--receipt")
    parser.add_argument("--structural-only", action="store_true",
                        help="skip Ed25519 signature checks explicitly; the run reports a "
                             "REDUCED check and can never print full verification.")
    args = parser.parse_args()

    sigs_ok = signatures_available()
    if not args.structural_only and not sigs_ok:
        # Fail closed: a verifier that cannot check signatures must not
        # imply it did. Do not silently continue.
        print("FATAL: signature checking unavailable (need the `openssl` binary and "
              "provider.ed25519.pub). Install openssl / fetch the key, or pass "
              "--structural-only to run an explicit hashes-and-structure check.")
        return 2

    leaves, problems = load_leaves()
    print(f"entries: {len(leaves)}")
    failures = list(problems)
    for problem in problems:
        print("PROBLEM:", problem)

    history_path = HERE / "sth-history.jsonl"
    heads = [json.loads(line) for line in history_path.read_text().splitlines() if line.strip()] if history_path.exists() else []

    if args.all or not args.receipt:
        # log-wide checks (GPT §4.3): history internally consistent AND the
        # published latest-sth.json is exactly the final history head.
        previous = -1
        log_id = None
        for position, head in enumerate(heads):
            size = int(head["tree_size"])
            if size > len(leaves):
                failures.append(f"STH #{position} claims size {size} > {len(leaves)} leaves")
            expected = merkle_root(leaves[:size]).hex()
            structural = "OK" if head["root_hash"] == expected and size >= previous else "MISMATCH"
            if structural != "OK":
                failures.append(f"STH #{position} prefix-root/monotonicity")
            if log_id is None:
                log_id = head.get("log_id")
            elif head.get("log_id") != log_id:
                failures.append(f"STH #{position} log_id changed mid-history")
            signature = check_sth_signature(head)
            if signature == "INVALID" or (signature == "UNAVAILABLE" and not args.structural_only):
                failures.append(f"STH #{position} signature {signature}")
            print(f"STH #{position} size={size} root={head['root_hash'][:16]}… prefix-root:{structural} signature:{signature}")
            previous = max(previous, size)
        latest_path = HERE / "latest-sth.json"
        if latest_path.exists() and heads:
            latest = json.loads(latest_path.read_text())
            if canonical_json(latest) != canonical_json(heads[-1]):
                failures.append("latest-sth.json is not the final sth-history head")
            elif int(latest["tree_size"]) != len(leaves):
                failures.append(f"latest-sth tree_size {latest['tree_size']} != {len(leaves)} leaves")
            else:
                print(f"latest-sth: size {latest['tree_size']} == leaf count, and == final history head  OK")

    if args.receipt:
        receipt = json.loads(Path(args.receipt).read_text())
        sth = receipt["sth"]
        index = int(receipt["leaf_index"])
        entry = json.loads((HERE / "entries" / f"{index:06d}.json").read_text())
        leaf_bytes = canonical_json(entry["leaf"])

        # (a) the receipt's STH must be signed by THIS log's key ...
        rsig = check_sth_signature(sth)
        if rsig == "INVALID" or (rsig == "UNAVAILABLE" and not args.structural_only):
            failures.append(f"receipt STH signature {rsig}")
        # (b) ... fingerprint the receipt names must be this key ...
        fp = (sth.get("signatures", {}).get("ed25519", {}) or {}).get("public_key_fingerprint_sha256")
        if sigs_ok and fp and fp != key_fingerprint():
            failures.append("receipt STH signed by a different key than provider.ed25519.pub")
        # (c) ... its log_id must match the log ...
        meta_log_id = json.loads((HERE / "log-metadata.json").read_text()).get("log_id") if (HERE / "log-metadata.json").exists() else None
        if meta_log_id and sth.get("log_id") not in (None, meta_log_id):
            failures.append("receipt STH log_id does not match this log")
        # (d) ... the receipt's STH must actually appear in the published history ...
        if heads and canonical_json(sth) not in {canonical_json(h) for h in heads}:
            failures.append("receipt STH is not present in sth-history.jsonl")
        # (e) ... the receipt's leaf_hash must match the named entry ...
        if receipt.get("leaf_hash") and receipt["leaf_hash"] != leaf_hash(leaf_bytes).hex():
            failures.append("receipt leaf_hash does not match the named entry")
        # (f) ... tree_size agreement ...
        if int(receipt.get("tree_size", -1)) != int(sth.get("tree_size", -2)):
            failures.append("receipt tree_size != its STH tree_size")
        # (g) ... and finally the inclusion proof itself.
        ok = verify_inclusion(
            leaf_bytes, index, int(receipt["tree_size"]),
            [bytes.fromhex(h) for h in receipt["inclusion_proof"]],
            bytes.fromhex(sth["root_hash"]),
        )
        if not ok:
            failures.append("receipt inclusion proof")
        print(f"receipt leaf {index} of {receipt['tree_size']}: STH-sig:{rsig} bindings:"
              f"{'OK' if not any('receipt' in f for f in failures) else 'FAIL'} inclusion:{'VALID' if ok else 'INVALID'}")

    mode = "REDUCED (structural only, signatures NOT checked)" if args.structural_only else "full"
    if failures:
        print(f"RESULT: FAILED ({len(failures)} problems) [{mode}]")
        return 1
    print(f"RESULT: OK [{mode}]"
          + ("" if not args.structural_only else " — signatures were NOT verified; this is not full verification"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
