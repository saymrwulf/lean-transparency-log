#!/usr/bin/env python3
"""Adversarial self-test for verify.py — proves the fail-closed paths fail.

Each case mutates a real published receipt (or the environment) and asserts
the verifier REJECTS it; plus the honest controls. Exit 0 only if every case
behaves. Run from a clone: python3 verify_selftest.py
"""
import copy
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run(*args, env=None):
    result = subprocess.run(
        [sys.executable, str(HERE / "verify.py"), *args],
        capture_output=True, text=True, env=env,
    )
    return result.returncode, result.stdout


def base_receipt():
    path = sorted((HERE / "receipts").glob("*.receipt.json"))[0]
    return json.loads(path.read_text())


def mutated(**changes):
    receipt = copy.deepcopy(base_receipt())
    for dotted, value in changes.items():
        target, keys = receipt, dotted.split(".")
        for key in keys[:-1]:
            target = target[key]
        if value is None:
            target.pop(keys[-1], None)
        else:
            target[keys[-1]] = value
    return receipt


def check_receipt(receipt) -> int:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(receipt, handle)
        path = handle.name
    try:
        code, _ = run("--receipt", path)
        return code
    finally:
        os.unlink(path)


def main() -> int:
    cases = []

    code, out = run("--all")
    cases.append(("honest --all passes (full)", code == 0 and "RESULT: OK [full]" in out))
    cases.append(("--all covers every published receipt",
                  out.count("receipt ") == len(list((HERE / "receipts").glob("*.receipt.json")))))

    cases.append(("honest receipt passes", check_receipt(base_receipt()) == 0))
    cases.append(("missing key fingerprint REJECTED",
                  check_receipt(mutated(**{"sth.signatures.ed25519.public_key_fingerprint_sha256": None})) == 1))
    cases.append(("missing leaf_hash REJECTED", check_receipt(mutated(leaf_hash=None)) == 1))
    cases.append(("wrong receipt type REJECTED", check_receipt(mutated(type="forged.v0")) == 1))
    cases.append(("forged (unsigned) root REJECTED",
                  check_receipt(mutated(**{"sth.root_hash": "ff" * 32})) == 1))
    cases.append(("tree_size mismatch REJECTED",
                  check_receipt(mutated(tree_size=int(base_receipt()["tree_size"]) + 1)) == 1))
    cases.append(("wrong log_id REJECTED",
                  check_receipt(mutated(**{"sth.log_id": "00" * 32})) == 1))

    code, out = run("--all", "--structural-only")
    cases.append(("--structural-only is explicit, never claims full",
                  code == 0 and "REDUCED" in out and "[full]" not in out))

    # The ADDITIVE post-quantum signature must fail closed when tampered.
    # Applicable only to mirrors whose heads carry it; older mirrors record
    # the case as not-applicable rather than silently passing.
    latest = json.loads((HERE / "latest-sth.json").read_text())
    slh = (latest.get("signatures") or {}).get("slh_dsa") or {}
    if slh.get("status") == "signed":
        import base64 as _b64
        import shutil as _sh
        with tempfile.TemporaryDirectory() as tmp:
            mirror = Path(tmp) / "mirror"
            _sh.copytree(HERE, mirror)
            raw = bytearray(_b64.b64decode(slh["signature_base64"])); raw[0] ^= 1
            bad = _b64.b64encode(bytes(raw)).decode()
            for name in ("latest-sth.json", "sth-history.jsonl"):
                path = mirror / name
                text = path.read_text().replace(slh["signature_base64"], bad)
                path.write_text(text)
            result = subprocess.run([sys.executable, str(mirror / "verify.py"), "--all"],
                                    capture_output=True, text=True)
            cases.append(("corrupted slh_dsa signature REJECTED",
                          result.returncode == 1 and "slh_dsa:INVALID" in result.stdout))
            # and the missing-pubkey path: a mirror claiming the signature but
            # shipping no key is a broken publication, not a degradation.
            (mirror / "provider.slhdsa.pub").unlink()
            for name in ("latest-sth.json", "sth-history.jsonl"):
                path = mirror / name
                path.write_text(path.read_text().replace(bad, slh["signature_base64"]))
            result = subprocess.run([sys.executable, str(mirror / "verify.py"), "--all"],
                                    capture_output=True, text=True)
            cases.append(("signed slh_dsa without published key REJECTED",
                          result.returncode == 1 and "NO-PUBKEY" in result.stdout))
    else:
        cases.append(("slh_dsa cases n/a (no signed slh_dsa block in this mirror)", True))

    with tempfile.TemporaryDirectory() as tmp:
        os.symlink(sys.executable, Path(tmp) / Path(sys.executable).name)
        code, out = run("--all", env={"PATH": tmp})
        cases.append(("no openssl -> FAIL CLOSED (exit 2)", code == 2))

    width = max(len(name) for name, _ in cases)
    for name, ok in cases:
        print(f"{'PASS' if ok else 'FAIL'}  {name:<{width}}")
    if all(ok for _, ok in cases):
        print(f"SELFTEST GREEN ({len(cases)} cases)")
        return 0
    print("SELFTEST RED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
