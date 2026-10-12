"""Verify shares from a JSON file and reconstruct the secret."""

import argparse
import json
from pathlib import Path

import ckzg


P = 52435875175126190479447740508185965837690552500527637822603658699938581184513


def main():
    parser = argparse.ArgumentParser(description="Verify VSS shares and reconstruct the secret.")
    parser.add_argument("shares", nargs="?", type=Path, default=Path("shares.json"))
    args = parser.parse_args()

    data = json.loads(args.shares.read_text())
    threshold = data["t"] + 1
    commitment = bytes.fromhex(data["commitment"])
    settings = ckzg.load_trusted_setup(str(Path(__file__).with_name("trusted_setup.txt")), 0)

    valid = []
    seen = set()
    for item in data["shares"]:
        try:
            index = item["i"]
            if not isinstance(index, int) or not 1 <= index <= data["n"] or index in seen:
                continue
            z = index.to_bytes(32, "big")
            share = bytes.fromhex(item["share"])
            witness = bytes.fromhex(item["witness"])
            if ckzg.verify_kzg_proof(commitment, z, share, witness, settings):
                valid.append((index, int.from_bytes(share, "big")))
                seen.add(index)
        except Exception:
            pass

    if len(valid) < threshold:
        raise SystemExit(f"Only {len(valid)} valid shares; need at least {threshold}.")

    secret = 0
    selected = valid[:threshold]
    for i, share_i in selected:
        coefficient = 1
        for j, _ in selected:
            if i != j:
                coefficient = coefficient * (-j) * pow(i - j, -1, P) % P
        secret = (secret + share_i * coefficient) % P

    print(f"Valid shares: {len(valid)} (need {threshold}).")
    print(f"Reconstructed secret: {secret}")


if __name__ == "__main__":
    main()
