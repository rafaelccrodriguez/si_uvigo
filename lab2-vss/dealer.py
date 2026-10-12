"""Create a VSS commitment and write participant shares to a JSON file."""

import argparse
import json
import secrets
from pathlib import Path

import ckzg


P = 52435875175126190479447740508185965837690552500527637822603658699938581184513
WIDTH = 4096  # Number of field elements in a KZG blob.
ROOT = 7      # Primitive root used to build the evaluation domain.


def reverse_12_bits(value):
    # C-KZG stores blob evaluations in bit-reversed domain order.
    result = 0
    for _ in range(12):
        result = (result << 1) | (value & 1)
        value >>= 1
    return result


def evaluate(coefficients, x):
    # Evaluate the polynomial with Horner's method, reducing modulo P.
    value = 0
    for coefficient in reversed(coefficients):
        value = (value * x + coefficient) % P
    return value


def make_blob(coefficients):
    # C-KZG commits to a 4096-value blob, so evaluate our polynomial there.
    omega = pow(ROOT, (P - 1) // WIDTH, P)
    values = []
    for index in range(WIDTH):
        point = pow(omega, reverse_12_bits(index), P)
        values.append(evaluate(coefficients, point).to_bytes(32, "big"))
    return b"".join(values)


def main():
    parser = argparse.ArgumentParser(description="Create VSS shares and KZG proofs.")
    parser.add_argument("--secret", type=int, default=123, help="Integer secret (default: 123)")
    parser.add_argument("--n", type=int, default=5, help="Number of participants (default: 5)")
    parser.add_argument("--t", type=int, default=2, help="Resilience threshold (default: 2)")
    parser.add_argument("--output", type=Path, default=Path("shares.json"))
    args = parser.parse_args()

    if args.t < 0 or args.t >= WIDTH or args.n < 2 * args.t + 1:
        parser.error("Choose t >= 0, t < 4096, and n >= 2t + 1.")
    if not 0 < args.secret < P:
        parser.error("The secret must be a nonzero integer in the BLS scalar field.")

    # The constant term is the secret; the other coefficients are random.
    coefficients = [args.secret] + [secrets.randbelow(P) for _ in range(args.t)]
    if args.t > 0:
        # Keep the polynomial's degree exactly t.
        coefficients[-1] = secrets.randbelow(P - 1) + 1
    blob = make_blob(coefficients)
    # Load the provided setup and commit to the polynomial represented by the blob.
    settings = ckzg.load_trusted_setup(str(Path(__file__).with_name("trusted_setup.txt")), 0)
    commitment = ckzg.blob_to_kzg_commitment(blob, settings)

    shares = []
    for index in range(1, args.n + 1):
        # For participant i, create the share phi(i) and its KZG witness.
        z = index.to_bytes(32, "big")
        witness, share = ckzg.compute_kzg_proof(blob, z, settings)
        shares.append({"i": index, "share": share.hex(), "witness": witness.hex()})

    # Save the public commitment and each participant's share and witness.
    data = {
        "n": args.n,
        "t": args.t,
        "commitment": commitment.hex(),
        "shares": shares,
    }
    args.output.write_text(json.dumps(data, indent=2) + "\n")
    print(f"Created commitment and {args.n} shares in {args.output}.")


if __name__ == "__main__":
    main()
