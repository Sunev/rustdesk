#!/usr/bin/env python3
"""Generate the ed25519 key pair that signs this fork's update metadata.

Prints the CI secret, the CI variable and the public key array to embed in
`src/update_metadata.rs`. Nothing is written to disk.

    python res/update/generate_update_keypair.py                 # new key pair
    python res/update/generate_update_keypair.py --from-seed -   # reprint, seed on stdin
    python res/update/generate_update_keypair.py --from-seed <b64>

The seed is the private key. Prefer `--from-seed -` over passing it as an
argument: command lines stay in shell history and process listings.
"""
import argparse
import base64
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

SEED_BYTES = 32


def parse_seed(raw):
    if raw == "-":
        raw = sys.stdin.readline().strip()
    if not raw:
        raise SystemExit("--from-seed needs a base64 seed, or '-' to read it from stdin")
    try:
        seed = base64.b64decode(raw, validate=True)
    except ValueError as error:
        raise SystemExit(f"invalid base64 seed: {error}")
    if len(seed) != SEED_BYTES:
        raise SystemExit(f"seed must decode to {SEED_BYTES} bytes")
    if len(set(seed)) == 1:
        raise SystemExit("refusing a constant seed: it carries no entropy")
    return seed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--from-seed",
        help="canonical base64 ed25519 seed to reprint, or '-' to read it from stdin",
    )
    parser.add_argument(
        "--public-only",
        action="store_true",
        help="print only the public key, to check a pasted key without echoing the seed",
    )
    args = parser.parse_args()
    if args.from_seed is None:
        if args.public_only:
            raise SystemExit("--public-only requires --from-seed: a fresh pair must save its seed")
        seed = os.urandom(SEED_BYTES)
    else:
        seed = parse_seed(args.from_seed)

    public_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key()
    public_bytes = public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    if not args.public_only:
        print("SECRET - repository secret RUSTDESK_UPDATE_ED25519_SEED")
        print("  never paste this into source, issues, logs, transcripts or chats")
        print(f"  {base64.b64encode(seed).decode()}")
        print()
    print("PUBLIC - repository variable RUSTDESK_UPDATE_ED25519_PUBLIC_KEY")
    print(f"  {base64.b64encode(public_bytes).decode()}")
    print()
    print("PUBLIC - src/update_metadata.rs -> TRUSTED_UPDATE_KEYS[0].public_key")
    print("    public_key: [")
    for start in range(0, SEED_BYTES, 12):
        chunk = ", ".join(str(byte) for byte in public_bytes[start : start + 12])
        print(f"        {chunk},")
    print("    ],")
    print()
    print("Then validate the wiring:")
    print("  python res/update/generate_update_metadata.py check-key")


if __name__ == "__main__":
    main()
