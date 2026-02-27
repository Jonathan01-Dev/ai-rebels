#!/usr/bin/env python3

import os
import json
import base64

from nacl.signing import SigningKey
from Crypto.Hash import SHA256


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def sha256(data: bytes) -> bytes:
    h = SHA256.new()
    h.update(data)
    return h.digest()


def main():
    os.makedirs("keys", exist_ok=True)

    name = input("Node name (ex: nodeA): ").strip()
    if not name:
        print("Invalid name")
        return

    # Generate Ed25519 keypair
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key

    private_seed = signing_key.encode()   # 32 bytes
    public_key = verify_key.encode()      # 32 bytes

    # NODE_ID = SHA256(public_key)
    node_id = sha256(public_key)

    identity = {
        "public_key_b64": b64e(public_key),
        "private_seed_b64": b64e(private_seed),
        "node_id_hex": node_id.hex()
    }

    path = f"keys/{name}.json"

    with open(path, "w") as f:
        json.dump(identity, f, indent=2)

    print("\n✅ Identity created:")
    print("File:", path)
    print("NODE_ID:", node_id.hex())


if __name__ == "__main__":
    main()
