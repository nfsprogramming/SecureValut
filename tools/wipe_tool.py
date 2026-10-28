#!/usr/bin/env python3
"""
SecureVault Remote Wipe Key & Signing Tool (Module 8 / F10)
------------------------------------------------------------
Generates P-256 (secp256r1) ECDSA key pairs and signs remote-wipe commands
in the exact format verified by WipeCommandVerifier.kt.

Usage:
  1. Generate key pair:
     python wipe_tool.py generate-key --out-key wipe_private.pem

  2. Sign a wipe command:
     python wipe_tool.py sign --key wipe_private.pem

  3. Verify a wipe signature:
     python wipe_tool.py verify --key wipe_private.pem --payload "WIPE|1700000000000|abc123" --signature "MEQC..."
"""

import argparse
import base64
import json
import os
import secrets
import sys
import time
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.exit(
        "Error: 'cryptography' library is required.\n"
        "Install it with: pip install cryptography"
    )


def generate_key(out_private_path: Path, out_public_path: Path = None):
    """Generate EC P-256 private and public keys."""
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Serialize private key to PEM (PKCS#8)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    out_private_path.write_bytes(private_pem)

    # Public key in SubjectPublicKeyInfo (SPKI) DER format, Base64 encoded
    # This directly matches Java's X509EncodedKeySpec for KeyFactory.getInstance("EC").generatePublic(...)
    public_key = private_key.public_key()
    pub_spki_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    b64_pub = base64.b64encode(pub_spki_der).decode("ascii")

    # Also save public PEM if path requested
    if out_public_path:
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        out_public_path.write_bytes(public_pem)

    print("=" * 70)
    print(" SecureVault Remote Wipe Keypair Generated")
    print("=" * 70)
    print(f" Private key written to:  {out_private_path.resolve()}")
    if out_public_path:
        print(f" Public key (PEM) to:    {out_public_path.resolve()}")
    print("-" * 70)
    print(" BASE64 PUBLIC KEY (Set as WIPE_PUBLIC_KEY_B64 in app/build.gradle.kts):")
    print("-" * 70)
    print(b64_pub)
    print("=" * 70)
    return b64_pub


def load_private_key(key_path: Path):
    """Load private EC key from PEM file."""
    if not key_path.exists():
        sys.exit(f"Error: Private key file not found: {key_path}")
    data = key_path.read_bytes()
    return serialization.load_pem_private_key(data, password=None)


def load_public_key(key_path_or_b64: str):
    """Load public EC key from file or base64 SPKI."""
    p = Path(key_path_or_b64)
    if p.exists():
        data = p.read_bytes()
        try:
            return serialization.load_pem_public_key(data)
        except Exception:
            # Might be private key PEM
            priv = serialization.load_pem_private_key(data, password=None)
            return priv.public_key()
    # Try decoding from Base64 SPKI DER
    try:
        der = base64.b64decode(key_path_or_b64)
        return serialization.load_der_public_key(der)
    except Exception as e:
        sys.exit(f"Error: Unable to load public key: {e}")


def sign_command(key_path: Path, timestamp: int = None, nonce: str = None, raw_payload: str = None):
    """Sign a wipe command payload."""
    private_key = load_private_key(key_path)

    if raw_payload:
        payload = raw_payload
    else:
        ts = timestamp if timestamp is not None else int(time.time() * 1000)
        nc = nonce if nonce is not None else secrets.token_hex(8)
        payload = f"WIPE|{ts}|{nc}"

    # Sign with SHA256withECDSA (ASN.1 DER format)
    signature_bytes = private_key.sign(
        payload.encode("utf-8"),
        ec.ECDSA(hashes.SHA256()),
    )
    signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

    result = {
        "payload": payload,
        "signature": signature_b64,
    }

    print("=" * 70)
    print(" SecureVault Signed Remote Wipe Command")
    print("=" * 70)
    print(f" Payload:   {payload}")
    print(f" Signature: {signature_b64}")
    print("-" * 70)
    print(" JSON Body (for /wipe-command endpoint or API response):")
    print(json.dumps(result, indent=2))
    print("=" * 70)
    return result


def verify_command(key_str: str, payload: str, signature_b64: str):
    """Verify a wipe command signature."""
    public_key = load_public_key(key_str)
    try:
        sig_bytes = base64.b64decode(signature_b64)
        public_key.verify(
            sig_bytes,
            payload.encode("utf-8"),
            ec.ECDSA(hashes.SHA256()),
        )
        print(" VERIFICATION SUCCESSFUL: Signature is valid for payload.")
        return True
    except InvalidSignature:
        print(" VERIFICATION FAILED: Invalid signature for payload.")
        return False
    except Exception as e:
        print(f" VERIFICATION ERROR: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="SecureVault Remote Wipe Key & Signing Tool")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # generate-key
    gen_parser = subparsers.add_parser("generate-key", help="Generate an EC P-256 key pair")
    gen_parser.add_argument("--out-key", default="wipe_private.pem", type=Path, help="Private key output path")
    gen_parser.add_argument("--out-pub", default=None, type=Path, help="Public key PEM output path (optional)")

    # sign
    sign_parser = subparsers.add_parser("sign", help="Sign a wipe command payload")
    sign_parser.add_argument("--key", required=True, type=Path, help="Path to private key PEM")
    sign_parser.add_argument("--timestamp", type=int, help="Optional epoch millis (defaults to current time)")
    sign_parser.add_argument("--nonce", type=str, help="Optional nonce string (defaults to random 16 hex chars)")
    sign_parser.add_argument("--payload", type=str, help="Explicit raw payload string (e.g. WIPE|1700000000000|abc123)")

    # verify
    verify_parser = subparsers.add_parser("verify", help="Verify a wipe command signature")
    verify_parser.add_argument("--key", required=True, type=str, help="Path to key file or Base64 public key")
    verify_parser.add_argument("--payload", required=True, type=str, help="Wipe payload (WIPE|timestamp|nonce)")
    verify_parser.add_argument("--signature", required=True, type=str, help="Base64 encoded ECDSA signature")

    args = parser.parse_args()

    if args.subcommand == "generate-key":
        generate_key(args.out_key, args.out_pub)
    elif args.subcommand == "sign":
        sign_command(args.key, args.timestamp, args.nonce, args.payload)
    elif args.subcommand == "verify":
        valid = verify_command(args.key, args.payload, args.signature)
        sys.exit(0 if valid else 1)


if __name__ == "__main__":
    main()

