import base64
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .safeio import atomic_write


def generate(private_path: str, public_path: str) -> None:
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    atomic_write(private_path, private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), 0o600)
    atomic_write(public_path, public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo), 0o644)


def sign(input_path: str, signature_path: str, private_path: str) -> None:
    private = serialization.load_pem_private_key(Path(private_path).read_bytes(), password=None)
    atomic_write(signature_path, (base64.b64encode(private.sign(Path(input_path).read_bytes())).decode() + "\n").encode(), 0o600)


def verify(input_path: str, signature_path: str, public_path: str) -> bool:
    try:
        public = serialization.load_pem_public_key(Path(public_path).read_bytes())
        signature = base64.b64decode(Path(signature_path).read_text(encoding="utf-8"))
        public.verify(signature, Path(input_path).read_bytes())
        return True
    except (InvalidSignature, ValueError, TypeError, OSError):
        return False
