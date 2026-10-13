import base64
import binascii
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .safeio import atomic_write


def generate(private_path: str, public_path: str) -> None:
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    atomic_write(private_path, private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), 0o600)
    atomic_write(public_path, public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo), 0o644)


def sign(input_path: str, signature_path: str, private_path: str) -> None:
    private = serialization.load_pem_private_key(Path(private_path).read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("private key must be an Ed25519 key")
    atomic_write(signature_path, (base64.b64encode(private.sign(Path(input_path).read_bytes())).decode() + "\n").encode(), 0o600)


def verify(input_path: str, signature_path: str, public_path: str) -> bool:
    try:
        public = serialization.load_pem_public_key(Path(public_path).read_bytes())
        if not isinstance(public, Ed25519PublicKey):
            return False
        signature_text = Path(signature_path).read_text(encoding="utf-8").strip()
        signature = base64.b64decode(signature_text, validate=True)
        public.verify(signature, Path(input_path).read_bytes())
        return True
    except (InvalidSignature, ValueError, TypeError, OSError, binascii.Error):
        return False
