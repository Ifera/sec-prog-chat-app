import base64
import hashlib
import json
import os
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def base64url_decode(data: str) -> bytes:
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(data)


def generate_rsa_keypair() -> Tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PrivateFormat.PKCS8,
                                            encryption_algorithm=serialization.NoEncryption())
    public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64url_encode(private_pem), base64url_encode(public_pem)


def load_private_key(private_key_b64: str) -> rsa.RSAPrivateKey:
    private_pem = base64url_decode(private_key_b64)
    return serialization.load_pem_private_key(private_pem, password=None, backend=default_backend())


def load_public_key(public_key_b64: str) -> rsa.RSAPublicKey:
    public_pem = base64url_decode(public_key_b64)
    return serialization.load_pem_public_key(public_pem, backend=default_backend())


def rsa_encrypt(public_key: rsa.RSAPublicKey, plaintext: bytes) -> str:
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64url_encode(ciphertext)


def rsa_decrypt(private_key: rsa.RSAPrivateKey, ciphertext_b64: str) -> bytes:
    ciphertext = base64url_decode(ciphertext_b64)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return plaintext


def rsa_sign(private_key: rsa.RSAPrivateKey, data: bytes) -> str:
    signature = private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return base64url_encode(signature)


def rsa_verify(public_key: rsa.RSAPublicKey, data: bytes, signature_b64: str) -> bool:
    signature = base64url_decode(signature_b64)
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except:
        return False


def canonicalize_payload(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(',', ':'))


def compute_content_sig(private_key: rsa.RSAPrivateKey, ciphertext: str, from_id: str, to: str, ts: int) -> str:
    data = f"{ciphertext}{from_id}{to}{ts}"
    return rsa_sign(private_key, data.encode('utf-8'))


def verify_content_sig(public_key: rsa.RSAPublicKey, ciphertext: str, from_id: str, to: str, ts: int,
                       sig_b64: str) -> bool:
    data = f"{ciphertext}{from_id}{to}{ts}"
    return rsa_verify(public_key, data.encode('utf-8'), sig_b64)


def compute_public_content_sig(private_key: rsa.RSAPrivateKey, ciphertext: str, from_id: str, ts: int) -> str:
    data = f"{ciphertext}{from_id}{ts}"
    return rsa_sign(private_key, data.encode('utf-8'))


def verify_public_content_sig(public_key: rsa.RSAPublicKey, ciphertext: str, from_id: str, ts: int,
                              sig_b64: str) -> bool:
    data = f"{ciphertext}{from_id}{ts}"
    return rsa_verify(public_key, data.encode('utf-8'), sig_b64)


def compute_transport_sig(private_key: rsa.RSAPrivateKey, payload: dict) -> str:
    canonical = canonicalize_payload(payload)
    return rsa_sign(private_key, canonical.encode('utf-8'))


def verify_transport_sig(public_key: rsa.RSAPublicKey, payload: dict, sig_b64: str) -> bool:
    canonical = canonicalize_payload(payload)
    return rsa_verify(public_key, canonical.encode('utf-8'), sig_b64)


def generate_aes_key() -> bytes:
    return os.urandom(32)  # 256 bits


def aes_encrypt(key: bytes, plaintext: bytes) -> str:
    iv = os.urandom(16)  # AES GCM IV
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    combined = iv + encryptor.tag + ciphertext
    return base64url_encode(combined)


def aes_decrypt(key: bytes, ciphertext_b64: str) -> bytes:
    combined = base64url_decode(ciphertext_b64)
    iv = combined[:16]
    tag = combined[16:32]
    ciphertext = combined[32:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


def compute_key_share_sig(private_key: rsa.RSAPrivateKey, shares: list, creator_pub: str) -> str:
    canonical_shares = json.dumps(shares, sort_keys=True, separators=(',', ':'))
    data = canonical_shares + creator_pub
    return rsa_sign(private_key, data.encode('utf-8'))


def get_fixed_group_key() -> bytes:
    return hashlib.sha256(b"public_channel_fixed_key_v1").digest()[:32]
