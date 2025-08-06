# crypto/encryption.py

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqcrypto.kem.ml_kem_512 import generate_keypair,encrypt, decrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# Generate a secure 32-byte AES key (for AES-256)
#New update no os.urandom(32) is used for aes key
def generate_kyber_key():
    public_key,private_key = generate_keypair()
    return base64.b64encode(public_key).decode(),base64.b64encode(private_key).decode()
    #return base64.b64encode(os.urandom(32)).decode()


# Encrypt the message
def encrypt_message(plaintext, key):
    aesgcm = AESGCM(key)

    nonce = os.urandom(12)  # 96-bit recommended nonce for AES-GCM
    plaintext_bytes = plaintext.encode()

    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)

    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode()
    }
    del key
    del ss



# Decrypt the message
#again logic has been updated!! no static aes key used
def derive_aes_key(shared_secret: bytes) -> bytes:
    """
    Derive an AES-GCM key from the Kyber shared secret using HKDF.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'secure-messaging-aes-key',
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)
def decrypt_message(encrypted_data, kyber_pvt_key):
    ss= decrypt(kyber_pvt_key, base64.b64decode(encrypted_data['kyber_cipher_text']))
    aes_key= derive_aes_key(ss)
    aesgcm = AESGCM(aes_key)

    nonce = base64.b64decode(encrypted_data["nonce"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])

    try:
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext_bytes.decode()
    except Exception as e:
        return f"[Decryption failed: {e}]"