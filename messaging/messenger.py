# messaging/messenger.py

import json
import os
import base64
from datetime import datetime
from auth.user_auth import load_users
from crypto.encryption import encrypt_message, decrypt_message
from pqcrypto.kem.ml_kem_512 import encrypt, decrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MSG_DB = os.path.join(os.path.dirname(__file__), "messages.json")

# Load all messages
def load_messages():
    if not os.path.exists(MSG_DB):
        return []
    with open(MSG_DB, "r") as f:
        return json.load(f)

# Save all messages
def save_messages(messages):
    with open(MSG_DB, "w") as f:
        json.dump(messages, f, indent=4)

# Send a message (encrypt + store)
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
def send_message(sender, receiver, plaintext):
    users = load_users()
    if receiver not in users:
        return False, "❌ Receiver not found."
#here receiver_key is actually kyber public key
    receiver_key = users[receiver]["pub_key"]
    receiver_public_key = base64.b64decode(receiver_key)
    kyber_cipher_text, ss = encrypt(receiver_public_key)
    aes_key = derive_aes_key(ss)
    stored_kyber_cipher_text = base64.b64encode(kyber_cipher_text).decode()
    #retrieve the base64 encoded pub key from here and then decode it first then use it to get ct and ss.
    encrypted_data = encrypt_message(plaintext, aes_key)

    new_message = {
        "sender": sender,
        "receiver": receiver,
        "ciphertext": encrypted_data["ciphertext"],
        "nonce": encrypted_data["nonce"],
        "kyber_cipher_text": stored_kyber_cipher_text,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    messages = load_messages()
    messages.append(new_message)
    save_messages(messages)

    return True, "✅ Message encrypted and sent securely."

# View messages sent TO the logged-in user
def view_inbox(username):
    users = load_users()
    #logic has been changed here an aes key is generated using ss from kyber at run time (no stored aes key is used)
    #here the user_key is the kyber private key
    user_key = users[username]["pvt_key"]
    kyber_pvt_key = base64.b64decode(user_key)


    messages = load_messages()
    inbox = [m for m in messages if m["receiver"] == username]

    if not inbox:
        print("📭 Your inbox is empty.")
        return

    print(f"\n📥 INBOX for {username}:\n" + "-"*30)
    for msg in inbox:
        decrypted = decrypt_message({
            "ciphertext": msg["ciphertext"],
            "nonce": msg["nonce"], "kyber_cipher_text": msg["kyber_cipher_text"],
        }, kyber_pvt_key)
        print(f"🕒 {msg['timestamp']} | 🧑 From: {msg['sender']}\n📨 {decrypted}\n")