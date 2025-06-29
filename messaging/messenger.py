# messaging/messenger.py

import json
import os
from datetime import datetime
from auth.user_auth import load_users
from crypto.encryption import encrypt_message, decrypt_message

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
def send_message(sender, receiver, plaintext):
    users = load_users()
    if receiver not in users:
        return False, "❌ Receiver not found."

    receiver_key = users[receiver]["aes_key"]
    encrypted_data = encrypt_message(plaintext, receiver_key)

    new_message = {
        "sender": sender,
        "receiver": receiver,
        "ciphertext": encrypted_data["ciphertext"],
        "nonce": encrypted_data["nonce"],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    messages = load_messages()
    messages.append(new_message)
    save_messages(messages)

    return True, "✅ Message sent securely."

# View messages sent TO the logged-in user
def view_inbox(username):
    users = load_users()
    user_key = users[username]["aes_key"]

    messages = load_messages()
    inbox = [m for m in messages if m["receiver"] == username]

    if not inbox:
        print("📭 Your inbox is empty.")
        return

    print(f"\n📥 INBOX for {username}:\n" + "-"*30)
    for msg in inbox:
        decrypted = decrypt_message({
            "ciphertext": msg["ciphertext"],
            "nonce": msg["nonce"]
        }, user_key)
        print(f"🕒 {msg['timestamp']} | 🧑 From: {msg['sender']}\n📨 {decrypted}\n")
