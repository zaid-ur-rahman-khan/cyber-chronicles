import json
import base64
import os
from pqcrypto.kem.ml_kem_512 import generate_keypair
import bcrypt
from crypto.encryption import generate_kyber_key
# Path to JSON database
USER_DB = os.path.join(os.path.dirname(__file__), "users.json")


# Load users from JSON
def load_users():
    if not os.path.exists(USER_DB):
        return {}
    with open(USER_DB, "r") as file:
        return json.load(file)


# Save users to JSON
def save_users(users):
    with open(USER_DB, "w") as file:
        json.dump(users, file, indent=4)


# Register new user
def register_user(username, password, phone):
    users = load_users()
    if username in users:
        return False, " User already exists."

    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    # pyotp secret will be added by main.py, not here
    from pyotp import random_base32
    otp_secret = random_base32()
#replaced old os.urandom(32) skeleton for aes key now using kyber to generate aes key
    pub_key,pvt_key= generate_kyber_key()
    users[username] = {
        "pvt_key": pvt_key,
        "pub_key": pub_key,
        "password": hashed_password,
        "phone": phone,
        "secret": otp_secret,
    }

    save_users(users)
    return True, " Registration successful."


# Verify login credentials
def verify_user(username, password):
    users = load_users()
    if username not in users:
        return False, " User not found.", None

    hashed_password = users[username]["password"].encode()
    if bcrypt.checkpw(password.encode(), hashed_password):
        return True, " Password verified.", users[username]
    else:
        return False, " Incorrect password.", None
