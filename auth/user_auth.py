# auth/user_auth.py

import bcrypt
import json
import os

USER_DB_FILE = "users.json"

# Load user database from JSON
def load_users():
    if not os.path.exists(USER_DB_FILE):
        return {}
    with open(USER_DB_FILE, "r") as f:
        return json.load(f)

# Save updated user DB
def save_users(users):
    with open(USER_DB_FILE, "w") as f:
        json.dump(users, f)

def register_user(username, password, phone):
    users = load_users()
    if username in users:
        return False, "User already exists."

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users[username] = {
        "password": hashed,
        "phone": phone
    }
    save_users(users)
    return True, "✅ Registration successful."

def verify_user(username, password):
    users = load_users()
    if username not in users:
        return False, "User not found.", None

    stored_hash = users[username]["password"].encode()
    if bcrypt.checkpw(password.encode(), stored_hash):
        phone = users[username]["phone"]
        return True, "Password verified.", phone
    else:
        return False, "Incorrect password.", None
