# auth/user_auth.py

import bcrypt

# Mock user database — upgrade later to SQLite or JSON
user_db = {}


def register_user(username, password):
    if username in user_db:
        return False, "User already exists."

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    user_db[username] = hashed
    return True, "Registration successful."


def verify_user(username, password):
    if username not in user_db:
        return False, "User not found."

    stored_hash = user_db[username]
    if bcrypt.checkpw(password.encode(), stored_hash):
        return True, "Password verified."
    else:
        return False, "Incorrect password."
