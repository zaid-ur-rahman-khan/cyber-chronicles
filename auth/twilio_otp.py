# auth/twilio_otp.py

from twilio.rest import Client
import os
from dotenv import load_dotenv
import pyotp
from auth.user_auth import load_users  # to fetch user secret

load_dotenv()

ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
FROM_NUMBER = os.getenv("TWILIO_PHONE")

client = Client(ACCOUNT_SID, AUTH_TOKEN)

# Send OTP via SMS
def send_otp(username):
    users = load_users()
    if username not in users:
        print("❌ User not found.")
        return False

    secret = users[username]["secret"]
    phone = users[username]["phone"]
    totp = pyotp.TOTP(secret,interval=300)
    otp = totp.now()

    message = client.messages.create(
        body=f"🔐 Your login OTP is: {otp}",
        from_=FROM_NUMBER,
        to=phone
    )

    print("📤 OTP sent via SMS.")
    return True

# Verify entered OTP
def verify_otp(username, entered_otp):
    users = load_users()
    if username not in users:
        return False

    secret = users[username]["secret"]
    totp = pyotp.TOTP(secret,interval=300)
    return totp.verify(entered_otp,valid_window=0)
