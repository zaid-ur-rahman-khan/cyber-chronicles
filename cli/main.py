# cli/main.py

from auth.user_auth import register_user, verify_user
from auth.twilio_otp import send_otp, verify_otp

def main():
    print("\n🛡️ WELCOME TO GRAND CYBER CHRONICLES - SECURE LOGIN 🛡️")
    print("1. Register")
    print("2. Login")
    choice = input("Select option: ")

    if choice == "1":
        username = input("Enter new username: ")
        password = input("Enter new password: ")
        phone = input("Enter your phone number (with country code): ")
        status, message = register_user(username, password, phone)
        print(message)

    elif choice == "2":
        username = input("Enter username: ")
        password = input("Enter password: ")
        valid, message, phone = verify_user(username, password)
        if not valid:
            print("❌", message)
            return

        print("✅ Password correct. Sending OTP to your registered number...")
        send_otp(phone)

        otp_input = input("Enter the OTP sent to your phone: ")
        if verify_otp(otp_input):
            print("🎉 LOGIN SUCCESSFUL! Welcome, agent.")
        else:
            print("❌ OTP verification failed.")

if __name__ == "__main__":
    main()
