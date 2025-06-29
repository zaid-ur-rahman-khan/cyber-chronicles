# cli/main.py
from messaging.messenger import send_message, view_inbox
from auth.user_auth import register_user, verify_user
from auth.twilio_otp import send_otp, verify_otp
def secure_messaging_menu(current_user):
    while True:
        print("\n🔐 Secure Messaging Menu:")
        print("1. Send a message")
        print("2. View inbox")
        print("3. Logout")
        opt = input("Choose an option: ")

        if opt == "1":
            receiver = input("Send to (username): ")
            msg = input("Enter your message: ")
            status, feedback = send_message(current_user, receiver, msg)
            print(feedback)

        elif opt == "2":
            view_inbox(current_user)

        elif opt == "3":
            print("👋 Logging out...")
            break

        else:
            print("❌ Invalid option. Try again.")

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
        valid, message, _ = verify_user(username, password)
        if not valid:
            print("❌", message)
            return

        print("✅ Password correct. Sending OTP...")
        if not send_otp(username):
            print("❌ Could not send OTP.")
            return

        otp_input = input("Enter the OTP sent to your phone: ")
        if verify_otp(username, otp_input):
            print(f"🎉 LOGIN SUCCESSFUL! Welcome,{username} .")
            secure_messaging_menu(username)
        else:
            print("❌ OTP verification failed.")
    else:
        print("❌ Invalid option. Try 1 or 2.")

if __name__ == "__main__":
    main()
