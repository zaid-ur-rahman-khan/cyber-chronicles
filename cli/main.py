from auth.twilio_otp import send_otp, verify_otp
if __name__ == '__main__':
    user_phone = input('Enter your phone number: ')
    send_otp(user_phone)

    otp_input = input('Enter your OTP received: ')
    verify_otp(user_phone, otp_input)
