import os
import random
from dotenv import load_dotenv
from twilio.rest import Client

load_dotenv()


ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
TWILIO_PHONE = os.getenv('TWILIO_PHONE')

client = Client(ACCOUNT_SID, AUTH_TOKEN)

otp_store={}
def send_otp(phone_number):
    otp=str(random.randint(10000,99999))
    message=f"Your OTP for grand cyber chronicles is {otp}"

    try:
        client.messages.create(body=message,from_=TWILIO_PHONE,to=phone_number)
        otp_store[phone_number]=otp
        print(f"OTP sent to {phone_number}")
    except Exception as e:
        print(f"failed to send OTP for {phone_number}\n{e}")
def verify_otp(phone_number,user_input_otp):
    real_otp=otp_store.get(phone_number)
    if real_otp and user_input_otp==real_otp:
        print(f"OTP verified for {phone_number} successfully!")
        return True
    else:
        print(f"OTP verification failed for {phone_number} invalid otp!")
        return False