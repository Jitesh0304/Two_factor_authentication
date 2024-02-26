from django.core.mail import send_mail
import random
from django.conf import settings
from .models import User
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings
import qrcode
from django_otp import devices_for_user
from django_otp.plugins.otp_totp.models import TOTPDevice
import os
import qrcode.image.pil
import pyotp
from base64 import b32encode
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile






current_dir = os.getcwd()
if os.path.exists(os.path.join(current_dir, "QR_folder")):
    pass
else:
    os.makedirs(os.path.join(current_dir, "QR_folder"), exist_ok=True)
qr_dir = os.path.join(current_dir, "QR_folder")



    ## send the verification otp to the user account
def sent_otp_by_email(email):
    subject = "Your account verification email.."
    # otp = random.randint(100000,999999)
    otp = 123456
    message = f"Your OTP for account verification is {otp}"
    email_from = settings.EMAIL_HOST_USER
        ## send the required dat and parameters in the send_email function
    # send_mail(subject, message, email_from, [email])
    user_obj = User.objects.get(email=email)
        ## save the otp in the user table for verification
    user_obj.otp = otp
    user_obj.save()



## send the forgot password otp
def reset_pass_otp_email(email):
    subject = "Your account verification email.."
    # otp = random.randint(100000,999999)
    otp = 987654
    message = f"Your OTP for forgot password is {otp}"
    email_from = settings.EMAIL_HOST_USER
    ## send the required dat and parameters in the send_email function
    send_mail(subject, message, email_from, [email])
    user_obj = User.objects.get(email=email)
    ## save the otp in the user table for verification
    user_obj.otp = otp
    ## make the user unverified
    user_obj.is_verified = False
    user_obj.save()



def generate_otp_qr_code(secret_key, account_name, issuer_name ="Django app", file_format='png'):
    # print(secret_key)
    # Choose the appropriate image factory based on the file format
    new_secret_key = b32encode(secret_key)
    # print(new_secret_key)
    # image_factory = qrcode.image.pil.PilImage if file_format == 'png' else qrcode.image.pil.PilImage
    totp = pyotp.TOTP(new_secret_key)

    # Format the OTP URI
    otp_uri = totp.provisioning_uri(name=account_name, issuer_name=issuer_name)

    # Choose the appropriate image factory based on the file format
    image_factory = qrcode.image.svg.SvgPathImage if file_format == 'svg' else qrcode.image.pil.PilImage


    # Generate QR code
    img = qrcode.make(otp_uri, image_factory=image_factory)
    # img = qrcode.make(secret_key, image_factory=image_factory)

    # Save the QR code as a file with the specified format
    img_path = os.path.join(qr_dir ,f'{account_name}_otp_qr.{file_format}')
    img.save(img_path)
    return img_path


def get_user_totp_device(user, confirmed=None):
    devices = devices_for_user(user, confirmed=confirmed)
    for device in devices:
        if isinstance(device, TOTPDevice):
            return device


    ## send the account activation link to the user email
# def send_activation_email(recipient_email, activation_url, host, uid, token):
def send_activation_email(recipient_email, activation_url, host):
    subject = 'Activate your Aaai tool account..'
    from_email = settings.EMAIL_HOST_USER
    to = [recipient_email]

    # Load the HTML template
    ## send the HTML design page and activation link ... and use that link and create a button in the html page
    html_content = render_to_string('account/activation_email.html', {'activation_url': activation_url})
    # html_content = render_to_string('account/activation_email.html', {'activation_url': activation_url, 'uid':uid, 'token':token})

    # Create the email body with both HTML and plain text versions
    text_content = strip_tags(html_content)
    ## send the email to the user
    email = EmailMultiAlternatives(subject, text_content, from_email, to)
    email.attach_alternative(html_content, "text/html")
    email.send()




def send_forgot_pass_email(recipient_email, forgot_verify, host):
    subject = 'Reset your Aaai tool password'
    # subject = 'Reset your password'+host
    from_email = settings.EMAIL_HOST_USER
    to = [recipient_email]
    html_content = render_to_string('account/forgot_pass.html', {'forgot_verify': forgot_verify})
    text_content = strip_tags(html_content)
    email = EmailMultiAlternatives(subject, text_content, from_email, to)
    email.attach_alternative(html_content, "text/html")
    email.send()





## save QR image in S3 bucket
# def generate_otp_qr_code(secret_key, account_name, issuer_name ="Django app", file_format='png'):
#     # print(secret_key)

#     new_secret_key = b32encode(secret_key)
#     # print(new_secret_key)

#     totp = pyotp.TOTP(new_secret_key)

#     otp_uri = totp.provisioning_uri(name=account_name, issuer_name=issuer_name)

#     image_factory = qrcode.image.svg.SvgPathImage if file_format == 'svg' else qrcode.image.pil.PilImage
#     # Generate QR code
#     img = qrcode.make(otp_uri, image_factory=image_factory)
#     # img = qrcode.make(secret_key, image_factory=image_factory)

#     img_path = os.path.join(qr_dir ,f'{account_name}_otp_qr.{file_format}')
#     img.save(img_path)
#     # file_path = default_storage.save(f'QR_folder/{account_name}_otp_qr.{file_format}', img_path)

#     with open(img_path, 'rb') as img_file:
#         content = ContentFile(img_file.read(), name=f'{account_name}_otp_qr.{file_format}')

#     # Save the file to Django's default storage
#     file_path = default_storage.save(f'QR_folder/{account_name}_otp_qr.{file_format}', content)
#     file_url = default_storage.url(file_path)
#     return file_url