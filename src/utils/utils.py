import os
from django.core.exceptions import ImproperlyConfigured
from django.core.mail import EmailMessage


def get_env(env_variable, defaultValue):
    try:
        return os.environ.get(env_variable, defaultValue)
    except KeyError:
        error_msg = f"Set the {env_variable} environment variable"
        raise ImproperlyConfigured(error_msg)


def confirm_email(token,user):
    link = os.environ.get('','')
    subject = 'Thank you for registering to our site'
    email_body = 'Use this link ' +link+token+ ' to activate your account'
    email = EmailMessage(subject= subject,body=email_body,from_email=os.environ.get('EMAIL_HOST_USER',''), to=[user.email])
    email.send()


def forgot_password(token,user):
    link = os.environ.get('','')
    subject = 'Password reset link'
    email_body = 'Use this link ' +link+token+ ' to change your password'
    email = EmailMessage(subject= subject,body=email_body,from_email=os.environ.get('EMAIL_HOST_USER',''), to=[user.email])
    email.send()
