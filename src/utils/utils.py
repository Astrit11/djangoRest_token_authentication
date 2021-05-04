import os
from django.core.exceptions import ImproperlyConfigured
from django.core.mail import EmailMessage

def get_env(env_variable, defaultValue):
    try:
        return os.environ.get(env_variable, defaultValue)
    except KeyError:
        error_msg = f"Set the {env_variable} environment variable"
        raise ImproperlyConfigured(error_msg)


def send_email(data):
    # user.email_verification_token = PasswordResetTokenGenerator().make_token(user)
    # link = 'https://www.anoriagroup.com/user/profile/' + user.email_verification_token
    # email_body = 'Use this ' + link + ' to activate your account'
    # email_data = {'email_body':email_body,'to_email':user.email,'email_subject':'Account activation'}
    email = EmailMessage(subject= data['email_subject'],body=data['email_body'], from_email="", to=[data['to_email']])
    email.send()