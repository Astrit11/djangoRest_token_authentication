import os
from django.core.exceptions import ImproperlyConfigured

def get_env(env_variable, defaultValue):
    try:
        return os.environ.get(env_variable, defaultValue)
    except KeyError:
        error_msg = f"Set the {env_variable} environment variable"
        raise ImproperlyConfigured(error_msg)