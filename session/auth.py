from django.contrib.auth.decorators import user_passes_test

from session.models import MyUser
from Crypto.Hash import SHA256
import pickle
import base64
from django.contrib.auth import login, REDIRECT_FIELD_NAME


def check_signature(data, pk, signature):
    data_hash = SHA256.new(data.encode('utf-8')).digest()
    public_key = pickle.loads(base64.b64decode(pk))
    decoded_signature = int(base64.b64decode(signature))
    if public_key.verify(data_hash, (decoded_signature, None)):
        return True
    return None


class SessionBackend(object):

    @staticmethod
    def authenticate(request, pk=None, signature=None, old_jc=None, new_jc=None):
        session_id = request.session.session_key
        try:
            if check_signature(session_id, pk, signature):
                user = MyUser.objects.get(pk=pk)
                if user.jump_code == old_jc:
                    user.jump_code = new_jc
                    user.save()
                    return user
                else:
                    user.is_compromised = True
                    user.save()
                    return None
            return None
        except MyUser.DoesNotExist:
            return None

    @staticmethod
    def session_login(request, user):
        if not user.is_compromised:
            login(request, user)

    @staticmethod
    def get_user(user_id):
        try:
            return MyUser.objects.get(pk=user_id)
        except MyUser.DoesNotExist:
            return None


def login_required(function=None, redirect_field_name=REDIRECT_FIELD_NAME, login_url=None):
    """
    Decorator for views that checks that the user is logged in, redirecting
    to the log-in page if necessary.
    """
    actual_decorator = user_passes_test(
        lambda u: u.is_authenticated and not u.is_compromised,
        login_url=login_url,
        redirect_field_name=redirect_field_name
    )
    if function:
        return actual_decorator(function)
    return actual_decorator
