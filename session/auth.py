from django.contrib.auth import login, REDIRECT_FIELD_NAME
from django.contrib.auth.decorators import user_passes_test
from crypto.helpers import *
from session.models import MyUser
import logging

class SessionBackend(object):

    @staticmethod
    def authenticate(session_id, pk_hash=None, signature=None, old_jc=None, new_jc=None):
        try:
            user = MyUser.objects.get(pk=pk_hash)
            logging.debug("user found")
            if check_signature(session_id, signature, user.public_key):
                logging.debug("signature matched")
                logging.debug(str(user.jump_code) + " " + str(old_jc) + " " + str(new_jc))
                if user.jump_code == old_jc and old_jc != new_jc:
                    logging.debug("jc mathced")
                    user.jump_code = new_jc
                    user.save()
                    return user
                else:
                    user.is_compromised = True
                    user.save()
                    return None
            return None
        except MyUser.DoesNotExist:
            logging.debug("User does not exists:" + str(pk_hash))
            return None

    @staticmethod
    def session_login(request, user):
        if not user.is_compromised:
            login(request, user)
            logging.debug("successful login")
        logging.debug("compromised, not logged in")

    @staticmethod
    def get_user(pk_hash):
        try:
            return MyUser.objects.get(pk=pk_hash)
        except MyUser.DoesNotExist:
            return None


def login_required(lambda_function=None, redirect_field_name=REDIRECT_FIELD_NAME, login_url=None):
    """
    Decorator for views that checks that the user is logged in, redirecting
    to the log-in page if necessary.
    """
    actual_decorator = user_passes_test(
        lambda u: u.is_authenticated and not u.is_compromised,
        login_url=login_url,
        redirect_field_name=redirect_field_name
    )
    if lambda_function:
        return actual_decorator(lambda_function)
    return actual_decorator
