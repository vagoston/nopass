from session.models import MyUser
from Crypto.Hash import SHA256
import pickle
import base64


class SessionBackend(object):

    @staticmethod
    def authenticate(request, pk=None, signature=None):
        session_id = request.session.session_key
        session_hash = SHA256.new(session_id.encode('utf-8')).digest()
        public_key = pickle.loads(base64.b64decode(pk))
        decoded_signature = int(base64.b64decode(signature))
        try:
            if public_key.verify(session_hash, (decoded_signature, None)):
                return MyUser.objects.get(pk=pk)
            return None
        except MyUser.DoesNotExist:
            return None

    @staticmethod
    def get_user(user_id):
        try:
            return MyUser.objects.get(pk=user_id)
        except MyUser.DoesNotExist:
            return None