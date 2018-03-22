import requests
import pickle
import base64
from random import SystemRandom
from sys import maxsize

from Crypto.Hash import SHA256


def main():
    URL = 'http://127.0.0.1:8000/session/register'

    client = requests.session()

    # Retrieve the CSRF token first
    client.get(URL)  # sets cookie
    if 'csrftoken' in client.cookies:
        # Django 1.6 and up
        csrftoken = client.cookies['csrftoken']
    else:
        # older versions
        csrftoken = client.cookies['csrf']
    with open('jumpcode', 'w') as jumpcode:
        jc_int = SystemRandom().randint(1, maxsize)
        jumpcode.write(str(jc_int))
    with open('keys/key', 'rb') as key_file:
        key = pickle.load(key_file)
        pk = base64.b64encode(pickle.dumps(key.publickey()))
        jc_hash = SHA256.new(str(jc_int).encode('utf-8')).digest()
        # TODO this is raw RSA sign, replace with PKCS1_PSS
        # TODO add timestamp, check on server side
        signature = base64.b64encode(str(key.sign(jc_hash, '')[0]).encode('utf-8'))

        login_data = dict(pk=pk,
                          jc=str(jc_int),
                          signature=signature,
                          csrfmiddlewaretoken=csrftoken,
                          next='/session')
        r = client.post(URL, data=login_data, headers=dict(Referer=URL))
        print(r.status_code, r.reason)


if __name__ == "__main__":
    main()
