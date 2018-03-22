import sys
import requests
import pickle
import base64
from Crypto.Hash import SHA256
from sys import maxsize
from random import SystemRandom


def main(argv):
    url = 'http://127.0.0.1:8000/session/login'

    client = requests.session()

    # Retrieve the CSRF token first
    client.get(url)  # sets cookie
    if 'csrftoken' in client.cookies:
        # Django 1.6 and up
        csrftoken = client.cookies['csrftoken']
    else:
        # older versions
        csrftoken = client.cookies['csrf']
    with open('jumpcode', 'r') as jumpcode:
        jc = jumpcode.read()
    with open('keys/key', 'rb') as key_file:
        session_id = argv[0]
        key = pickle.load(key_file)
        pk = base64.b64encode(pickle.dumps(key.publickey()))
        session_hash = SHA256.new(session_id.encode('utf-8')).digest()
        # TODO this is raw RSA sign, replace with PKCS1_PSS
        # TODO add timestamp, check on server side
        signature = base64.b64encode(str(key.sign(session_hash, '')[0]).encode('utf-8'))

        login_data = dict(session_id=session_id,
                          pk=pk,
                          jc=jc,
                          signature=signature,
                          csrfmiddlewaretoken=csrftoken,
                          next='/session/check'
                          )
        r = client.post(url, data=login_data, headers=dict(Referer=url))
        print(r.status_code, r.reason)


if __name__ == "__main__":
    main(sys.argv[1:])
