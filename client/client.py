import sys
import select
import requests
import pickle
import base64
from random import SystemRandom
from sys import maxsize
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.PublicKey import RSA
import os.path


def generate_keys():
    with open('key', 'wb') as key_file:
        random_generator = Random.new().read
        key = RSA.generate(1024, random_generator)
        pickle.dump(key, key_file)
        with open('key.pub', 'wb') as key_pub_file:
            pickle.dump(key.publickey(), key_pub_file)
        print("Keys were generated.")


def get_keys():
    with open('key', 'rb') as key_file:
        with open('key.pub', 'rb') as key_pub_file:
            key = pickle.load(key_file)
            pk = base64.b64encode(key_pub_file.read())
            return key, pk


def register():
    url = 'http://127.0.0.1:8000/session/register'
    client = requests.session()
    client.get(url)  # sets cookie
    csrftoken = client.cookies['csrftoken']
    if os.path.exists('jumpcode'):
        with open('jumpcode', 'r') as jumpcode:
            jc = jumpcode.read()
    else:
        with open('jumpcode', 'w') as jumpcode:
            jc = str(SystemRandom().randint(1, maxsize))
            jumpcode.write(jc)
    if not os.path.exists('key') or not os.path.exists('key.pub'):
        generate_keys()
    key, pk = get_keys()
    jc_hash = SHA256.new(jc.encode('utf-8')).digest()
    # TODO this is raw RSA sign, replace with PKCS1_PSS
    # TODO add timestamp, check on server side
    signature = base64.b64encode(str(key.sign(jc_hash, '')[0]).encode('utf-8'))

    register_data = dict(pk=pk,
                         jc=jc,
                         signature=signature,
                         csrfmiddlewaretoken=csrftoken,
                         next='/session')
    r = client.post(url, data=register_data, headers=dict(Referer=url))
    print("Registration:", r.reason)


def heartbeat():
    url = 'http://127.0.0.1:8000/session/heartbeat'
    client = requests.session()
    client.get(url)  # sets cookie
    csrftoken = client.cookies['csrftoken']
    with open('jumpcode', 'r+') as jumpcode:
        old_jumpcode = jumpcode.read()
        new_jumpcode = str(SystemRandom().randint(1, maxsize))
        key, pk = get_keys()
        new_jc_hash = SHA256.new(new_jumpcode.encode('utf-8')).digest()
        # TODO this is raw RSA sign, replace with PKCS1_PSS
        # TODO add timestamp, check on server side
        signature = base64.b64encode(str(key.sign(new_jc_hash, '')[0]).encode('utf-8'))
        login_data = dict(pk=pk,
                          old_jc=old_jumpcode,
                          new_jc=new_jumpcode,
                          signature=signature,
                          csrfmiddlewaretoken=csrftoken,
                          next='/session')
        r = client.post(url, data=login_data, headers=dict(Referer=url))
        #print(r.status_code, r.reason)
        if r.status_code == 200:
            jumpcode.seek(0)
            jumpcode.write(new_jumpcode)
            jumpcode.truncate()
        else:
            print('Heartbeat:', r.reason)


def login(session_id):
    url = 'http://127.0.0.1:8000/session/login'
    client = requests.session()
    client.get(url)  # sets cookie
    csrftoken = client.cookies['csrftoken']
    with open('jumpcode', 'r') as jumpcode:
        jc = jumpcode.read()
        key, pk = get_keys()
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
        print("Login:", r.reason)


if __name__ == "__main__":
    register()
    print("Enter session id to log in.")
    while True:
        i, o, e = select.select([sys.stdin], [], [], 10)
        if i:
            login(sys.stdin.readline().strip())
        else:
            heartbeat()