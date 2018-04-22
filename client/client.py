import sys
import select
import requests
from random import SystemRandom
from sys import maxsize
import os.path
from crypto.helpers import *

HOST = 'http://127.0.0.1:8000'
#HOST = 'https://s3bd4f4ova.execute-api.eu-west-1.amazonaws.com/dev'

def register(email):
    url = HOST + '/session/register'
    client = requests.session()
    if os.path.exists('jumpcode'):
        with open('jumpcode', 'r') as jumpcode:
            jc = jumpcode.read()
    else:
        with open('jumpcode', 'w') as jumpcode:
            jc = str(SystemRandom().randint(1, maxsize))
            jumpcode.write(jc)
    generate_keys()
    key, pk = get_keys()

    signature = b64(sign(jc.encode(), key))
    register_data = dict(email=email,
                         pk=pack(pk),
                         jc=jc,
                         signature=signature,
                         next='/session')
    r = client.post(url, data=register_data, headers=dict(Referer=url))
    print("Registration:", r.reason)


def heartbeat():
    url = HOST + '/session/heartbeat'
    client = requests.session()
    # import pdb; pdb.set_trace()
    with open('jumpcode', 'r+') as jumpcode:
        old_jumpcode = jumpcode.read()
        new_jumpcode = str(SystemRandom().randint(1, maxsize))
        key, pk = get_keys()
        signature = b64(sign(new_jumpcode.encode(), key))
        login_data = dict(pk_hash=hash(pack(pk)),
                          old_jc=old_jumpcode,
                          new_jc=new_jumpcode,
                          signature=signature,
                          next='/session')
        r = client.post(url, data=login_data, headers=dict(Referer=url))
        if r.status_code == 200:
            jumpcode.seek(0)
            jumpcode.write(new_jumpcode)
            jumpcode.truncate()
        else:
            print('Heartbeat:', r.reason)


def login(session_id):
    url = HOST + '/session/login'
    client = requests.session()
    with open('jumpcode', 'r+') as jumpcode:
        old_jumpcode = jumpcode.read()
        new_jumpcode = str(SystemRandom().randint(1, maxsize))
        key, pk = get_keys()
        signature = b64(sign(session_id.encode(), key))
        h = SHA256.new()
        h.update(pack(pk).encode("UTF-8"))
        pk_hash = b64(h.digest())
        login_data = dict(session_id=session_id,
                          pk_hash=pk_hash,
                          old_jc=old_jumpcode,
                          new_jc=new_jumpcode,
                          signature=signature,
                          next='/session/check'
                          )
        r = client.post(url, data=login_data, headers=dict(Referer=url))
        if r.status_code == 200:
            jumpcode.seek(0)
            jumpcode.write(new_jumpcode)
            jumpcode.truncate()
        print("Login:", r.reason)


if __name__ == "__main__":
    print("Enter email address.")
    register(sys.stdin.readline().strip())
    print("Enter session id to log in.")
    while True:
        i, o, e = select.select([sys.stdin], [], [], 10)
        if i:
            login(sys.stdin.readline().strip())
        else:
            pass
#            heartbeat()