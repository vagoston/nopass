import base64
import pickle

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA

KEY_SIZE = 4096


def chunks(string, size):
    for i in range(0, len(string), size):
        yield string[i:i+size]


def encrypt(string, pk):
    cipher = PKCS1_OAEP.new(pk)
    cipher_text = b""
    for chunk in chunks(string, KEY_SIZE // (8 * 2)):
        cipher_text += cipher.encrypt(chunk)
    return cipher_text


def decrypt(string, key):
    cipher = PKCS1_OAEP.new(key)
    deciphered = b""
    for chunk in chunks(string, KEY_SIZE // 8):
        deciphered += cipher.decrypt(chunk)
    return deciphered


def sign(string, key):
    h = SHA.new()
    if type(string) == str:
        string = string.encode()
    h.update(string)
    signer = PKCS1_PSS.new(key)
    return signer.sign(h)


def check_signature(string, signature, key):
    key = unpack(key)
    h = SHA.new()
    if type(string) == str:
        string = string.encode()
    h.update(string)
    verifier = PKCS1_PSS.new(key)
    return verifier.verify(h, b64decode(signature))


def generate_keys():
    with open('key', 'wb') as key_file:
        key = RSA.generate(KEY_SIZE)
        key_file.write(key.exportKey('PEM'))
        with open('key.pub', 'wb') as key_pub_file:
            key_pub_file.write(key.publickey().exportKey('PEM'))
            #pickle.dump(key.publickey(), key_pub_file)
        print("Keys were generated.")


def get_keys():
    with open('key', 'rb') as key_file:
        with open('key.pub', 'rb') as key_pub_file:
            key = RSA.importKey(key_file.read())
            pk = RSA.importKey(key_pub_file.read())
            return key, pk


def b64(byte_string):
    return base64.b64encode(byte_string)


def b64decode(string):
    return base64.b64decode(string)


def pack(object):
    return b64(pickle.dumps(object))


def unpack(b64message):
    return pickle.loads(b64decode(b64message))