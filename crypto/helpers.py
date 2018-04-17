import base64
import pickle
from itertools import permutations
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA

from os import path, makedirs

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
    if type(string) == int:
        string = str(int)
    if type(string) == str:
        string = string.encode()
    h.update(string)
    signer = PKCS1_PSS.new(key)
    return signer.sign(h)


def check_signature(string, signature, key):
    if type(key) == bytearray or type(key) == unicode or type(key) == buffer:
        key = unpack(key)
    h = SHA.new()
    if type(string) == int:
        string = str(string)
    if type(string) == str:
        string = string.encode()
    h.update(string)
    verifier = PKCS1_PSS.new(key)
    if type(signature) == unicode:
        signature = b64decode(signature)
    if type(signature) == int:
        signature = str(signature)
    return verifier.verify(h, signature)


def generate_key_on_path(directory='.', filename="key"):
    private_path = path.join(directory, filename)
    public_path = path.join(directory, filename + '.pub')
    if not path.exists(directory):
        makedirs(directory)
    if not path.exists(private_path) or not path.exists(public_path):

        with open(private_path, 'wb') as key_file:
            key = RSA.generate(KEY_SIZE)
            key_file.write(key.exportKey('PEM'))
            with open(public_path, 'wb') as key_pub_file:
                key_pub_file.write(key.publickey().exportKey('PEM'))
            print("Keys were generated.")
            return key.publickey()
    else:
        with open(public_path, 'rb') as key_pub_file:
            pk = RSA.importKey(key_pub_file.read())
            return pk


def generate_keys():
    generate_key_on_path()


def generate_foreign_keys():
    keys = []
    for i in range(5):
        keys.append(generate_key_on_path('foreign_keys', str(i) + 'key'))
    return keys


def generate_recovery_data(keys_arr, secret):
    length = len(keys_arr)
    encrypted_keys = []
    for triplets in permutations(range(length), 3):
        encrypted_keys.append(encrypt(
                                encrypt(
                                    encrypt(secret, keys_arr[triplets[0]]),
                                    keys_arr[triplets[1]]),
                                keys_arr[triplets[2]])
                              )
    return encrypted_keys


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


def pack(obj):
    return b64(obj.exportKey("PEM"))


def unpack(b64message):
    return RSA.importKey(b64decode(b64message))
