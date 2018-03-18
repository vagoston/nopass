import pickle
from Crypto import Random
from Crypto.PublicKey import RSA

with open('key.pub', 'wb') as pub:
    with open('key', 'wb') as key_file:
        random_generator = Random.new().read
        key = RSA.generate(1024, random_generator)
        pickle.dump(key.publickey(), pub)
        pickle.dump(key, key_file)

