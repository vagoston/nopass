import pickle
import base64
from Crypto import Random
from Crypto.PublicKey import RSA

with open('key', 'wb') as key_file:
    random_generator = Random.new().read
    key = RSA.generate(1024, random_generator)
    pickle.dump(key, key_file)
    print(base64.b64encode(pickle.dumps(key.publickey())))

