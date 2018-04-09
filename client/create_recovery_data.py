from crypto.helpers import *

key, pk = get_keys()
foreign_keys = generate_foreign_keys()
verification_key = RSA.generate(KEY_SIZE)
recovery_token = sign(pickle.dumps(pk), verification_key)
recovery_data = generate_recovery_data(foreign_keys, pickle.dumps((key, recovery_token)))

# upload recovery_data
with open('recovery_data', 'wb') as recovery_file:
    recovery_file.write(pickle.dumps(recovery_data))
# upload verification_key.puplickey()
with open('verification_key', 'wb') as verification_key_file:
    verification_key_file.write(verification_key.publickey().exportKey('PEM'))
# verification key was used only for generating recovery token. Private key should never been used again.
verification_key = None
