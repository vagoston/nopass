from crypto.helpers import *


def batch_recrypt(arr, old_key, n_key):
    result = []
    for secret in arr:
        try:
            result.append(encrypt(decrypt(secret, old_key), n_key))
        except ValueError:
            pass
    return result


# generate new key on new client
new_key = RSA.generate(KEY_SIZE)
new_pk = new_key.publickey()

# register(new_key), start recovery state

# submit first foreign key

# download recovery_data to first foreign client with new public key
with open('recovery_data', 'r+b') as recovery_file:
    recovery_data = recovery_file.read()
    with open('foreign_keys/0key', 'rb') as first_key:
        first_priv_key = RSA.importKey(first_key.read())
        recovery_keys = pickle.loads(recovery_data)
        recovery_keys = batch_recrypt(recovery_keys, first_priv_key, new_pk)
        # upload first layer to server
        recovery_file.seek(0)
        recovery_file.write(pickle.dumps(recovery_keys))
        recovery_file.truncate()

# download partially recovered data to new client, prepare for next client
with open('recovery_data', 'r+b') as recovery_file:
    recovery_data = recovery_file.read()
    with open('foreign_keys/2key.pub', 'rb') as second_pk_file:
        pk_2 = RSA.importKey(second_pk_file.read())
        recovery_keys = pickle.loads(recovery_data)
        recovery_keys = batch_recrypt(recovery_keys, new_key, pk_2)
        recovery_file.seek(0)
        recovery_file.write(pickle.dumps(recovery_keys))
        recovery_file.truncate()

# download recovery_data to second foreign client with new public key
with open('recovery_data', 'r+b') as recovery_file:
    recovery_data = recovery_file.read()
    with open('foreign_keys/2key', 'rb') as first_key:
        second_priv_key = RSA.importKey(first_key.read())
        recovery_keys = pickle.loads(recovery_data)
        recovery_keys = [decrypt(secret, second_priv_key) for secret in recovery_keys]
        recovery_keys = batch_recrypt(recovery_keys, second_priv_key, new_pk)
        # upload second layer to server
        recovery_file.seek(0)
        recovery_file.write(pickle.dumps(recovery_keys))
        recovery_file.truncate()

# download partially recovered data to new client, prepare for next client
with open('recovery_data', 'r+b') as recovery_file:
    recovery_data = recovery_file.read()
    with open('foreign_keys/4key.pub', 'rb') as second_pk_file:
        pk_4 = RSA.importKey(second_pk_file.read())
        recovery_keys = pickle.loads(recovery_data)
        recovery_keys = batch_recrypt(recovery_keys, new_key, pk_4)
        recovery_file.seek(0)
        recovery_file.write(pickle.dumps(recovery_keys))
        recovery_file.truncate()

# download recovery_data to third foreign client with new public key
with open('recovery_data', 'r+b') as recovery_file:
    recovery_data = recovery_file.read()
    with open('foreign_keys/4key', 'rb') as first_key:
        # This is the most vulnerable point. A foreign client can access both the old_key and the recovery token.
        # The owner of this client should be the most trusted person.
        third_priv_key = RSA.importKey(first_key.read())
        recovery_keys = pickle.loads(recovery_data)
        recovery_keys = [decrypt(secret, third_priv_key) for secret in recovery_keys]
        recovery_keys = batch_recrypt(recovery_keys, third_priv_key, new_pk)
        # upload third layer to server. This is actually all information needed for recovery, encrypted
        # with the new key.
        recovery_file.seek(0)
        recovery_file.write(pickle.dumps(recovery_keys))
        recovery_file.truncate()

# download recovered data to new client, restore data
with open('recovery_data', 'r+b') as recovery_file:
    recovery_data = recovery_file.read()
    recovery_keys = pickle.loads(recovery_data)
    recovery_keys = [decrypt(secret, new_key) for secret in recovery_keys]
    recovered_key, token = pickle.loads(recovery_keys[0])

# check if recovery was successful
with open('key', 'rb') as old_key_file:
    original_key = RSA.importKey(old_key_file.read())
    if original_key == recovered_key:
        print("key restored successfully")
    else:
        print("something went wrong")

with open('verification_key', 'rb') as verification_key_file:
    verification_key = RSA.importKey(verification_key_file.read())
    if check_signature(pickle.dumps(original_key.publickey()), token, verification_key):
        print("Token accepted.")
    else:
        print("Token rejected.")
