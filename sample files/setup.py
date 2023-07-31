import base64

from dilithium.dilithium import Dilithium2

pk, sk = Dilithium2.keygen()

# save the public key to a file
with open('public_key.pem', 'wb') as f:
    f.write(base64.b64encode(pk))

# save the secret key to a file
with open('secret_key.pem', 'wb') as f:
    f.write(base64.b64encode(sk))
