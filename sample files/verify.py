import base64

from dilithium.dilithium import Dilithium2

# read signature from a file
with open('signature.pem', 'rb') as f:
    sig = f.read()

# read msg from a file
with open('msg.txt', 'r') as f:
    msg = f.read()


# decode the signature from base64
sig = base64.b64decode(sig)

msg = bytes(msg, 'utf-8')

# read the public key from a file
with open('public_key.pem', 'rb') as f:
    pk = f.read()

# decode the public key from base64
pk = base64.b64decode(pk)


# assert Dilithium2.verify(pk, msg, sig)

# image based signature verification
import pyexiv2
import base64
import hashlib

with open('secret_key.pem', 'rb') as f:
    sk = f.read()

sk = base64.b64decode(sk)

with pyexiv2.Image('./demo-cert.png') as img:
    data = img.read_xmp()
    tbs_data = {k: v for k, v in data.items() if k != 'Xmp.dc.signature'}
    tbs_data_hash = hashlib.sha256(str(tbs_data).encode('utf-8')).digest()
    sig = data['Xmp.dc.signature'].encode('utf-8')
    new_sig = Dilithium2.sign(sk, tbs_data_hash)

assert Dilithium2.verify(pk, tbs_data_hash, base64.b64decode(sig))
