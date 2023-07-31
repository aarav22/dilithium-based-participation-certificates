import base64
import hashlib

from dilithium.dilithium import Dilithium2



# read the secret key from a file
with open('secret_key.pem', 'rb') as f:
    sk = f.read()

# read msg from a file
with open('msg.txt', 'r') as f:
    msg = f.read()


# decode the secret key from base64
sk = base64.b64decode(sk)
# msg = bytes(msg, 'utf-8')

import pyexiv2

with pyexiv2.Image('./demo-cert.png') as img:
    data = img.read_xmp()
    # sign all the data except the signature 'Xmp.dc.signature'
    tbs_data = {k: v for k, v in data.items() if k != 'Xmp.dc.signature'}
    tbs_data_hash = hashlib.sha256(str(tbs_data).encode('utf-8')).digest()
    sig = Dilithium2.sign(sk, tbs_data_hash)
    dict1 = {'Xmp.dc.signature': base64.b64encode(sig).decode('utf-8')}
    img.modify_xmp(dict1)
    data = img.read_xmp()
    print(data)



# # save the signature to a file
# with open('signature.pem', 'wb') as f:
#     f.write(base64.b64encode(sig))
