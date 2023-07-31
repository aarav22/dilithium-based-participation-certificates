import streamlit as st
import pyexiv2

import base64
import hashlib

from dilithium.dilithium import Dilithium2

# read the secret key from a file
with open('secret_key.pem', 'rb') as f:
    sk = f.read()

sk = base64.b64decode(sk)

def sign(msg: bytes, sk: bytes) -> bytes:
    with pyexiv2.ImageData(msg) as img:
        data = img.read_xmp()

        # sign all the data except the signature 'Xmp.dc.signature'
        tbs_data = {k: v for k, v in data.items() if k != 'Xmp.dc.signature'}

        tbs_data_hash = hashlib.sha256(str(tbs_data).encode('utf-8')).digest()

        sig = Dilithium2.sign(sk, tbs_data_hash)

        dict1 = {'Xmp.dc.signature': base64.b64encode(sig).decode('utf-8')}
        img.modify_xmp(dict1)

        st.write(img.read_xmp())

        st.write(tbs_data)
        st.write(tbs_data_hash.hex())

        # save image to signed-cert.png
        return img.get_bytes()


st.title('Upload the certificate')
cert = st.file_uploader('Upload the certificate', type=['png'], label_visibility='hidden')

if cert is not None:
    cert = cert.read()
    certBytes = sign(cert, sk)

    with pyexiv2.ImageData(certBytes) as img:
        st.write(img.read_xmp())
    st.write('Signed certificate')
    st.download_button('Download', certBytes, 'signed-cert.png')
