import streamlit as st

import pyexiv2
import base64
import hashlib

from dilithium.dilithium import Dilithium2

# read the public key from a file
with open('public_key.pem', 'rb') as f:
    pk_b64 = f.read()

# decode the public key from base64
pk = base64.b64decode(pk_b64)

# add_logo('http://placekitten.com/120/120', height=100)

# # Add a selectbox to the sidebar:
# add_selectbox = st.sidebar.selectbox(
#     'How would you like to be contacted?',
#     ('Email', 'Home phone', 'Mobile phone')
# )

# Add an option to upload a file in the sidebar:
# st.sidebar.title('Upload your signature')
# add_file = st.sidebar.file_uploader(
#     'Upload your signature',
#     type=['txt', 'pem'],
#     label_visibility='hidden'
# )
# st.sidebar.title('Department of Computer Science, Ashoka University')

st.sidebar.title('Certificate Verification')

st.sidebar.write("For Workshop on Lattice-based Post-Quantum Cryptography July 17-19, 2023")
st.sidebar.write("Organized by Prof. Mahavir Jhawar, Department of Computer Science, Ashoka University")

add_file = st.sidebar.file_uploader(
    'Upload your certificate',
    type=['png'],
    label_visibility='hidden'
)


# This certificate has been signed using the post-quantum signature scheme Dilithium 
# The public key of the organiser is available at  "website"
# The signature is available in one of the metadata tags of the resulting .png file 
# For verification, one may visit "website"' + ''')




# extract the uploaded file if it exists:
imageBytes = None
if add_file is not None:
    imageBytes = add_file.read() # BytesIO object

# read the signature from the image
if imageBytes is not None:
    with pyexiv2.ImageData(imageBytes) as img:
        data = img.read_xmp()
        if 'Xmp.dc.signature' not in data:
            st.sidebar.error('No signature found')
            st.stop()
        sig = base64.b64decode(data['Xmp.dc.signature'].encode('utf-8'))
        tbs_data = {k: v for k, v in data.items() if k != 'Xmp.dc.signature'}
        tbs_data_hash = hashlib.sha256(str(tbs_data).encode('utf-8')).digest()

        # st.write(tbs_data_hash.hex())
        # st.write(img.read_xmp())

    # verify the signature
    if Dilithium2.verify(pk, tbs_data_hash, sig):
        st.sidebar.success('Signature verified')
    else:
        st.sidebar.error('Signature not verified')



def format_public_key(public_key):
    # Add a line break every 64 characters to improve readability
    # formatted_key = '\n'.join([public_key[i:i+64] for i in range(0, len(public_key), 64)])
    formatted_key = public_key
    # Wrap the key in a pre tag to preserve whitespace and formatting
    return f"<pre>{formatted_key}</pre>"

# Custom CSS to style the public key display
key_display_style = """
<style>
.key-container {
    background-color: black;
    padding: 10px;
    border-radius: 5px;
    max-height: 300px; /* Maximum height of the container, after which it becomes scrollable */
    width: 100%;
    word-wrap: break-word;
    overflow: auto; /* Enable scrolling when the content exceeds the maximum height */
    white-space: pre-wrap; /* Preserve line breaks and wrap long lines */
    font-family: monospace; /* Use a monospaced font for better formatting */
}
.copy-button {
    margin-top: 10px;
}
</style>
"""

st.title('Workshop on Lattice-based Post-Quantum Cryptography')
st.subheader('Public Key generated using Dilithium2, a lattice-based signature scheme. The public key is of size 1312 bytes.')

# st.header("PK Value:")
# Add custom CSS for key display
st.markdown(key_display_style, unsafe_allow_html=True)
st.markdown(f'<div class="key-container">{format_public_key(pk.hex())}</div>', unsafe_allow_html=True)

# Copy to Clipboard button
if st.button("Copy to Clipboard"):
    st.write("Key copied to clipboard!")
    st.text(pk.hex())
# use html to format the public key in a nice code box with fixed width and height:
