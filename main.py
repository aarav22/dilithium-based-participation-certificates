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

st.sidebar.title('Certificate Verification')

st.sidebar.write('''For "Workshop on Lattice-based Post-Quantum Cryptography" held from July 18-20, 2023''')
st.sidebar.write("Organized by Mahavir Jhawar, Department of Computer Science, Ashoka University")

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
        tbs_data = {k: v for k, v in data.items() if k == 'Xmp.Attrib.Ads[1]/Attrib'}
        tbs_data_hash = hashlib.sha256(str(tbs_data).encode('utf-8')).digest()

        # st.write(tbs_data_hash.hex())
        # st.write(str(tbs_data))

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
    max-height: 200px; /* Maximum height of the container, after which it becomes scrollable */
    width: 100%;
    word-wrap: break-word;
    overflow: auto; /* Enable scrolling when the content exceeds the maximum height */
    white-space: pre-wrap; /* Preserve line breaks and wrap long lines */
    font-family: monospace; /* Use a monospaced font for better formatting */
}
.copy-button {
    margin-top: 100px;
}
</style>
"""

# st.title('Workshop on Lattice-based Post-Quantum Cryptography')
tab1, tab2 = st.tabs(["Public Key", "Verification Info"])
c = st.container()
tab1.header("Organizer's Public Key")
tab1.write('''Generated using Dilithium2, a lattice-based signature scheme. The public key is of size 1312 bytes.''')

# st.header("PK Value:")
# Add custom CSS for key display
tab1.markdown(key_display_style, unsafe_allow_html=True)
tab1.markdown(f'<div class="key-container">{format_public_key(pk.hex())}</div>', unsafe_allow_html=True)
# gap 
tab1.write('')
# Copy to Clipboard button
if tab1.button("Copy to Clipboard"):
    tab1.write("Key copied to clipboard!")
# use html to format the public key in a nice code box with fixed width and height:


tab2.header("Dilithium2 Signature Verification")
tab2.write('''Certificates presented to the participants of the workshop were digitally signed using the post-quantum signature scheme Dilithium. The signature is available in one of the metadata tags of the resulting .png file.''')
tab2.write('''The signature is extraced from the image and verified using the public key of the organizer.''')

tab2.write(''' The tags may look like this: ''')

dict2 = {'Xmp.pdf.Author': 'aarav', 'Xmp.xmp.CreatorTool': 'Canva', 'Xmp.dc.signature': 'avYHRB6pQ8OW5pRqVpFWt1kXams50T...[clipped]', 'Xmp.dc.title': {'lang="x-default"': 'lorem ipsum'}, 'Xmp.dc.creator': ['Dilithium2'], 'Xmp.Attrib.Ads': 'type="Seq"', 'Xmp.Attrib.Ads[1]': 'type="Struct"', 'Xmp.Attrib.Ads[1]/Attrib:Created': '2023-07-31', 'Xmp.Attrib.Ads[1]/Attrib:ExtId': '6f747215-1475-496c-8a98-d99e4d3ad6ae', 'Xmp.Attrib.Ads[1]/Attrib:FbId': '525265914179580', 'Xmp.Attrib.Ads[1]/Attrib:TouchType': '2'}

tab2.write(dict2)
 
hide_streamlit_style = """
            <style>
            footer {visibility: hidden;}
            </style>
            """
st.markdown(hide_streamlit_style, unsafe_allow_html=True) 

# add footer with text Made by Aarav (hyperlink it to https://github.com/aarav22)
st.sidebar.write('')
st.sidebar.write('')
st.sidebar.markdown('Website made by [Aarav](https://github.com/aarav22)')