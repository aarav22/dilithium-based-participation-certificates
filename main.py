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

st.sidebar.title('Upload your certificate')
add_file = st.sidebar.file_uploader(
    'Upload your certificate',
    type=['png'],
    label_visibility='hidden'
)




# extract the uploaded file if it exists:
imageBytes = None
if add_file is not None:
    imageBytes = add_file.read() # BytesIO object

# read the signature from the image
if imageBytes is not None:
    with pyexiv2.ImageData(imageBytes) as img:
        data = img.read_xmp()
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



# set max upload size to 1 MB


# Add a slider to the sidebar:
# add_slider = st.sidebar.slider(
#     'Select a range of values',
#     0.0, 100.0, (25.0, 75.0)
# )

# st.text('Fixed width text')
# st.markdown('_Markdown_') # see *
# st.caption('Balloons. Hundreds of them...')
# st.latex(r''' e^{i\pi} + 1 = 0 ''')
# st.write('Most objects') # df, err, func, keras!
# st.write(['st', 'is <', 3]) # see *
st.title('My PQC Workship Certificate Verification')
st.header('Public Key')
# st.subheader('My sub')
# st.code('for i in range(8): foo()')


# a large text box to show full public key to a user:
st.code(pk_b64.hex(), 'markdown')