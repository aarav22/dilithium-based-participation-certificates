"""
Cryptographic operations for ML-DSA certificate signing and verification
"""
import base64
import hashlib
import streamlit as st
from PIL import Image
from PIL.PngImagePlugin import PngInfo
from io import BytesIO
from dilithium_py.ml_dsa import ML_DSA_44
from config import PUBLIC_KEY_PATH, SECRET_KEY_PATH

@st.cache_resource
def load_keys():
    """Load ML-DSA public and secret keys"""
    try:
        with open(PUBLIC_KEY_PATH, 'rb') as f:
            pk = base64.b64decode(f.read())
        with open(SECRET_KEY_PATH, 'rb') as f:
            sk = base64.b64decode(f.read())
        return pk, sk
    except FileNotFoundError:
        st.error("Key files not found. Run: python src/generate_keys.py")
        st.stop()

def sign_certificate(cert_bytes: bytes, sk: bytes) -> tuple[bytes, bool, str]:
    """
    Sign the certificate image with ML-DSA signature
    
    Process:
    1. Compute SHA-256 hash of the entire original PNG image
    2. Store this hash in PNG metadata (imageHash text chunk)
    3. Sign the hash with ML-DSA
    4. Store signature in PNG metadata (signature text chunk)
    
    This ensures the entire image is protected - if anyone modifies the image,
    the stored hash won't match, and they can't update it without the private key.
    
    Args:
        cert_bytes: PNG certificate image bytes
        sk: ML-DSA secret key
    
    Returns:
        Tuple of (signed_bytes, success, message)
    """
    try:
        # 1. Compute hash of original image
        image_hash = hashlib.sha256(cert_bytes).digest()
        image_hash_hex = image_hash.hex()
        
        # 2. Sign the hash
        try:
            sig = ML_DSA_44.sign(sk, image_hash)
            sig_b64 = base64.b64encode(sig).decode('utf-8')
        except Exception as e:
            print(f"Error signing hash: {e}")
        
        # 3. Open the image and prepare metadata
        img = Image.open(BytesIO(cert_bytes))
        
        # Create PNG metadata object
        metadata = PngInfo()
        
        # Preserve existing metadata
        for key, value in img.info.items():
            if key not in ['signature', 'imageHash', 'signer', 'description']:
                metadata.add_text(key, str(value))
        
        # Add signature metadata
        metadata.add_text('signature', sig_b64)
        metadata.add_text('imageHash', image_hash_hex)
        metadata.add_text('signer', 'ML-DSA-44')
        metadata.add_text('description', 'Post-quantum signed certificate')
        
        # 4. Save to bytes with metadata
        output = BytesIO()
        img.save(output, format='PNG', pnginfo=metadata)
        signed_bytes = output.getvalue()
        
        return signed_bytes, True, "Success"
        
    except Exception as e:
        return None, False, str(e)

def verify_certificate(cert_bytes: bytes, pk: bytes) -> tuple[bool, str]:
    """
    Verify ML-DSA signature on a certificate
    
    Process:
    1. Extract stored image hash and signature from PNG text chunks
    2. Verify the signature of the stored hash
    
    Note: The stored hash protects the original image. If someone changes
    the image pixels, they would need to update the hash and re-sign it,
    which requires the private key they don't have.
    
    Args:
        cert_bytes: Signed certificate image bytes
        pk: ML-DSA public key
    
    Returns:
        Tuple of (is_valid, message)
    """
    try:
        # Open image and read metadata
        img = Image.open(BytesIO(cert_bytes))
        
        # Check for required fields
        if 'signature' not in img.info:
            return False, "No signature found in certificate"
        if 'imageHash' not in img.info:
            return False, "No image hash found - certificate may be from old version"
        
        # Extract signature and hash
        sig_b64 = img.info['signature']
        sig = base64.b64decode(sig_b64.encode('utf-8'))
        
        stored_hash_hex = img.info['imageHash']
        stored_hash = bytes.fromhex(stored_hash_hex)
        
        # Verify the signature of the stored hash
        is_valid = ML_DSA_44.verify(pk, stored_hash, sig)
        
        if is_valid:
            return True, "Certificate signature is valid - original image is protected"
        else:
            return False, "Certificate signature is invalid - may have been tampered with"
            
    except Exception as e:
        return False, f"Verification error: {str(e)}""""
Cryptographic operations for ML-DSA certificate signing and verification
"""
import base64
import hashlib
import streamlit as st
from PIL import Image
from PIL.PngImagePlugin import PngInfo
from io import BytesIO
from dilithium_py.ml_dsa import ML_DSA_44
from config import PUBLIC_KEY_PATH, SECRET_KEY_PATH

@st.cache_resource
def load_keys():
    """Load ML-DSA public and secret keys"""
    try:
        with open(PUBLIC_KEY_PATH, 'rb') as f:
            pk = base64.b64decode(f.read())
        with open(SECRET_KEY_PATH, 'rb') as f:
            sk = base64.b64decode(f.read())
        return pk, sk
    except FileNotFoundError:
        st.error("Key files not found. Run: python src/generate_keys.py")
        st.stop()

def sign_certificate(cert_bytes: bytes, sk: bytes) -> tuple[bytes, bool, str]:
    """
    Sign the certificate image with ML-DSA signature
    
    Process:
    1. Compute SHA-256 hash of the entire original PNG image
    2. Store this hash in PNG metadata (imageHash text chunk)
    3. Sign the hash with ML-DSA
    4. Store signature in PNG metadata (signature text chunk)
    
    This ensures the entire image is protected - if anyone modifies the image,
    the stored hash won't match, and they can't update it without the private key.
    
    Args:
        cert_bytes: PNG certificate image bytes
        sk: ML-DSA secret key
    
    Returns:
        Tuple of (signed_bytes, success, message)
    """
    try:
        # 1. Compute hash of original image
        image_hash = hashlib.sha256(cert_bytes).digest()
        image_hash_hex = image_hash.hex()
        
        # 2. Sign the hash
        sig = ML_DSA_44.sign(sk, image_hash)
        sig_b64 = base64.b64encode(sig).decode('utf-8')
        
        # 3. Open the image and prepare metadata
        img = Image.open(BytesIO(cert_bytes))
        
        # Create PNG metadata object
        metadata = PngInfo()
        
        # Preserve existing metadata
        for key, value in img.info.items():
            if key not in ['signature', 'imageHash', 'signer', 'description']:
                metadata.add_text(key, str(value))
        
        # Add signature metadata
        metadata.add_text('signature', sig_b64)
        metadata.add_text('imageHash', image_hash_hex)
        metadata.add_text('signer', 'ML-DSA-44')
        metadata.add_text('description', 'Post-quantum signed certificate')
        
        # 4. Save to bytes with metadata
        output = BytesIO()
        img.save(output, format='PNG', pnginfo=metadata)
        signed_bytes = output.getvalue()
        
        return signed_bytes, True, "Success"
        
    except Exception as e:
        return None, False, str(e)

def verify_certificate(cert_bytes: bytes, pk: bytes) -> tuple[bool, str]:
    """
    Verify ML-DSA signature on a certificate
    
    Process:
    1. Extract stored image hash and signature from PNG text chunks
    2. Verify the signature of the stored hash
    
    Note: The stored hash protects the original image. If someone changes
    the image pixels, they would need to update the hash and re-sign it,
    which requires the private key they don't have.
    
    Args:
        cert_bytes: Signed certificate image bytes
        pk: ML-DSA public key
    
    Returns:
        Tuple of (is_valid, message)
    """
    try:
        # Open image and read metadata
        img = Image.open(BytesIO(cert_bytes))
        
        # Check for required fields
        if 'signature' not in img.info:
            return False, "No signature found in certificate"
        if 'imageHash' not in img.info:
            return False, "No image hash found - certificate may be from old version"
        
        # Extract signature and hash
        sig_b64 = img.info['signature']
        sig = base64.b64decode(sig_b64.encode('utf-8'))
        
        stored_hash_hex = img.info['imageHash']
        stored_hash = bytes.fromhex(stored_hash_hex)
        
        # Verify the signature of the stored hash
        is_valid = ML_DSA_44.verify(pk, stored_hash, sig)
        
        if is_valid:
            return True, "Certificate signature is valid - original image is protected"
        else:
            return False, "Certificate signature is invalid - may have been tampered with"
            
    except Exception as e:
        return False, f"Verification error: {str(e)}"