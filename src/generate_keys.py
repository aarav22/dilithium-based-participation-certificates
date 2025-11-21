"""
Generate ML-DSA-44 (Dilithium2) key pair for certificate signing

Usage:
    python src/generate_keys.py
"""

import base64
from pathlib import Path
from dilithium_py.ml_dsa import ML_DSA_44

def generate_keys():
    """Generate and save ML-DSA-44 key pair"""
    
    print("Generating ML-DSA-44 (Dilithium2) key pair...")
    print("This may take a moment...")
    
    # Generate keys
    pk, sk = ML_DSA_44.keygen()
    
    # Create keys directory if it doesn't exist
    keys_dir = Path(__file__).parent.parent / "keys"
    keys_dir.mkdir(exist_ok=True)
    
    # Save public key
    pk_path = keys_dir / "public_key.pem"
    with open(pk_path, 'wb') as f:
        f.write(base64.b64encode(pk))
    print(f"✓ Public key saved to: {pk_path}")
    print(f"  Size: {len(pk)} bytes")
    
    # Save secret key
    sk_path = keys_dir / "secret_key.pem"
    with open(sk_path, 'wb') as f:
        f.write(base64.b64encode(sk))
    print(f"✓ Secret key saved to: {sk_path}")
    print(f"  Size: {len(sk)} bytes")

if __name__ == "__main__":
    generate_keys()

