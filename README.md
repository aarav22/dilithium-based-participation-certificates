# ML-DSA Certificate Platform

A simple platform for signing and verifying workshop participation certificates using ML-DSA-44, a post-quantum cryptographic signature scheme.

## Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Generate keys (if you don't have them)
python src/generate_keys.py
```

## Usage

Run the unified application:

```bash
./run.sh
```

The website has three sections:

**Verify Certificate** - Public access. Participants upload their signed certificates to check authenticity.

**Sign Certificates** - Admin access only (password required). Organizers can:
- Sign single certificates
- Bulk upload and sign multiple certificates at once (downloads as ZIP)

**Public Key** - Shows the organizer's public key that anyone can use to verify signatures.

Default admin password is `workshop2025`. Change it by setting the `ADMIN_PASSWORD` environment variable.

## How it works

### Signing Process

When you sign a certificate:
1. The system computes a SHA-256 hash of the **entire original PNG image** (all bytes)
2. This hash is stored in the certificate's metadata (`Xmp.dc.imageHash`)
3. The hash is signed using ML-DSA-44 with the private key
4. The signature is embedded in the metadata (`Xmp.dc.signature`)

**This protects the entire image.** If anyone modifies even one pixel, the stored hash won't match, and they cannot update it without the private key.

### Verification Process

When someone verifies a certificate:
1. The signature and stored image hash are extracted from metadata
2. The signature is verified using the public key
3. If valid, the certificate is authentic and the image is protected

**Security Note:** The stored hash acts as a cryptographic commitment to the original image. Even though adding the signature changes the file size, the original image content is protected because:
- The hash was computed before adding the signature
- An attacker would need the private key to sign a new hash
- Changing the image invalidates the signature

## Project Structure

```
src/
  app.py              - Main application entry point
  config.py           - Configuration settings
  crypto_utils.py     - Signing and verification functions
  ui_components.py    - UI components and page layouts
  generate_keys.py    - Utility to create new key pairs

keys/
  public_key.pem      - Public key (shareable)
  secret_key.pem      - Secret key (keep private!)

run.sh                - Quick start script
requirements.txt      - Python dependencies
```

## Deployment

Deploy to any platform that supports Streamlit (Streamlit Cloud, Heroku, etc). The entry point is `src/app.py`. Include the `public_key.pem` file but never include `secret_key.pem` in public deployments.

## Requirements

Certificate images must be PNG files. No special metadata is required - the signature system will add all necessary metadata automatically.
