"""
UI components and page layouts
"""

import streamlit as st
import io
import zipfile
from crypto_utils import sign_certificate, verify_certificate
from config import ADMIN_PASSWORD


def render_verification_tab(pk: bytes):
    """Render the certificate verification tab"""
    st.header("Verify Your Certificate")
    st.write("Upload your signed certificate to verify its authenticity.")
    
    verify_file = st.file_uploader(
        "Upload signed certificate (PNG)",
        type=['png'],
        key="verify_upload"
    )
    
    if verify_file:
        cert_bytes = verify_file.read()
        
        col1, col2 = st.columns([1, 1])
        
        with col1:
            st.write("**Your Certificate**")
            st.image(cert_bytes, width='stretch')
        
        with col2:
            st.write("**Verification Result**")
            with st.spinner("Verifying signature..."):
                is_valid, message = verify_certificate(cert_bytes, pk)
            
            if is_valid:
                st.success(f"**{message}**")
                st.info("""
                This certificate was officially issued by the workshop organizers.
                The signature was created using ML-DSA-44, a post-quantum secure signature scheme.
                """)
            else:
                st.error(f"**{message}**")
                st.warning("This certificate may not be authentic or has been tampered with.")


def render_signing_tab(sk: bytes):
    """Render the certificate signing tab"""
    st.header("Sign Certificates")
    st.write("Admin access required")
    
    password = st.text_input("Admin Password", type="password", key="admin_password")
    
    if password:
        if password != ADMIN_PASSWORD:
            st.error("Incorrect password")
        else:
            st.success("Access granted")
            
            mode = st.radio("Select mode:", ["Single Certificate", "Bulk Upload"], horizontal=True)
            
            if mode == "Single Certificate":
                render_single_signing(sk)
            else:
                render_bulk_signing(sk)


def render_single_signing(sk: bytes):
    """Render single certificate signing interface"""
    st.write("### Sign Single Certificate")
    
    cert_file = st.file_uploader(
        "Upload certificate to sign (PNG)",
        type=['png'],
        key="sign_single"
    )
    
    if cert_file:
        cert_bytes = cert_file.read()
        
        with st.spinner("Signing certificate..."):
            signed_bytes, success, message = sign_certificate(cert_bytes, sk)
        
        if success:
            st.success("Certificate signed successfully!")
            
            col1, col2 = st.columns(2)
            with col1:
                st.write("**Original**")
                st.image(cert_bytes, width='stretch')
            with col2:
                st.write("**Signed**")
                st.image(signed_bytes, width='stretch')
            
            st.download_button(
                label="Download Signed Certificate",
                data=signed_bytes,
                file_name=f"signed_{cert_file.name}",
                mime="image/png",
                width='stretch'
            )
        else:
            st.error(f"Error: {message}")


def render_bulk_signing(sk: bytes):
    """Render bulk certificate signing interface"""
    st.write("### Bulk Sign Certificates")
    st.info("Upload multiple PNG certificates at once. All signed certificates will be downloaded as a ZIP file.")
    
    cert_files = st.file_uploader(
        "Upload certificates to sign (PNG files)",
        type=['png'],
        accept_multiple_files=True,
        key="sign_bulk"
    )
    
    if cert_files:
        st.write(f"**{len(cert_files)} certificates uploaded**")
        
        if st.button("Sign All Certificates", type="primary", width='stretch'):
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            zip_buffer = io.BytesIO()
            
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                success_count = 0
                failed_files = []
                
                for idx, cert_file in enumerate(cert_files):
                    status_text.text(f"Signing {cert_file.name}...")
                    
                    cert_bytes = cert_file.read()
                    signed_bytes, success, message = sign_certificate(cert_bytes, sk)
                    
                    if success:
                        zip_file.writestr(f"signed_{cert_file.name}", signed_bytes)
                        success_count += 1
                    else:
                        failed_files.append((cert_file.name, message))
                    
                    progress_bar.progress((idx + 1) / len(cert_files))
            
            status_text.empty()
            progress_bar.empty()
            
            st.success(f"Successfully signed {success_count} out of {len(cert_files)} certificates")
            
            if failed_files:
                st.warning("Failed certificates:")
                for filename, error in failed_files:
                    st.text(f"  - {filename}: {error}")
            
            if success_count > 0:
                st.download_button(
                    label=f"Download All Signed Certificates (ZIP)",
                    data=zip_buffer.getvalue(),
                    file_name="signed_certificates.zip",
                    mime="application/zip",
                    width='stretch'
                )


def render_public_key_tab(pk: bytes):
    """Render the public key display tab"""
    st.header("Organizer's Public Key")
    st.write("ML-DSA-44 Public Key (1,312 bytes)")
    
    pk_hex = pk.hex()
    st.code(pk_hex, language="text")
    
    if st.button("Copy Public Key"):
        st.toast("Public key copied to clipboard!")


def render_sidebar():
    """Render the sidebar with workshop information"""
    st.sidebar.title("PQStation")
    st.sidebar.write("**Training on Lattice-based Post-Quantum Cryptography**")
    # st.sidebar.write("July 18-20, 2023")
    # st.sidebar.write("Organized by Prof. Mahavir Jhawar")
    # st.sidebar.write("Ashoka University")
    
    st.sidebar.divider()
        
    # from config import WORKSHOP_PDF
    # if WORKSHOP_PDF.exists():
    #     with open(WORKSHOP_PDF, 'rb') as f:
    #         st.sidebar.download_button(
    #             label='Download Schedule',
    #             data=f.read(),
    #             file_name='Workshop_Schedule.pdf',
    #             mime='application/pdf',
    #             use_container_width=True
    #         )



def hide_streamlit_branding():
    """Hide Streamlit default branding"""
    hide_style = """
    <style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    </style>
    """
    st.markdown(hide_style, unsafe_allow_html=True)

