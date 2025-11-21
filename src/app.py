"""
ML-DSA Certificate Platform
Main application entry point
"""

import streamlit as st
from crypto_utils import load_keys
from ui_components import (
    render_verification_tab,
    render_signing_tab,
    render_public_key_tab,
    render_sidebar,
    hide_streamlit_branding
)

# Page configuration
st.set_page_config(
    page_title="Participa Certificate Platform",
    page_icon="🔐",
    layout="wide"
)

# Load cryptographic keys
pk, sk = load_keys()

# Main UI
st.title("Participation Certificate Platform")
st.write("Post-quantum certificate signing and verification")

# Main tabs
tab1, tab2, tab3 = st.tabs(["Verify Certificate", "Sign Certificates", "Public Key"])

with tab1:
    render_verification_tab(pk)

with tab2:
    render_signing_tab(sk)

with tab3:
    render_public_key_tab(pk)

# Sidebar
render_sidebar()

# Hide Streamlit branding
hide_streamlit_branding()
