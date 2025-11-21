"""
Configuration settings for ML-DSA Certificate Platform
"""

import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).parent.parent  # Project root
KEYS_DIR = BASE_DIR / "keys"
PUBLIC_KEY_PATH = KEYS_DIR / "public_key.pem"
SECRET_KEY_PATH = KEYS_DIR / "secret_key.pem"
# WORKSHOP_PDF = BASE_DIR / "Workshop_on_Lattice-based_Post-Quantum Cryptography.pdf"

# Authentication
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "workshop2025")

# Workshop Information
WORKSHOP_NAME = "Training on Lattice-based Post-Quantum Cryptography"
WORKSHOP_DATES = "November 21-22, 2025"
# ORGANIZER = "Prof. Mahavir Jhawar"
# INSTITUTION = "Ashoka University"
# LECTURE_SLIDES_URL = "https://drive.google.com/file/d/1Fmzx5GPQJLIjoEk9w5qvdkLpvhg6B9LU/view"

