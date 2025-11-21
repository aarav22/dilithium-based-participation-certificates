#!/bin/bash
# Start the unified ML-DSA Certificate Platform

echo "Starting ML-DSA Certificate Platform..."
echo "========================================"
echo ""
echo "Default admin password: workshop2025"
echo "To change: export ADMIN_PASSWORD='your-password'"
echo ""
echo "Opening at http://localhost:8501"
echo ""

streamlit run src/app.py
