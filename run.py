#!/usr/bin/env python3
"""
CryptoPIX Bridge v3.0 - Application Runner
Simple script to start the CryptoPIX Bridge application
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.main import app

if __name__ == '__main__':
    print("Starting CryptoPIX Bridge v3.0...")
    print("VDS must be manually started from Settings page")
    print("Web interface available at http://localhost:8000")

    app.run(
        host='0.0.0.0',
        port=8000,
        debug=False  # Set to False for production
    )