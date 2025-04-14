#!/usr/bin/env python3
import sys
import os

# Add the parent directory to sys.path to allow absolute imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the main Typer app from vaultic.py
from vaultic import app

if __name__ == "__main__":
    app()