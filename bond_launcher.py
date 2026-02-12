"""Thin launcher for Bond MCP Server — no-spaces path for OnlyOffice compatibility."""
import sys
import os

BOND_DIR = os.environ.get("BOND_DIR", os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BOND_DIR)
os.chdir(BOND_DIR)

from bond_server import main
main()
