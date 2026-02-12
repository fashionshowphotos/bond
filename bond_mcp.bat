@echo off
cd /d "%~dp0"
python -u bond_server.py --policy RESTRICTED --insecure-allow-unverified-modules
