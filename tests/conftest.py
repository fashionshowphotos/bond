import os
import sys


BOND_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BOND_ROOT not in sys.path:
    sys.path.insert(0, BOND_ROOT)
