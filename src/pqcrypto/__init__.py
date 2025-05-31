"""
laicrypto

Post-quantum Lemniscate-AGM Isogeny (LAI) Encryption Scheme.
"""

from .lai import (
    H,
    sqrt_mod,
    T,
    keygen,
    encrypt,
    decrypt,
)

__all__ = [
    "H",
    "sqrt_mod",
    "T",
    "keygen",
    "encrypt",
    "decrypt",
]

# Versi paket, sinkronkan dengan pyproject.toml:
__version__ = "0.1.2"
