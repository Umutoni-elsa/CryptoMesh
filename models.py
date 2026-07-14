"""
models.py

Shared constants, Diffie-Hellman parameters and helper functions.
"""

import base64
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend


# =========================
# Directories
# =========================

BASE_DIR = Path.cwd() / "secure_messenger_data"
USERS_DIR = BASE_DIR / "users"
MSGS_DIR = BASE_DIR / "messages"


# =========================
# Diffie-Hellman Parameters
# RFC 3526 - 2048-bit MODP Group 14
# =========================

DH_P = 32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559

DH_G = 2

# packages the modulus and generator into the object form expected by the cryptography library.
DH_PARAM_NUMBERS = dh.DHParameterNumbers(DH_P, DH_G)
DH_PARAMETERS = DH_PARAM_NUMBERS.parameters(default_backend())


# =========================
# Base64 Helpers
# =========================

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(data: str) -> bytes:
    return base64.b64decode(data)


# =========================
# Integer Conversion Helpers
# =========================

def int_to_b64(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return b64e(value.to_bytes(length, "big"))


def b64_to_int(value: str) -> int:
    return int.from_bytes(b64d(value), "big")


# =========================
# Storage Initialization
# =========================

def initialize_storage():
    """
    Create the application's storage folders if they do not exist.
    """
    for directory in (BASE_DIR, USERS_DIR, MSGS_DIR):
        directory.mkdir(parents=True, exist_ok=True)