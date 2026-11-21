"""


Password storage and password policy.
  SECURE_MODE = False -> md5_hash()   (VULNERABLE: unsalted, fast, crackable)
  SECURE_MODE = True  -> bcrypt_hash() (SECURE: salted, slow by design)
"""
import hashlib
import re

import bcrypt

# Shown to the user on the register page (secure mode)
PASSWORD_RULES = [
    "At least 8 characters",
    "At least one uppercase letter (A-Z)",
    "At least one lowercase letter (a-z)",
    "At least one number (0-9)",
    "At least one special character (e.g. ! @ # $ %)",
]


def validate_password(password):
    """Return the rules the password does NOT meet. An empty list means it is valid."""
    checks = [
        len(password) >= 8,
        re.search(r"[A-Z]", password),
        re.search(r"[a-z]", password),
        re.search(r"[0-9]", password),
        re.search(r"[^A-Za-z0-9]", password),
    ]
    return [rule for rule, ok in zip(PASSWORD_RULES, checks) if not ok]


def md5_hash(password):
    # VULNERABLE: MD5 is fast and unsalted, so identical passwords give identical hashes
    return hashlib.md5(password.encode()).hexdigest()


def bcrypt_hash(password):
    # SECURE: bcrypt adds a random salt to each password and is slow by design
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def bcrypt_check(password, stored_hash):
    # Compares in constant time. Returns False if the stored value is not a bcrypt hash.
    try:
        return bcrypt.checkpw(password.encode(), stored_hash.encode())
    except ValueError:
        return False
