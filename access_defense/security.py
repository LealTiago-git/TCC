"""Password hashing and verification using PBKDF2-SHA256.

This module implements secure password storage for demo users. While this is
a prototype, it demonstrates security best practices:
  ✓ Passwords are hashed, never stored in plain text
  ✓ Uses PBKDF2-SHA256 with 260,000 iterations (NIST recommendation)
  ✓ Each password gets a unique 128-bit salt
  ✓ Timing-safe comparison prevents timing attacks
  ✓ Hash format: pbkdf2_sha256$260000$base64_salt$base64_digest

Reference: OWASP Authentication Cheat Sheet
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets


# PBKDF2 configuration (aligned with Django defaults and NIST guidelines)
HASH_NAME = "pbkdf2_sha256"
ITERATIONS = 260_000  # Updated from Django 4.2+


def hash_password(plain_password: str) -> str:
    """Securely hash a password using PBKDF2-SHA256.
    
    Each password is hashed with:
      - Unique 128-bit (16-byte) random salt
      - 260,000 PBKDF2 iterations (prevents brute-force)
      - SHA256 hash algorithm
    
    Args:
        plain_password: User-entered password in plain text
        
    Returns:
        String format: "pbkdf2_sha256$260000$base64_salt$base64_digest"
        Safe for storage in database
        
    Example:
        >>> hashed = hash_password("my-secure-password")
        >>> verify_password("my-secure-password", hashed)
        True
        >>> verify_password("wrong-password", hashed)
        False
    """

    # Generate random salt for this password
    password_salt = secrets.token_bytes(16)
    
    # Derive hash using PBKDF2
    password_hash = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=plain_password.encode("utf-8"),
        salt=password_salt,
        iterations=ITERATIONS
    )
    
    # Encode salt and hash to base64 for storage
    encoded_salt = base64.b64encode(password_salt).decode("ascii")
    encoded_hash = base64.b64encode(password_hash).decode("ascii")
    
    # Return format: algorithm$iterations$salt$digest
    return "$".join([
        HASH_NAME,
        str(ITERATIONS),
        encoded_salt,
        encoded_hash,
    ])


def verify_password(candidate_password: str, stored_hash: str) -> bool:
    """Verify a password against a stored hash using timing-safe comparison.
    
    Args:
        candidate_password: Password user is attempting
        stored_hash: Hash stored in database (from hash_password)
        
    Returns:
        True if password matches, False otherwise
        
    Raises:
        Returns False on format errors rather than raising exceptions
        (prevents information leakage about which users exist)
    """

    try:
        # Parse stored hash
        hash_name_stored, iterations_str, salt_b64, digest_b64 = (
            stored_hash.split("$", 3)
        )
        
        # Validate algorithm name
        if hash_name_stored != HASH_NAME:
            return False
        
        # Decode salt from base64
        password_salt = base64.b64decode(salt_b64.encode("ascii"))
        
        # Get expected hash from storage
        stored_digest = base64.b64decode(digest_b64.encode("ascii"))
        
        # Re-derive hash using same salt and iterations
        candidate_hash = hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=candidate_password.encode("utf-8"),
            salt=password_salt,
            iterations=int(iterations_str),
        )
        
        # Use timing-safe comparison to prevent timing attacks
        # This prevents attackers from guessing passwords by measuring response time
        passwords_match = hmac.compare_digest(candidate_hash, stored_digest)
        
        return passwords_match
        
    except (ValueError, TypeError) as format_error:
        # Handle malformed hash format gracefully
        return False

