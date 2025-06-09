"""Cryptographic utilities."""

import secrets
import string


def generate_secret_key(length: int = 32) -> str:
    """Generate a cryptographically secure secret key.
    
    Args:
        length: Length of the secret key (default: 32)
        
    Returns:
        Secure random string suitable for JWT signing
    """
    alphabet = string.ascii_letters + string.digits + "-_"
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_state_token(length: int = 32) -> str:
    """Generate a secure state token for OAuth flows.
    
    Args:
        length: Length of the state token (default: 32)
        
    Returns:
        URL-safe random string
    """
    return secrets.token_urlsafe(length)