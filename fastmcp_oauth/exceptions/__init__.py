"""OAuth authentication exceptions."""

from .auth import (
    OAuthError,
    AuthenticationError,
    AuthorizationError,
    InvalidTokenError,
    ConfigurationError,
    ProviderError,
)

__all__ = [
    "OAuthError",
    "AuthenticationError", 
    "AuthorizationError",
    "InvalidTokenError",
    "ConfigurationError",
    "ProviderError",
]