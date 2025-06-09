"""OAuth authentication exceptions."""

from typing import Optional


class OAuthError(Exception):
    """Base exception for OAuth errors."""
    
    def __init__(self, message: str, error_code: Optional[str] = None):
        super().__init__(message)
        self.error_code = error_code


class AuthenticationError(OAuthError):
    """Raised when authentication is required but not provided."""
    
    def __init__(self, message: str = "Authentication required"):
        super().__init__(message, "authentication_required")


class AuthorizationError(OAuthError):
    """Raised when user lacks required permissions/scopes."""
    
    def __init__(self, message: str, required_scope: Optional[str] = None):
        super().__init__(message, "insufficient_scope")
        self.required_scope = required_scope


class InvalidTokenError(OAuthError):
    """Raised when token is invalid or expired."""
    
    def __init__(self, message: str = "Invalid or expired token"):
        super().__init__(message, "invalid_token")


class ConfigurationError(OAuthError):
    """Raised when OAuth configuration is invalid."""
    
    def __init__(self, message: str, missing_config: Optional[str] = None):
        super().__init__(message, "configuration_error")
        self.missing_config = missing_config


class ProviderError(OAuthError):
    """Raised when identity provider returns an error."""
    
    def __init__(self, message: str, provider: str, provider_error: Optional[str] = None):
        super().__init__(message, "provider_error")
        self.provider = provider
        self.provider_error = provider_error