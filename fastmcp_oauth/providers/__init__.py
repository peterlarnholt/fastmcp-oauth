"""OAuth identity providers for FastMCP."""

from .base import IdentityProvider
from .google import GoogleOAuth, GoogleIdentityProvider  
from .github import GitHubOAuth, GitHubIdentityProvider

__all__ = [
    "IdentityProvider",
    "GoogleOAuth", 
    "GoogleIdentityProvider",
    "GitHubOAuth",
    "GitHubIdentityProvider",
]