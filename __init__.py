"""
FastMCP OAuth - OAuth 2.1 authentication for FastMCP servers

This package provides drop-in OAuth 2.1 authentication for FastMCP servers
with support for real identity providers like Google, GitHub, and Azure.

Quick Start:
    from fastmcp import FastMCP
    from fastmcp_oauth import GoogleOAuth, require_auth
    
    mcp = FastMCP("My Server")
    oauth = GoogleOAuth(client_id="...", client_secret="...")
    app = oauth.install(mcp)
    
    @mcp.tool()
    @require_auth
    async def protected_tool(ctx) -> str:
        return f"Hello {ctx.auth.user.name}!"
"""

__version__ = "1.0.0"
__author__ = "FastMCP OAuth Contributors"
__license__ = "MIT"

# Core exports
from .core.provider import OAuthProvider
from .core.auth import AuthContext, UserInfo

# Identity providers
from .providers.google import GoogleOAuth, GoogleIdentityProvider
from .providers.github import GitHubOAuth, GitHubIdentityProvider
from .providers.microsoft import MicrosoftOAuth, MicrosoftIdentityProvider

# Decorators
from .decorators.auth import require_auth, require_scope, require_user

# Exceptions
from .exceptions.auth import (
    AuthenticationError,
    AuthorizationError,
    InvalidTokenError,
    ConfigurationError,
)

# Configuration
from .config.settings import OAuthConfig

__all__ = [
    # Core
    "OAuthProvider",
    "AuthContext", 
    "UserInfo",
    
    # Providers
    "GoogleOAuth",
    "GoogleIdentityProvider",
    "GitHubOAuth", 
    "GitHubIdentityProvider",
    "MicrosoftOAuth",
    "MicrosoftIdentityProvider",
    
    # Decorators
    "require_auth",
    "require_scope",
    "require_user",
    
    # Exceptions
    "AuthenticationError",
    "AuthorizationError", 
    "InvalidTokenError",
    "ConfigurationError",
    
    # Config
    "OAuthConfig",
]