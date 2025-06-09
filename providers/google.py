"""Google OAuth identity provider."""

import urllib.parse
from typing import Dict, Any, Optional
import httpx

from .base import IdentityProvider
from ..core.auth import UserInfo
from ..exceptions.auth import ProviderError


class GoogleIdentityProvider(IdentityProvider):
    """Google OAuth 2.0 identity provider."""
    
    def __init__(
        self, 
        client_id: str, 
        client_secret: str,
        scopes: str = "openid email profile"
    ):
        super().__init__(client_id, client_secret)
        self.scopes = scopes
        self.auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
        self.token_url = "https://oauth2.googleapis.com/token"
        self.userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo"
    
    @property
    def name(self) -> str:
        return "google"
    
    async def get_authorization_url(
        self, 
        redirect_uri: str, 
        state: str,
        scopes: str = None
    ) -> str:
        """Get Google OAuth authorization URL."""
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": scopes or self.scopes,
            "state": state,
            "access_type": "offline",
            "prompt": "consent"
        }
        
        query_string = urllib.parse.urlencode(params)
        return f"{self.auth_url}?{query_string}"
    
    async def exchange_code_for_token(
        self, 
        code: str, 
        redirect_uri: str
    ) -> Dict[str, Any]:
        """Exchange authorization code for Google access token."""
        data = {
            "code": code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(self.token_url, data=data)
            
            if response.status_code != 200:
                raise ProviderError(
                    f"Google token exchange failed: {response.text}",
                    provider="google",
                    provider_error=response.text
                )
            
            return response.json()
    
    async def get_user_info(self, access_token: str) -> UserInfo:
        """Get Google user information."""
        headers = {"Authorization": f"Bearer {access_token}"}
        
        async with httpx.AsyncClient() as client:
            response = await client.get(self.userinfo_url, headers=headers)
            
            if response.status_code != 200:
                raise ProviderError(
                    f"Google userinfo request failed: {response.text}",
                    provider="google",
                    provider_error=response.text
                )
            
            user_data = response.json()
            
            return UserInfo(
                id=user_data["id"],
                email=user_data["email"],
                name=user_data.get("name", ""),
                provider="google",
                picture=user_data.get("picture"),
                verified_email=user_data.get("verified_email", True)
            )


class GoogleOAuth:
    """Simplified Google OAuth provider for FastMCP.
    
    Usage:
        from fastmcp import FastMCP
        from fastmcp_oauth import GoogleOAuth
        
        mcp = FastMCP("My Server")
        oauth = GoogleOAuth(
            client_id="your-client-id",
            client_secret="your-client-secret"
        )
        app = oauth.install(mcp)
    """
    
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        scopes: Optional[str] = None,
        **kwargs
    ):
        self.google_provider = GoogleIdentityProvider(
            client_id=client_id,
            client_secret=client_secret,
            scopes=scopes or "openid email profile"
        )
        self.kwargs = kwargs
    
    def install(self, mcp):
        """Install OAuth authentication on FastMCP instance."""
        # Import here to avoid circular imports
        from ..core.provider import OAuthProvider
        
        oauth_provider = OAuthProvider(
            identity_providers=[self.google_provider],
            **self.kwargs
        )
        
        return oauth_provider.install(mcp)
    
    @classmethod
    def from_env(cls, prefix: str = "GOOGLE_") -> "GoogleOAuth":
        """Create GoogleOAuth from environment variables.
        
        Expected environment variables:
        - GOOGLE_CLIENT_ID
        - GOOGLE_CLIENT_SECRET  
        - GOOGLE_SCOPES (optional)
        - SECRET_KEY (for OAuth secret)
        """
        import os
        
        client_id = os.getenv(f"{prefix}CLIENT_ID")
        client_secret = os.getenv(f"{prefix}CLIENT_SECRET")
        scopes = os.getenv(f"{prefix}SCOPES", "openid email profile")
        
        # Get OAuth secret key from environment
        secret_key = os.getenv("SECRET_KEY") or os.getenv("OAUTH_SECRET_KEY")
        
        if not client_id or not client_secret:
            from ..exceptions.auth import ConfigurationError
            raise ConfigurationError(
                f"Missing Google OAuth configuration: {prefix}CLIENT_ID and {prefix}CLIENT_SECRET required"
            )
        
        if not secret_key:
            from ..exceptions.auth import ConfigurationError
            raise ConfigurationError(
                "Missing SECRET_KEY or OAUTH_SECRET_KEY environment variable"
            )
        
        return cls(
            client_id=client_id,
            client_secret=client_secret,
            scopes=scopes,
            secret_key=secret_key
        )