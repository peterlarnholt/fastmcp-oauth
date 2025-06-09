"""Microsoft Entra ID (Azure AD) OAuth provider."""

import os
import urllib.parse
from typing import Optional, List, Dict, Any
import httpx

from .base import IdentityProvider
from ..core.auth import UserInfo
from ..core.provider import OAuthProvider
from ..exceptions.auth import ProviderError, ConfigurationError


class MicrosoftIdentityProvider(IdentityProvider):
    """Microsoft Entra ID OAuth provider implementation."""
    
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        tenant: str = "common",
        base_url: str = "https://login.microsoftonline.com"
    ):
        """Initialize Microsoft OAuth provider.
        
        Args:
            client_id: Microsoft application (client) ID
            client_secret: Microsoft application secret
            tenant: Azure AD tenant ID or 'common' for multi-tenant
            base_url: Base URL for Microsoft identity platform
        """
        super().__init__(client_id=client_id, client_secret=client_secret)
        self.tenant = tenant
        self.base_url = base_url
        self._client = httpx.AsyncClient()
    
    @property
    def name(self) -> str:
        """Provider name."""
        return "microsoft"
    
    @property
    def authorization_endpoint(self) -> str:
        """Get Microsoft authorization endpoint."""
        return f"{self.base_url}/{self.tenant}/oauth2/v2.0/authorize"
    
    @property
    def token_endpoint(self) -> str:
        """Get Microsoft token endpoint."""
        return f"{self.base_url}/{self.tenant}/oauth2/v2.0/token"
    
    @property
    def userinfo_endpoint(self) -> str:
        """Get Microsoft Graph user info endpoint."""
        return "https://graph.microsoft.com/v1.0/me"
    
    async def get_authorization_url(
        self,
        redirect_uri: str,
        state: str,
        scopes: Optional[List[str]] = None
    ) -> str:
        """Generate Microsoft authorization URL.
        
        Args:
            redirect_uri: OAuth callback URL
            state: State parameter for CSRF protection
            scopes: OAuth scopes (defaults to User.Read)
            
        Returns:
            Authorization URL
        """
        if scopes is None:
            scopes = ["User.Read", "openid", "profile", "email"]
        
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "response_mode": "query",
            "scope": " ".join(scopes),
            "state": state,
            "prompt": "select_account"
        }
        
        return f"{self.authorization_endpoint}?{urllib.parse.urlencode(params)}"
    
    async def exchange_code_for_token(self, code: str, redirect_uri: str) -> Dict[str, Any]:
        """Exchange authorization code for access token.
        
        Args:
            code: Authorization code from Microsoft
            redirect_uri: Same redirect URI used in authorization
            
        Returns:
            Token response from Microsoft
        """
        data = {
            "client_id": self.client_id,
            "scope": "User.Read openid profile email",
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "client_secret": self.client_secret
        }
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        try:
            response = await self._client.post(
                self.token_endpoint,
                data=data,
                headers=headers
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            raise ProviderError(f"Failed to exchange code: {str(e)}")
    
    async def get_user_info(self, access_token: str) -> UserInfo:
        """Get user information from Microsoft Graph.
        
        Args:
            access_token: Microsoft access token
            
        Returns:
            UserInfo object
        """
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        
        try:
            response = await self._client.get(
                self.userinfo_endpoint,
                headers=headers
            )
            response.raise_for_status()
            user_data = response.json()
            
            # Microsoft Graph returns different field names
            return UserInfo(
                id=user_data.get("id"),
                email=user_data.get("mail") or user_data.get("userPrincipalName"),
                name=user_data.get("displayName"),
                provider="microsoft"
            )
        except httpx.HTTPError as e:
            raise ProviderError(f"Failed to get user info: {str(e)}")
    
    async def complete_oauth_flow(self, code: str, redirect_uri: str) -> UserInfo:
        """Complete OAuth flow and return user info.
        
        Args:
            code: Authorization code
            redirect_uri: OAuth callback URL
            
        Returns:
            UserInfo object
        """
        # Exchange code for token
        token_response = await self.exchange_code_for_token(code, redirect_uri)
        access_token = token_response.get("access_token")
        
        if not access_token:
            raise ProviderError("No access token in response")
        
        # Get user info
        return await self.get_user_info(access_token)
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self._client.aclose()


class MicrosoftOAuth(OAuthProvider):
    """Convenience class for Microsoft-only OAuth setup.
    
    Usage:
        oauth = MicrosoftOAuth(client_id="...", client_secret="...", tenant="...")
        app = oauth.install(mcp)
    """
    
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        tenant: str = "common",
        **kwargs
    ):
        """Initialize Microsoft OAuth provider.
        
        Args:
            client_id: Microsoft application (client) ID
            client_secret: Microsoft application secret
            tenant: Azure AD tenant ID or 'common' for multi-tenant
            **kwargs: Additional arguments passed to OAuthProvider
        """
        provider = MicrosoftIdentityProvider(client_id, client_secret, tenant)
        super().__init__(identity_providers=[provider], **kwargs)
    
    @classmethod
    def from_env(cls, prefix: str = "MICROSOFT_") -> "MicrosoftOAuth":
        """Create Microsoft OAuth provider from environment variables.
        
        Required environment variables:
            MICROSOFT_CLIENT_ID: Application (client) ID
            MICROSOFT_CLIENT_SECRET: Application secret
            
        Optional:
            MICROSOFT_TENANT: Tenant ID (defaults to 'common')
            SECRET_KEY: JWT signing key
            
        Returns:
            Configured MicrosoftOAuth instance
        """
        client_id = os.getenv(f"{prefix}CLIENT_ID")
        client_secret = os.getenv(f"{prefix}CLIENT_SECRET")
        tenant = os.getenv(f"{prefix}TENANT", "common")
        
        if not client_id or not client_secret:
            raise ConfigurationError(
                f"Missing required environment variables: "
                f"{prefix}CLIENT_ID and {prefix}CLIENT_SECRET"
            )
        
        # Get shared secret key
        secret_key = os.getenv("SECRET_KEY") or os.getenv("OAUTH_SECRET_KEY")
        if not secret_key:
            raise ConfigurationError("SECRET_KEY environment variable is required")
        
        return cls(
            client_id=client_id,
            client_secret=client_secret,
            tenant=tenant,
            secret_key=secret_key
        )