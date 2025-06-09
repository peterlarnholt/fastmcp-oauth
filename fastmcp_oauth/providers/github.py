"""GitHub OAuth identity provider."""

import urllib.parse
from typing import Dict, Any, Optional
import httpx

from .base import IdentityProvider
from ..core.auth import UserInfo
from ..exceptions.auth import ProviderError


class GitHubIdentityProvider(IdentityProvider):
    """GitHub OAuth identity provider."""
    
    def __init__(self, client_id: str, client_secret: str):
        super().__init__(client_id, client_secret)
        self.auth_url = "https://github.com/login/oauth/authorize"
        self.token_url = "https://github.com/login/oauth/access_token"
        self.user_url = "https://api.github.com/user"
        self.emails_url = "https://api.github.com/user/emails"
    
    @property
    def name(self) -> str:
        return "github"
    
    async def get_authorization_url(
        self, 
        redirect_uri: str, 
        state: str,
        scopes: str = None
    ) -> str:
        """Get GitHub OAuth authorization URL."""
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "scope": scopes or "user:email"
        }
        
        query_string = urllib.parse.urlencode(params)
        return f"{self.auth_url}?{query_string}"
    
    async def exchange_code_for_token(
        self, 
        code: str, 
        redirect_uri: str
    ) -> Dict[str, Any]:
        """Exchange authorization code for GitHub access token."""
        data = {
            "code": code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": redirect_uri
        }
        
        headers = {"Accept": "application/json"}
        
        async with httpx.AsyncClient() as client:
            response = await client.post(self.token_url, data=data, headers=headers)
            
            if response.status_code != 200:
                raise ProviderError(
                    f"GitHub token exchange failed: {response.text}",
                    provider="github",
                    provider_error=response.text
                )
            
            return response.json()
    
    async def get_user_info(self, access_token: str) -> UserInfo:
        """Get GitHub user information."""
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        async with httpx.AsyncClient() as client:
            # Get user profile
            user_response = await client.get(self.user_url, headers=headers)
            
            if user_response.status_code != 200:
                raise ProviderError(
                    f"GitHub user request failed: {user_response.text}",
                    provider="github",
                    provider_error=user_response.text
                )
            
            user_data = user_response.json()
            
            # Get user emails
            email = user_data.get("email")
            if not email:
                emails_response = await client.get(self.emails_url, headers=headers)
                if emails_response.status_code == 200:
                    emails = emails_response.json()
                    # Find primary email
                    primary_email = next(
                        (e["email"] for e in emails if e.get("primary")), 
                        None
                    )
                    email = primary_email or f"{user_data['login']}@users.noreply.github.com"
                else:
                    email = f"{user_data['login']}@users.noreply.github.com"
            
            return UserInfo(
                id=str(user_data["id"]),
                email=email,
                name=user_data.get("name") or user_data["login"],
                provider="github",
                picture=user_data.get("avatar_url"),
                verified_email=True  # GitHub emails are considered verified
            )


class GitHubOAuth:
    """Simplified GitHub OAuth provider for FastMCP.
    
    Usage:
        from fastmcp import FastMCP
        from fastmcp_oauth import GitHubOAuth
        
        mcp = FastMCP("My Server")
        oauth = GitHubOAuth(
            client_id="your-client-id",
            client_secret="your-client-secret"
        )
        app = oauth.install(mcp)
    """
    
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        **kwargs
    ):
        self.github_provider = GitHubIdentityProvider(
            client_id=client_id,
            client_secret=client_secret
        )
        self.kwargs = kwargs
    
    def install(self, mcp):
        """Install OAuth authentication on FastMCP instance."""
        # Import here to avoid circular imports
        from ..core.provider import OAuthProvider
        
        oauth_provider = OAuthProvider(
            identity_providers=[self.github_provider],
            **self.kwargs
        )
        
        return oauth_provider.install(mcp)
    
    @classmethod
    def from_env(cls, prefix: str = "GITHUB_") -> "GitHubOAuth":
        """Create GitHubOAuth from environment variables.
        
        Expected environment variables:
        - GITHUB_CLIENT_ID
        - GITHUB_CLIENT_SECRET
        """
        import os
        
        client_id = os.getenv(f"{prefix}CLIENT_ID")
        client_secret = os.getenv(f"{prefix}CLIENT_SECRET")
        
        if not client_id or not client_secret:
            from ..exceptions.auth import ConfigurationError
            raise ConfigurationError(
                f"Missing GitHub OAuth configuration: {prefix}CLIENT_ID and {prefix}CLIENT_SECRET required"
            )
        
        return cls(
            client_id=client_id,
            client_secret=client_secret
        )