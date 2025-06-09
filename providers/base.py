"""Base identity provider interface."""

from abc import ABC, abstractmethod
from typing import Dict, Any
from ..core.auth import UserInfo


class IdentityProvider(ABC):
    """Base class for OAuth identity providers."""
    
    def __init__(self, client_id: str, client_secret: str):
        self.client_id = client_id
        self.client_secret = client_secret
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name (e.g., 'google', 'github')."""
        pass
    
    @abstractmethod
    async def get_authorization_url(
        self, 
        redirect_uri: str, 
        state: str,
        scopes: str = None
    ) -> str:
        """Get OAuth authorization URL."""
        pass
    
    @abstractmethod
    async def exchange_code_for_token(
        self, 
        code: str, 
        redirect_uri: str
    ) -> Dict[str, Any]:
        """Exchange authorization code for access token."""
        pass
    
    @abstractmethod
    async def get_user_info(self, access_token: str) -> UserInfo:
        """Get user information using access token."""
        pass
    
    async def complete_oauth_flow(
        self, 
        code: str, 
        redirect_uri: str
    ) -> UserInfo:
        """Complete OAuth flow and return user info."""
        token_data = await self.exchange_code_for_token(code, redirect_uri)
        access_token = token_data.get("access_token")
        if not access_token:
            raise ValueError("No access token received from provider")
        return await self.get_user_info(access_token)