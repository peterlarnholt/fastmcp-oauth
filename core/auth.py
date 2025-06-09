"""Authentication context and user information classes."""

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class UserInfo:
    """User information from identity provider."""
    
    id: str
    email: str
    name: str
    provider: str
    picture: Optional[str] = None
    verified_email: bool = True
    
    def __str__(self) -> str:
        return f"{self.name} <{self.email}> ({self.provider})"


@dataclass
class AuthContext:
    """Authentication context for MCP tools."""
    
    user: Optional[UserInfo]
    scopes: List[str]
    token: Optional[str] = None
    
    @property
    def is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        return self.user is not None
    
    def has_scope(self, scope: str) -> bool:
        """Check if user has specific scope."""
        return scope in self.scopes
    
    def has_any_scope(self, scopes: List[str]) -> bool:
        """Check if user has any of the specified scopes."""
        return any(scope in self.scopes for scope in scopes)
    
    def has_all_scopes(self, scopes: List[str]) -> bool:
        """Check if user has all of the specified scopes."""
        return all(scope in self.scopes for scope in scopes)
    
    def require_scope(self, scope: str) -> bool:
        """Require specific scope, raise exception if not present."""
        if not self.has_scope(scope):
            from ..exceptions.auth import AuthorizationError
            raise AuthorizationError(f"Required scope '{scope}' not found")
        return True
    
    def require_authentication(self) -> bool:
        """Require authentication, raise exception if not authenticated."""
        if not self.is_authenticated:
            from ..exceptions.auth import AuthenticationError
            raise AuthenticationError("Authentication required")
        return True