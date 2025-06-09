"""JWT token management for OAuth authentication."""

import time
from typing import Dict, Any, Optional
from authlib.jose import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ..core.auth import UserInfo
from ..config.settings import OAuthConfig
from ..exceptions.auth import InvalidTokenError


class TokenManager:
    """Manages JWT token creation and validation."""
    
    def __init__(self, config: OAuthConfig):
        self.config = config
        self._rsa_private_key = None
        self._rsa_public_key = None
    
    def _get_rsa_keys(self):
        """Get or generate RSA key pair for MCP tokens."""
        if self._rsa_private_key is None:
            self._rsa_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            self._rsa_public_key = self._rsa_private_key.public_key()
        
        return self._rsa_private_key, self._rsa_public_key
    
    def get_public_key_pem(self) -> str:
        """Get RSA public key in PEM format."""
        _, public_key = self._get_rsa_keys()
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    
    def create_web_token(self, user_info: UserInfo) -> str:
        """Create JWT token for web authentication (HS256)."""
        header = {"alg": "HS256"}
        now = int(time.time())
        
        payload = {
            "sub": user_info.email,
            "iss": self.config.OAUTH_ISSUER_URL,
            "aud": "web",
            "iat": now,
            "exp": now + self.config.OAUTH_TOKEN_EXPIRY,
            "email": user_info.email,
            "name": user_info.name,
            "provider": user_info.provider,
            "provider_id": user_info.id
        }
        
        token = jwt.encode(header, payload, self.config.OAUTH_SECRET_KEY)
        return token.decode('utf-8') if isinstance(token, bytes) else token
    
    def create_mcp_token(self, user_info: UserInfo, issuer: str = None) -> str:
        """Create JWT token for MCP authentication (RS256)."""
        private_key, _ = self._get_rsa_keys()
        header = {"alg": "RS256", "typ": "JWT"}
        now = int(time.time())
        
        payload = {
            "sub": user_info.email,
            "iss": issuer or self.config.OAUTH_ISSUER_URL,
            "aud": "mcp-server",
            "iat": now,
            "exp": now + self.config.OAUTH_TOKEN_EXPIRY,
            "scope": " ".join(self.config.OAUTH_SCOPES),
            "email": user_info.email,
            "name": user_info.name,
            "provider": user_info.provider,
            "provider_id": user_info.id
        }
        
        # Convert private key to PEM bytes
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        token = jwt.encode(header, payload, private_key_pem)
        return token.decode('utf-8') if isinstance(token, bytes) else token
    
    def decode_token(self, token: str) -> Dict[str, Any]:
        """Decode and validate JWT token."""
        try:
            # Handle string representation of bytes
            if token.startswith("b'") and token.endswith("'"):
                token = token[2:-1]
            
            # Try web token first (HS256) - more common
            try:
                payload = jwt.decode(token, self.config.OAUTH_SECRET_KEY)
                payload.validate()
                return dict(payload)
            except:
                # Fall back to MCP token (RS256)
                try:
                    _, public_key = self._get_rsa_keys()
                    public_key_pem = public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    payload = jwt.decode(token, public_key_pem)
                    payload.validate()
                    return dict(payload)
                except Exception as rsa_error:
                    raise InvalidTokenError(f"Unable to decode token with either HS256 or RS256: {str(rsa_error)}")
                
        except Exception as e:
            raise InvalidTokenError(f"Invalid token: {str(e)}")
    
    def validate_token(self, token: str) -> bool:
        """Validate if token is valid and not expired."""
        try:
            self.decode_token(token)
            return True
        except:
            return False