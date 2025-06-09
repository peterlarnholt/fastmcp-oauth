"""OAuth configuration settings."""

import os
from typing import List

from ..exceptions.auth import ConfigurationError


class OAuthConfig:
    """OAuth configuration settings."""
    
    def __init__(self, **kwargs):
        # Core OAuth settings
        self.OAUTH_SECRET_KEY: str = kwargs.get("OAUTH_SECRET_KEY", "")
        self.OAUTH_ISSUER_URL: str = kwargs.get("OAUTH_ISSUER_URL", "https://localhost:8000")
        self.OAUTH_TOKEN_EXPIRY: int = kwargs.get("OAUTH_TOKEN_EXPIRY", 3600)
        self.OAUTH_SCOPES: List[str] = kwargs.get("OAUTH_SCOPES", ["read", "write"])
        
        # CORS settings
        self.CORS_ORIGINS: List[str] = kwargs.get("CORS_ORIGINS", ["*"])
        
        # Environment detection
        self.ENVIRONMENT: str = kwargs.get("ENVIRONMENT", "development")
    
    @classmethod
    def from_env(cls, prefix: str = "OAUTH_") -> "OAuthConfig":
        """Create configuration from environment variables."""
        # Map environment variables with prefix
        env_mapping = {
            f"{prefix}SECRET_KEY": "OAUTH_SECRET_KEY",
            f"{prefix}ISSUER_URL": "OAUTH_ISSUER_URL", 
            f"{prefix}TOKEN_EXPIRY": "OAUTH_TOKEN_EXPIRY",
            f"{prefix}SCOPES": "OAUTH_SCOPES",
            "CORS_ALLOWED_ORIGINS": "CORS_ORIGINS",
            "ENVIRONMENT": "ENVIRONMENT"
        }
        
        config_data = {}
        for env_var, config_key in env_mapping.items():
            value = os.getenv(env_var)
            if value is not None:
                if config_key == "OAUTH_SCOPES" or config_key == "CORS_ORIGINS":
                    config_data[config_key] = value.split(",")
                elif config_key == "OAUTH_TOKEN_EXPIRY":
                    config_data[config_key] = int(value)
                else:
                    config_data[config_key] = value
        
        # Use existing environment variables as fallback
        if not config_data.get("OAUTH_SECRET_KEY"):
            config_data["OAUTH_SECRET_KEY"] = os.getenv("SECRET_KEY", "")
        
        config = cls(**config_data)
        config.validate()
        return config
    
    def validate(self):
        """Validate configuration."""
        if not self.OAUTH_SECRET_KEY:
            raise ConfigurationError("OAUTH_SECRET_KEY is required")
        
        if len(self.OAUTH_SECRET_KEY) < 32:
            raise ConfigurationError("OAUTH_SECRET_KEY must be at least 32 characters")
        
        if self.ENVIRONMENT == "production":
            self._validate_production()
    
    def _validate_production(self):
        """Validate production-specific settings."""
        if self.OAUTH_SECRET_KEY == "dev-secret-key":
            raise ConfigurationError("Must use secure SECRET_KEY in production")
        
        if "*" in self.CORS_ORIGINS:
            raise ConfigurationError("Must specify CORS origins in production (not '*')")