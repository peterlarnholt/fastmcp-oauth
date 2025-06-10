"""Main OAuth provider for FastMCP servers."""

import os
import secrets
import asyncio
from typing import List, Dict, Any, Optional
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse
from starlette.exceptions import HTTPException

from ..providers.base import IdentityProvider
from ..core.auth import AuthContext, UserInfo
from ..core.tokens import TokenManager
from ..core.middleware import OAuthMiddleware
from ..config.settings import OAuthConfig
from ..exceptions.auth import ConfigurationError, ProviderError


class OAuthProvider:
    """Main OAuth provider for FastMCP servers."""
    
    def __init__(
        self,
        identity_providers: List[IdentityProvider],
        scopes: List[str] = None,
        token_expiry: int = 3600,
        issuer_url: str = None,
        secret_key: str = None,
        config: OAuthConfig = None
    ):
        self.identity_providers = identity_providers
        self.providers_by_name = {p.name: p for p in identity_providers}
        self.config = config or OAuthConfig()
        
        # Override config with explicit parameters
        if scopes:
            self.config.OAUTH_SCOPES = scopes
        if token_expiry:
            self.config.OAUTH_TOKEN_EXPIRY = token_expiry
        if issuer_url:
            self.config.OAUTH_ISSUER_URL = issuer_url
        if secret_key:
            self.config.OAUTH_SECRET_KEY = secret_key
        
        # Validate configuration
        self._validate_config()
        
        # Initialize token manager
        self.token_manager = TokenManager(self.config)
        
        # Storage for OAuth state and codes
        self.auth_codes: Dict[str, Any] = {}
        self.oauth_states: Dict[str, Any] = {}
    
    def _validate_config(self):
        """Validate OAuth configuration."""
        if not self.config.OAUTH_SECRET_KEY:
            raise ConfigurationError("OAUTH_SECRET_KEY is required")
        
        if not self.identity_providers:
            raise ConfigurationError("At least one identity provider is required")
    
    @classmethod
    def from_env(cls, prefix: str = "OAUTH_") -> "OAuthProvider":
        """Create OAuthProvider from environment variables."""
        config = OAuthConfig.from_env(prefix)
        
        # Auto-detect and configure identity providers
        providers = []
        
        # Google provider
        google_client_id = os.getenv("GOOGLE_CLIENT_ID")
        google_client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
        if google_client_id and google_client_secret:
            from ..providers.google import GoogleIdentityProvider
            providers.append(GoogleIdentityProvider(google_client_id, google_client_secret))
        
        # Microsoft provider
        microsoft_client_id = os.getenv("MICROSOFT_CLIENT_ID")
        microsoft_client_secret = os.getenv("MICROSOFT_CLIENT_SECRET")
        microsoft_tenant = os.getenv("MICROSOFT_TENANT", "common")
        if microsoft_client_id and microsoft_client_secret:
            from ..providers.microsoft import MicrosoftIdentityProvider
            providers.append(MicrosoftIdentityProvider(
                microsoft_client_id, 
                microsoft_client_secret,
                tenant=microsoft_tenant
            ))
        
        # GitHub provider
        github_client_id = os.getenv("GITHUB_CLIENT_ID")
        github_client_secret = os.getenv("GITHUB_CLIENT_SECRET")
        if github_client_id and github_client_secret:
            from ..providers.github import GitHubIdentityProvider
            providers.append(GitHubIdentityProvider(github_client_id, github_client_secret))
        
        if not providers:
            raise ConfigurationError(
                "No identity providers configured. Set GOOGLE_CLIENT_ID/SECRET, "
                "MICROSOFT_CLIENT_ID/SECRET, or GITHUB_CLIENT_ID/SECRET"
            )
        
        return cls(identity_providers=providers, config=config)
    
    def install(self, mcp):
        """Install OAuth authentication on FastMCP instance."""
        # Add OAuth routes
        self._add_oauth_routes(mcp)
        
        # Create middleware
        middleware = self._create_middleware()
        
        # Create FastMCP app with middleware
        app = mcp.http_app(transport="sse", middleware=middleware)
        
        # Inject authentication context into MCP tools
        self._setup_auth_context(mcp)
        
        return app
    
    def _add_oauth_routes(self, mcp):
        """Add OAuth endpoints to FastMCP."""
        # OAuth discovery endpoints
        mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])(
            self._oauth_metadata
        )
        mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])(
            self._oauth_protected_resource_metadata
        )
        
        # OAuth flow endpoints
        mcp.custom_route("/oauth/register", methods=["POST"])(self._register_client)
        mcp.custom_route("/oauth/authorize", methods=["GET"])(self._authorize)
        mcp.custom_route("/oauth/token", methods=["POST"])(self._token_endpoint)
        
        # Standard OAuth callback endpoint
        mcp.custom_route("/oauth/callback", methods=["GET"])(
            self._create_unified_callback_handler()
        )
    
    def _create_middleware(self):
        """Create middleware stack for OAuth."""
        return [
            Middleware(OAuthMiddleware, oauth_provider=self),
            Middleware(SessionMiddleware, secret_key=self.config.OAUTH_SECRET_KEY),
            Middleware(
                CORSMiddleware,
                allow_origins=self.config.CORS_ORIGINS,
                allow_credentials=True,
                allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                allow_headers=["*"]
            )
        ]
    
    def _setup_auth_context(self, mcp):
        """Setup authentication context for MCP tools."""
        # This would inject auth context into MCP request context
        # Implementation depends on FastMCP's internal API
        pass
    
    async def _oauth_metadata(self, request: Request):
        """OAuth 2.0 Authorization Server Metadata."""
        # For metadata endpoints, prioritize configured issuer URL
        if (self.config.OAUTH_ISSUER_URL and 
            self.config.OAUTH_ISSUER_URL not in ["https://localhost:8000", "http://localhost:8000", ""]):
            base_url = self.config.OAUTH_ISSUER_URL
        else:
            base_url = self._detect_base_url(request)
        
        return JSONResponse({
            "issuer": base_url,
            "authorization_endpoint": f"{base_url}/oauth/authorize",
            "token_endpoint": f"{base_url}/oauth/token",
            "registration_endpoint": f"{base_url}/oauth/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": self.config.OAUTH_SCOPES,
        })
    
    async def _oauth_protected_resource_metadata(self, request: Request):
        """OAuth 2.0 Protected Resource Metadata."""
        # For metadata endpoints, prioritize configured issuer URL
        if (self.config.OAUTH_ISSUER_URL and 
            self.config.OAUTH_ISSUER_URL not in ["https://localhost:8000", "http://localhost:8000", ""]):
            base_url = self.config.OAUTH_ISSUER_URL
        else:
            base_url = self._detect_base_url(request)
        
        return JSONResponse({
            "resource": f"{base_url}/sse",
            "authorization_servers": [base_url],
            "bearer_methods_supported": ["header"],
            "scopes_supported": self.config.OAUTH_SCOPES,
        })
    
    async def _register_client(self, request: Request):
        """Dynamic client registration."""
        try:
            client_data = await request.json()
        except:
            raise HTTPException(status_code=400, detail="Invalid JSON")
        
        client_id = secrets.token_urlsafe(16)
        # Store client registration (in production, use persistent storage)
        
        return JSONResponse({
            "client_id": client_id,
            "client_name": client_data.get("client_name", "MCP Client"),
            "redirect_uris": client_data.get("redirect_uris", []),
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none"
        })
    
    async def _authorize(self, request: Request):
        """OAuth authorization endpoint."""
        params = request.query_params
        provider_name = params.get("provider", "google")  # Default to first provider
        
        if provider_name not in self.providers_by_name:
            # Use first available provider if not specified
            provider_name = list(self.providers_by_name.keys())[0]
        
        provider = self.providers_by_name[provider_name]
        
        # Store OAuth request parameters
        oauth_state = secrets.token_urlsafe(32)
        self.oauth_states[oauth_state] = {
            "client_id": params.get("client_id"),
            "redirect_uri": params.get("redirect_uri"),
            "code_challenge": params.get("code_challenge"),
            "code_challenge_method": params.get("code_challenge_method"),
            "state": params.get("state"),
            "provider": provider_name
        }
        
        # Redirect to identity provider
        base_url = self._detect_base_url(request)
        callback_uri = f"{base_url}/oauth/callback"
        
        auth_url = await provider.get_authorization_url(
            redirect_uri=callback_uri,
            state=oauth_state
        )
        
        return RedirectResponse(url=auth_url)
    
    def _create_unified_callback_handler(self):
        """Create unified callback handler for all providers."""
        async def callback_handler(request: Request):
            code = request.query_params.get("code")
            state = request.query_params.get("state")
            error = request.query_params.get("error")
            
            if error:
                raise HTTPException(status_code=400, detail=f"OAuth error: {error}")
            
            if state not in self.oauth_states:
                raise HTTPException(status_code=400, detail="Invalid state parameter")
            
            oauth_request = self.oauth_states[state]
            provider_name = oauth_request.get("provider", "google")  # Default to google
            del self.oauth_states[state]
            
            # Get the provider
            provider = self.providers_by_name.get(provider_name)
            if not provider:
                raise HTTPException(status_code=400, detail=f"Unknown provider: {provider_name}")
            
            # Exchange code for user info
            base_url = self._detect_base_url(request)
            callback_uri = f"{base_url}/oauth/callback"
            
            try:
                user_info = await provider.complete_oauth_flow(code, callback_uri)
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"OAuth flow failed: {str(e)}")
            
            # Generate MCP authorization code
            mcp_code = secrets.token_urlsafe(32)
            self.auth_codes[mcp_code] = {
                "user_info": user_info,
                "client_id": oauth_request["client_id"],
                "redirect_uri": oauth_request["redirect_uri"],
                "code_challenge": oauth_request["code_challenge"],
                "expires_at": asyncio.get_event_loop().time() + 600
            }
            
            # Redirect back to MCP client
            redirect_url = f"{oauth_request['redirect_uri']}?code={mcp_code}"
            if oauth_request.get("state"):
                redirect_url += f"&state={oauth_request['state']}"
            
            return RedirectResponse(url=redirect_url)
        
        return callback_handler
    
    async def _token_endpoint(self, request: Request):
        """OAuth token endpoint."""
        form_data = await request.form()
        code = form_data.get("code")
        
        if code not in self.auth_codes:
            raise HTTPException(status_code=400, detail="Invalid authorization code")
        
        auth_data = self.auth_codes[code]
        
        # Check expiration
        if asyncio.get_event_loop().time() > auth_data["expires_at"]:
            del self.auth_codes[code]
            raise HTTPException(status_code=400, detail="Authorization code expired")
        
        # Validate PKCE if present
        code_verifier = form_data.get("code_verifier")
        if auth_data.get("code_challenge") and code_verifier:
            import base64
            import hashlib
            challenge = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode()).digest()
            ).decode().rstrip("=")
            
            if challenge != auth_data["code_challenge"]:
                raise HTTPException(status_code=400, detail="Invalid code verifier")
        
        user_info = auth_data["user_info"]
        del self.auth_codes[code]
        
        # Create access token (use web token HS256 for compatibility)
        base_url = self._detect_base_url(request)
        access_token = self.token_manager.create_web_token(user_info)
        
        return JSONResponse({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": self.config.OAUTH_TOKEN_EXPIRY,
            "scope": " ".join(self.config.OAUTH_SCOPES)
        })
    
    def _detect_base_url(self, request: Request) -> str:
        """Detect base URL from request headers."""
        # Debug logging
        import logging
        logger = logging.getLogger(__name__)
        logger.debug(f"OAUTH_ISSUER_URL from config: {self.config.OAUTH_ISSUER_URL}")
        
        # First check if OAUTH_ISSUER_URL is explicitly set and not a default value
        if (self.config.OAUTH_ISSUER_URL and 
            self.config.OAUTH_ISSUER_URL not in ["https://localhost:8000", "http://localhost:8000"]):
            # Use the explicitly configured issuer URL
            logger.info(f"Using configured OAUTH_ISSUER_URL: {self.config.OAUTH_ISSUER_URL}")
            return self.config.OAUTH_ISSUER_URL
        
        # Check for standard proxy headers
        if "x-forwarded-proto" in request.headers and "x-forwarded-host" in request.headers:
            protocol = request.headers["x-forwarded-proto"]
            host = request.headers["x-forwarded-host"]
            return f"{protocol}://{host}"
        
        # Check for X-Forwarded-Proto only (Cloud Run case)
        if "x-forwarded-proto" in request.headers:
            protocol = request.headers["x-forwarded-proto"]
            host = request.headers.get("host", request.url.netloc)
            return f"{protocol}://{host}"
        
        # Check for Forwarded header (RFC 7239)
        forwarded = request.headers.get("forwarded")
        if forwarded:
            import re
            proto_match = re.search(r'proto=([^;,\s]+)', forwarded)
            host_match = re.search(r'host=([^;,\s]+)', forwarded)
            if proto_match and host_match:
                return f"{proto_match.group(1)}://{host_match.group(1)}"
        
        # Google Cloud Run specific check
        if request.url.netloc.endswith(".run.app"):
            # Cloud Run always uses HTTPS for external traffic
            return f"https://{request.url.netloc}"
        
        # Default fallback
        return f"{request.url.scheme}://{request.url.netloc}"
    
    def get_auth_context(self, request: Request) -> AuthContext:
        """Extract authentication context from request."""
        auth_header = request.headers.get("authorization")
        token_param = request.query_params.get("token")
        
        token = None
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]
        elif token_param:
            token = token_param
        
        if token:
            try:
                user_data = self.token_manager.decode_token(token)
                user_info = UserInfo(
                    id=user_data["provider_id"],
                    email=user_data["email"],
                    name=user_data["name"],
                    provider=user_data["provider"]
                )
                scopes = user_data.get("scope", "").split()
                return AuthContext(user=user_info, scopes=scopes, token=token)
            except:
                pass
        
        return AuthContext(user=None, scopes=[], token=None)