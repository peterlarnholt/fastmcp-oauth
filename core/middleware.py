"""OAuth middleware for FastMCP servers."""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from ..core.auth import AuthContext


class OAuthMiddleware(BaseHTTPMiddleware):
    """Middleware that adds OAuth authentication context to requests."""
    
    def __init__(self, app, oauth_provider):
        super().__init__(app)
        self.oauth_provider = oauth_provider
    
    async def dispatch(self, request: Request, call_next):
        # Check if this is the SSE endpoint and enforce authentication
        if request.url.path == "/sse":
            auth_header = request.headers.get("authorization")
            token_param = request.query_params.get("token")
            
            if not (auth_header or token_param):
                return Response("Unauthorized", status_code=401)
        
        # Add authentication context to request
        auth_context = self.oauth_provider.get_auth_context(request)
        request.state.auth = auth_context
        
        response = await call_next(request)
        return response