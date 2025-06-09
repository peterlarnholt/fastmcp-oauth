"""URL detection utilities."""

from starlette.requests import Request


def detect_base_url(request: Request) -> str:
    """Detect the actual base URL from request headers.
    
    This handles proxies like ngrok that set x-forwarded-* headers.
    
    Args:
        request: Starlette request object
        
    Returns:
        Base URL (e.g., 'https://example.com' or 'http://localhost:8000')
    """
    # Check for proxy headers (ngrok, load balancers, etc.)
    if "x-forwarded-proto" in request.headers and "x-forwarded-host" in request.headers:
        protocol = request.headers["x-forwarded-proto"]
        host = request.headers["x-forwarded-host"]
        return f"{protocol}://{host}"
    
    # Fallback to direct connection
    return f"{request.url.scheme}://{request.url.netloc}"


def build_redirect_uri(base_url: str, provider: str) -> str:
    """Build OAuth callback redirect URI.
    
    Args:
        base_url: Base URL of the server
        provider: Provider name (e.g., 'google', 'github')
        
    Returns:
        Full redirect URI for OAuth callback
    """
    return f"{base_url}/oauth/callback/{provider}"