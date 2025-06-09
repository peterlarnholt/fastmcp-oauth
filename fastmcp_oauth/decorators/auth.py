"""Authentication decorators for MCP tools."""

from functools import wraps
from typing import Callable, List, Optional, Any, Awaitable
from ..core.auth import AuthContext, UserInfo
from ..exceptions.auth import AuthenticationError, AuthorizationError


def require_auth(func: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
    """Decorator that requires authentication for an MCP tool.
    
    Usage:
        @mcp.tool()
        @require_auth
        async def my_tool(ctx) -> str:
            user = ctx.auth.user
            return f"Hello {user.name}!"
    """
    import inspect
    
    # Get the original function signature
    sig = inspect.signature(func)
    
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # Try to bind arguments to original function signature
        try:
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()
            
            # Find the context parameter (usually named 'ctx')
            ctx = None
            for param_name, param_value in bound_args.arguments.items():
                # Check if this looks like a Context object
                if hasattr(param_value, 'get_http_request'):
                    ctx = param_value
                    break
            
            if ctx is None:
                return f"❌ No Context found. Parameters: {list(bound_args.arguments.keys())}"
                
        except Exception as e:
            return f"❌ Argument binding failed: {str(e)}"
        
        # Get HTTP request from context
        try:
            request = ctx.get_http_request()
            auth_header = request.headers.get('authorization')
            
            if not auth_header or not auth_header.startswith('Bearer '):
                return "❌ Authentication required"
            
            # Extract and validate token
            token = auth_header[7:]
            
            # Try simple HS256 decoding first (bypass RSA issues)
            try:
                from authlib.jose import jwt
                secret_key = __import__('os').getenv('SECRET_KEY')
                print(f"🔍 DEBUG: Trying HS256 with SECRET_KEY: {secret_key[:20]}...")
                
                payload = jwt.decode(token, secret_key)
                payload.validate()
                user_data = dict(payload)
                print(f"✅ DEBUG: HS256 decoding successful!")
                
            except Exception as hs256_error:
                print(f"❌ DEBUG: HS256 failed: {hs256_error}")
                
                # Try to decode the JWT header to see what algorithm it uses
                try:
                    import base64
                    import json
                    header_b64 = token.split('.')[0]
                    # Add padding if needed
                    header_b64 += '=' * (4 - len(header_b64) % 4)
                    header = json.loads(base64.urlsafe_b64decode(header_b64))
                    print(f"🔍 DEBUG: Token header: {header}")
                except:
                    print("❌ DEBUG: Could not decode JWT header")
                
                raise Exception(f"Token decoding failed. HS256 error: {hs256_error}")
            
            # Process user data regardless of which decoder worked
            user_info = UserInfo(
                id=user_data.get('provider_id', ''),
                email=user_data.get('email', ''),
                name=user_data.get('name', ''),
                provider=user_data.get('provider', '')
            )
            scopes = user_data.get('scope', '').split() if user_data.get('scope') else ['read', 'write']
            auth_context = AuthContext(user=user_info, scopes=scopes, token=token)
            
            # Inject auth context into ctx
            ctx.auth = auth_context
            
            return await func(*args, **kwargs)
            
        except Exception as e:
            return f"❌ Invalid token: {str(e)}"
            
        except Exception as e:
            return f"❌ Authentication error: {str(e)}"
    
    return wrapper


def require_scope(scope: str) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    """Decorator that requires a specific scope for an MCP tool.
    
    Args:
        scope: Required scope (e.g., "read", "write", "admin")
        
    Usage:
        @mcp.tool()
        @require_scope("admin")
        async def admin_tool(ctx) -> str:
            return "Admin operation completed"
    """
    def decorator(func: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # FastMCP may pass Context as keyword argument
            ctx = None
            if args:
                ctx = args[0]
            elif 'ctx' in kwargs:
                ctx = kwargs['ctx']
            
            if ctx is None:
                return f"❌ No context provided. Args: {args}, Kwargs: {list(kwargs.keys())}"
            
            # Get HTTP request from context
            try:
                request = ctx.get_http_request()
                auth_header = request.headers.get('authorization')
                
                if not auth_header or not auth_header.startswith('Bearer '):
                    return "❌ Authentication required"
                
                # Extract and validate token
                token = auth_header[7:]
                
                from ..core.tokens import TokenManager
                from ..config.settings import OAuthConfig
                
                config = OAuthConfig(OAUTH_SECRET_KEY=__import__('os').getenv('SECRET_KEY', 'dev-key'))
                token_manager = TokenManager(config)
                
                try:
                    user_data = token_manager.decode_token(token)
                    
                    user_info = UserInfo(
                        id=user_data.get('provider_id', ''),
                        email=user_data.get('email', ''),
                        name=user_data.get('name', ''),
                        provider=user_data.get('provider', '')
                    )
                    scopes = user_data.get('scope', '').split() if user_data.get('scope') else ['read', 'write']
                    auth_context = AuthContext(user=user_info, scopes=scopes, token=token)
                    
                    # Check required scope
                    if not auth_context.has_scope(scope):
                        return f"❌ Requires scope: {scope}"
                    
                    # Inject auth context into ctx
                    ctx.auth = auth_context
                    
                    return await func(*args, **kwargs)
                    
                except Exception as e:
                    return f"❌ Invalid token: {str(e)}"
                
            except Exception as e:
                return f"❌ Authentication error: {str(e)}"
        
        return wrapper
    return decorator


def require_user(
    email: Optional[str] = None, 
    domain: Optional[str] = None,
    provider: Optional[str] = None
) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    """Decorator that requires specific user characteristics.
    
    Args:
        email: Required email address
        domain: Required email domain (e.g., "company.com")
        provider: Required OAuth provider (e.g., "google", "github")
        
    Usage:
        @mcp.tool()
        @require_user(domain="company.com")
        async def company_tool(ctx) -> str:
            return "Company-only operation"
            
        @mcp.tool()
        @require_user(email="admin@company.com")
        async def admin_tool(ctx) -> str:
            return "Admin-only operation"
    """
    def decorator(func: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        @wraps(func)
        async def wrapper(ctx, *args, **kwargs):
            # Get authentication context
            auth_context = getattr(ctx, 'auth', None)
            if auth_context is None:
                return "❌ Authentication system not configured"
            
            if not auth_context.is_authenticated:
                return "❌ Authentication required"
            
            user = auth_context.user
            
            # Check specific email
            if email and user.email != email:
                return "❌ Access denied"
            
            # Check email domain
            if domain and not user.email.endswith(f"@{domain}"):
                return f"❌ Requires {domain} email domain"
            
            # Check OAuth provider
            if provider and user.provider != provider:
                return f"❌ Requires {provider} authentication"
            
            return await func(ctx, *args, **kwargs)
        
        return wrapper
    return decorator


def require_any_scope(scopes: List[str]) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    """Decorator that requires any of the specified scopes.
    
    Args:
        scopes: List of acceptable scopes
        
    Usage:
        @mcp.tool()
        @require_any_scope(["read", "write"])
        async def data_tool(ctx) -> str:
            return "Data operation"
    """
    def decorator(func: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        @wraps(func)
        async def wrapper(ctx, *args, **kwargs):
            auth_context = getattr(ctx, 'auth', None)
            if auth_context is None:
                return "❌ Authentication system not configured"
            
            if not auth_context.is_authenticated:
                return "❌ Authentication required"
            
            if not auth_context.has_any_scope(scopes):
                return f"❌ Requires one of: {', '.join(scopes)}"
            
            return await func(ctx, *args, **kwargs)
        
        return wrapper
    return decorator


def require_all_scopes(scopes: List[str]) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    """Decorator that requires all of the specified scopes.
    
    Args:
        scopes: List of required scopes
        
    Usage:
        @mcp.tool()
        @require_all_scopes(["read", "write", "admin"])
        async def super_admin_tool(ctx) -> str:
            return "Super admin operation"
    """
    def decorator(func: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        @wraps(func)
        async def wrapper(ctx, *args, **kwargs):
            auth_context = getattr(ctx, 'auth', None)
            if auth_context is None:
                return "❌ Authentication system not configured"
            
            if not auth_context.is_authenticated:
                return "❌ Authentication required"
            
            if not auth_context.has_all_scopes(scopes):
                missing = [s for s in scopes if not auth_context.has_scope(s)]
                return f"❌ Missing required scopes: {', '.join(missing)}"
            
            return await func(ctx, *args, **kwargs)
        
        return wrapper
    return decorator