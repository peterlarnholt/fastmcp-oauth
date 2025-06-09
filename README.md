# FastMCP OAuth

OAuth 2.1 + PKCE authentication for FastMCP servers with support for Google, Microsoft, and GitHub.

## ✨ Features

- **🔐 OAuth 2.1 + PKCE** - Standards-compliant authentication
- **🏢 Multiple Providers** - Google, Microsoft Entra ID, GitHub
- **🛡️ Scope-based Authorization** - Granular permission control
- **📱 MCP Tools** - Authenticated AI tool access
- **🚀 Production Ready** - Comprehensive error handling & security

## 🚀 Quick Start

### Installation

```bash
# From PyPI (when published)
pip install fastmcp-oauth

# From Git
pip install git+https://github.com/peterlarnholt/fastmcp-oauth.git

# With Poetry
poetry add git+https://github.com/peterlarnholt/fastmcp-oauth.git
```

### Usage

```python
from fastmcp import FastMCP
from fastmcp_oauth import MicrosoftOAuth, require_auth

# Create server
mcp = FastMCP("My Server")

# Add Microsoft OAuth (3 lines!)
oauth = MicrosoftOAuth.from_env()
app = oauth.install(mcp)

# Protected tool
@mcp.tool()
@require_auth
async def get_user_info(ctx) -> str:
    user = ctx.auth.user
    return f"Hello {user.name}! Email: {user.email}"
```

### Environment Variables

```bash
SECRET_KEY=your-secret-key-32-chars-minimum
MICROSOFT_CLIENT_ID=your-microsoft-client-id
MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret
MICROSOFT_TENANT=common  # or your tenant ID
```

## 🔧 Providers

### Microsoft Entra ID

```python
from fastmcp_oauth import MicrosoftOAuth

oauth = MicrosoftOAuth.from_env()
```

### Google OAuth

```python
from fastmcp_oauth import GoogleOAuth

oauth = GoogleOAuth.from_env()
```

### GitHub OAuth

```python
from fastmcp_oauth import GitHubOAuth

oauth = GitHubOAuth.from_env()
```

### Multi-Provider (Auto-detected)

```python
from fastmcp_oauth import OAuthProvider

# Detects all configured providers
oauth = OAuthProvider.from_env()
```

## 🛡️ Authorization

### Basic Authentication

```python
@mcp.tool()
@require_auth
async def protected_tool(ctx) -> str:
    return f"Hello {ctx.auth.user.name}!"
```

### Scope-based Authorization

```python
@mcp.tool()
@require_scope("admin")
async def admin_tool(ctx) -> str:
    return "Admin operation"
```

### User-based Authorization

```python
@mcp.tool()
@require_user(domain="company.com")
async def company_tool(ctx) -> str:
    return "Company-only tool"

@mcp.tool()
@require_user(provider="microsoft")
async def microsoft_only(ctx) -> str:
    return "Microsoft users only"
```

## 📚 Documentation

- **Setup Guides**: Provider-specific setup instructions
- **API Reference**: Complete API documentation
- **Examples**: Working examples for each provider
- **Security**: Best practices and security considerations

## 🔗 Provider Setup

### Microsoft Entra ID

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Active Directory** → **App registrations**
3. Create new registration
4. Add redirect URI: `http://localhost:8000/oauth/callback`
5. Generate client secret
6. Configure API permissions: `User.Read`, `openid`, `profile`, `email`

### Google OAuth

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create OAuth 2.0 credentials
3. Add redirect URI: `http://localhost:8000/oauth/callback`
4. Configure OAuth consent screen

### GitHub OAuth

1. Go to GitHub Settings → Developer settings → OAuth Apps
2. Create new OAuth app
3. Set Authorization callback URL: `http://localhost:8000/oauth/callback`

## 🧪 Testing

```python
# Test with MCP Inspector
npx @modelcontextprotocol/inspector http://localhost:8000/sse
```

## 📄 License

MIT License - see LICENSE file for details.

## 🤝 Contributing

Contributions welcome! Please read our contributing guidelines.

## 🔧 Development

```bash
git clone https://github.com/peterlarnholt/fastmcp-oauth.git
cd fastmcp-oauth
pip install -e ".[dev]"
pytest
```