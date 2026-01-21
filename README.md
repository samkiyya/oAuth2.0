# OAuth 2.0/2.1 Authorization Server with OpenID Connect

A complete, production-ready OAuth 2.0/2.1 Authorization Server implementation with OpenID Connect support, Multi-Factor Authentication, and Device Authorization Grant.

**Tech Stack**: TypeScript, Express 5, MongoDB, Redis, jose, PKCE, JWT (RS256)

---

## 🚀 Features

### OAuth 2.0/2.1 Grants
| Grant Type | RFC | Description |
|------------|-----|-------------|
| Authorization Code + PKCE | RFC 7636 | Web & mobile apps (PKCE required per OAuth 2.1) |
| Client Credentials | RFC 6749 | Machine-to-machine |
| Refresh Token | RFC 6749 | Token refresh with rotation |
| **Device Authorization** | RFC 8628 | TV, IoT, CLI apps |

### OpenID Connect
- Discovery (`/.well-known/openid-configuration`)
- JWKS (`/.well-known/jwks.json`)
- ID Tokens with standard claims
- UserInfo endpoint

### Additional Features
| Feature | RFC/Standard |
|---------|-------------|
| Token Revocation | RFC 7009 |
| Token Introspection | RFC 7662 |
| Dynamic Client Registration | RFC 7591 |
| **TOTP Multi-Factor Auth** | RFC 6238 |

### Security
- RS256 JWT signing with key rotation
- PKCE (S256 only) - OAuth 2.1 compliant
- Refresh token rotation with family tracking
- Account lockout after failed attempts
- Rate limiting per endpoint
- Helmet security headers
- Zod input validation
- Structured logging with correlation IDs

---

## 📁 Project Structure

```
oauth2.0/
├── packages/
│   ├── shared-types/        # TypeScript type definitions
│   └── shared-utils/        # Logger, crypto, validation, errors
├── auth-server/             # Authorization Server (port 3000)
├── client-app/              # Demo OAuth Client (port 3001)
├── resource-server/         # Protected API (port 3002)
├── k8s/                     # Kubernetes manifests
├── docs/                    # OpenAPI specification
├── .github/workflows/       # CI/CD pipelines
└── docker-compose.yml       # Local development
```

---

## ⚡ Quick Start

### Prerequisites
- Node.js 20+
- pnpm 9+
- Docker & Docker Compose

### Option 1: Docker (Recommended)
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f
```

### Option 2: Manual Development
```bash
# Install dependencies
pnpm install

# Build shared packages
pnpm build:packages

# Copy environment files
cp auth-server/.env.example auth-server/.env
cp client-app/.env.example client-app/.env
cp resource-server/.env.example resource-server/.env

# Start infrastructure
docker-compose up -d mongodb redis

# Run all services
pnpm dev
```

### Test the Flow
1. Open http://localhost:3001
2. Click "Login with OAuth"
3. Register at http://localhost:3000/register
4. Authorize the application
5. View dashboard with tokens
6. Test protected API calls

---

## 📖 API Documentation

### Discovery Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-configuration` | GET | OIDC Discovery |
| `/.well-known/jwks.json` | GET | JSON Web Key Set |

### OAuth Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/authorize` | GET | Authorization |
| `/token` | POST | Token exchange |
| `/revoke` | POST | Token revocation |
| `/introspect` | POST | Token introspection |
| `/userinfo` | GET | User information |
| `/register` | POST | Client registration |

### Device Flow
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/device/code` | POST | Get device code |
| `/device` | GET | User verification page |

### User Management
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/login` | GET/POST | User login |
| `/register` | GET/POST | User registration |
| `/logout` | GET/POST | Logout |
| `/mfa/setup` | GET/POST | Enable MFA |
| `/mfa/verify` | GET/POST | Verify MFA |

### Resource Server
| Endpoint | Method | Scope | Description |
|----------|--------|-------|-------------|
| `/api/v1/profile` | GET | profile | User profile |
| `/api/v1/user` | GET | email | User data |
| `/api/v1/resources` | GET | read | Protected resources |
| `/health` | GET | - | Health check |

Full OpenAPI 3.1 spec: [docs/openapi.yaml](./docs/openapi.yaml)

---

## 🔐 OAuth 2.0 Flow Example

### Authorization Code with PKCE

```javascript
// 1. Generate PKCE values
const codeVerifier = crypto.randomBytes(32).toString('base64url');
const codeChallenge = crypto.createHash('sha256')
  .update(codeVerifier).digest('base64url');

// 2. Redirect to authorization
const authUrl = new URL('http://localhost:3000/authorize');
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', 'your-client-id');
authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
authUrl.searchParams.set('scope', 'openid profile email');
authUrl.searchParams.set('code_challenge', codeChallenge);
authUrl.searchParams.set('code_challenge_method', 'S256');
authUrl.searchParams.set('state', crypto.randomBytes(16).toString('hex'));

// 3. Exchange code for tokens
const tokenResponse = await fetch('http://localhost:3000/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: 'received-auth-code',
    redirect_uri: 'http://localhost:3001/callback',
    client_id: 'your-client-id',
    code_verifier: codeVerifier,
  }),
});
```

---

## ⚙️ Configuration

### Auth Server
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | 3000 | Server port |
| `ISSUER` | Yes | - | OAuth issuer URL |
| `MONGODB_URI` | Yes | - | MongoDB connection |
| `REDIS_URL` | Yes | - | Redis connection |
| `SESSION_SECRET` | Yes | - | Session encryption (32+ chars) |
| `JWT_ACCESS_TOKEN_EXPIRES_IN` | No | 15m | Access token TTL |
| `JWT_REFRESH_TOKEN_EXPIRES_IN` | No | 7d | Refresh token TTL |

### Client App
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AUTH_SERVER_URL` | Yes | - | Auth server URL |
| `CLIENT_ID` | Yes | - | OAuth client ID |
| `CLIENT_SECRET` | Yes | - | OAuth client secret |
| `REDIRECT_URI` | Yes | - | Callback URL |

### Resource Server
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AUTH_SERVER_URL` | Yes | - | Auth server URL |
| `AUDIENCE` | Yes | - | Expected JWT audience |
| `CORS_ORIGINS` | No | - | Allowed CORS origins |

---

## 🧪 Testing

```bash
pnpm test              # Run all tests
pnpm test:unit         # Unit tests only
pnpm test:coverage     # With coverage report
```

---

## 🐳 Production Deployment

### Docker Build
```bash
docker-compose -f docker-compose.yml build
```

### Kubernetes
```bash
# Apply base resources
kubectl apply -k k8s/base

# Apply production overlay
kubectl apply -k k8s/overlays/production
```

---

## 📄 License

MIT