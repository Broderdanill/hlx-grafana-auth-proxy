
# RSSO / HSSO / OIDC Integration Guide
Helix Grafana Auth Proxy supports multiple enterprise-grade Single Sign-On patterns used in modern BMC Helix environments. This document provides a complete guide to configuring RSSO, HSSO, or full OIDC passthrough.

---

# 1. Overview

Helix SSO (RSSO/HSSO) is the authentication framework commonly deployed with BMC Helix.  
Your environment may include:

- **RSSO** (older Remote SSO server)
- **HSSO** (Helix Single Sign-On, Keycloak-based)
- **OIDC** provider behind HSSO (Keycloak, Azure AD, ADFS, Okta…)

The proxy supports three modes of integration:

| Mode | Description | Grafana OAuth? | Recommended |
|------|-------------|----------------|-------------|
| **RSSO Header Mode (`AUTH_MODE=rsso`)** | Identity is provided by reverse proxy via header | No | Good |
| **OIDC Passthrough (`AUTH_MODE=oidc`)** | Reverse proxy validates ID token, passes username | No | Excellent |
| **Local (`AUTH_MODE=local`)** | Proxy login screen, authenticates to Helix directly | No | Test/dev |

All modes still use:
- Helix group lookup  
- Role mapping  
- Team/user synchronization via webhooks  

---

# 2. RSSO / HSSO Header-Based Authentication

This is the simplest form of SSO: the user logs in to RSSO/HSSO outside the container, the reverse proxy injects a trusted header such as:

```
X-RSSO-USER: <helix-login-name>
```

The auth proxy:
1. Reads the header  
2. Validates it is present  
3. Looks up the user in Helix User form  
4. Extracts Group List  
5. Maps group → role  
6. Sends user + role to Grafana

## Required configuration

```
AUTH_MODE=rsso
RSSO_HEADER_NAME=X-RSSO-USER
```

### Reverse Proxy Examples

#### Apache
```
RequestHeader set X-RSSO-USER %{REMOTE_USER}s
ProxyPass / http://helix-grafana-pod:8081/
ProxyPassReverse / http://helix-grafana-pod:8081/
```

#### NGINX
```
proxy_set_header X-RSSO-USER $remote_user;
proxy_pass http://helix-grafana-pod:8081;
```

### When to choose this mode
- You already run RSSO/HSSO  
- You want seamless login  
- You don’t want redirects to Grafana login page  

### Limitations
- Reverse proxy must strictly protect the header  
- No ID token validation  
- Identity is based on HTTP trust, not cryptography  

---

# 3. OIDC Passthrough Mode (Recommended for Production)

This mode leverages your existing HSSO OIDC realm without turning Grafana into an OAuth client.

### Architecture flow

1. User authenticates to **HSSO (Keycloak)** via application in your environment  
2. Reverse proxy validates ID token received from HSSO  
3. Reverse proxy injects header (e.g., `X-OIDC-USER`) containing a validated username claim  
4. Helix Grafana Auth Proxy receives header  
5. Proxy performs Helix group lookup → role mapping  
6. Grafana receives external identity

### Why Passthrough, not Grafana OAuth?

Because:
- Grafana OAuth makes Grafana the login “master”  
- You would lose user impersonation and webhook syncing  
- Grafana OAuth does *not* integrate with Helix group model  
- Proxy-based identity preserves all current logic  

### Required settings

```
AUTH_MODE=oidc
OIDC_HEADER_NAME=X-OIDC-USER
OIDC_ISSUER_URL=https://hsso.example.com/auth/realms/myrealm
OIDC_CLIENT_ID=<stored in Secret>
OIDC_CLIENT_SECRET=<stored in Secret>
```

The proxy does **not** perform a full OAuth redirect.  
Instead:
- It validates ID token signature & issuer (optional mode)
- Extracts username from header
- Continues flow as in RSSO mode

### Reverse Proxy Example (OIDC Token Forwarding)

#### Apache + mod_auth_openidc
```
OIDCProviderMetadataURL https://hsso.example.com/auth/realms/myrealm/.well-known/openid-configuration
OIDCClientID grafana-proxy
OIDCClientSecret <secret>
OIDCRedirectURI https://grafana.example.com/redirect_uri
OIDCRemoteUserClaim preferred_username

RequestHeader set X-OIDC-USER %{OIDC_CLAIM_preferred_username}e
ProxyPass / http://helix-grafana-pod:8081/
```

#### NGINX + lua + introspection (enterprise setups)
```
proxy_set_header X-OIDC-USER $oidc_preferred_username;
proxy_pass http://helix-grafana-pod:8081;
```

---

# 4. Claim Mapping

Common HSSO/Keycloak claims:

| Claim | Meaning | Suitable? |
|-------|---------|-----------|
| `preferred_username` | Actual login name | ✔️ Best choice |
| `sub` | Internal UUID | ❌ No |
| `email` | Email | Maybe |
| `upn` | AD identity | Works if same as Helix login |

You must ensure the forwarded username matches the **Helix User Form → Login Name** field.

---

# 5. Handling Sessions

Neither RSSO nor OIDC Passthrough requires the proxy to maintain its own session.

Your reverse proxy handles:
- ID token refresh  
- SSO cookies  
- Logout redirects  

The auth proxy receives only the identity.

For logout, reverse proxy can rewrite `/logout` to your HSSO logout endpoint.

---

# 6. Security Recommendations

### 1. Protect headers strictly
Upstream servers must guarantee:
- Headers **cannot** be spoofed by clients  
- Only trusted proxies can reach the auth proxy  
- HTTPS enforced  

### 2. Use K8s Secrets for OIDC credentials
```
apiVersion: v1
kind: Secret
metadata:
  name: oidc-client
stringData:
  OIDC_CLIENT_ID: grafana-proxy
  OIDC_CLIENT_SECRET: <secret>
```

### 3. Use IP allowlists (optional)
Allow only:
- Reverse proxy  
- Grafana container  
- Helix server  

### 4. Token expiration awareness
OIDC tokens typically last 5–15 minutes.  
Reverse proxy must refresh automatically.

---

# 7. Troubleshooting

| Symptom | Cause | Fix |
|--------|-------|------|
| 401 Missing OIDC header | Proxy misconfigured | Ensure `X-OIDC-USER` is forwarded |
| Username not found in Helix | Claim mismatch | Use `preferred_username` |
| Wrong role | Group List mapping wrong | Fix `HELIX_GROUP_ROLE_MAPPING` |
| Endless redirects | Reverse proxy misrouting | Verify proxy path & cookies |

---

# 8. End-to-End Flow Diagram

**OIDC Passthrough Mode**

1. User → Reverse proxy  
2. Reverse proxy authenticates via HSSO  
3. Reverse proxy validates ID token  
4. Reverse proxy injects `X-OIDC-USER`  
5. Auth proxy → fetches user from Helix  
6. Auth proxy → calculates role  
7. Auth proxy → forwards headers to Grafana  
8. Grafana logs user in

---

# 9. See Also

- `02-authentication-modes.md`  
- `03-helix-integration.md`  
- `05-webhooks.md`  
- `10-security.md`  