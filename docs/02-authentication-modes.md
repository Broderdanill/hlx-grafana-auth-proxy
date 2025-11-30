
# Authentication Modes  
Helix Grafana Auth Proxy supports three authentication strategies designed for different deployment environments and security models. All modes share the same internal authorization logic, Helix group mapping, and Grafana provisioning flow.

---

# 1. Local Authentication (Username + Password Against Helix)
In this mode, users authenticate through a dedicated login page served by the auth proxy.

## How It Works
1. User accesses Grafana → proxy intercepts → redirects to `/login`
2. User enters Helix credentials
3. Proxy sends credentials to **Helix JWT Login API**
4. Proxy retrieves AR-JWT and user metadata
5. Proxy evaluates group → Grafana role mapping
6. Proxy injects  
   - `X-WEBAUTH-USER`  
   - `X-WEBAUTH-ROLE`  
   - optional `X-WEBAUTH-GROUPS`  
7. Grafana trusts the request and logs the user in

## Required Settings
```
AUTH_MODE=local
HELIX_JWT_LOGIN_URL=http://arserver:8008/api/jwt/login
```

## When to Use
- Test/lab environments  
- Environments without RSSO/HSSO  
- Lightweight deployments

---

# 2. RSSO / HSSO Header-Based Authentication (“Passthrough Mode”)

This mode trusts an external reverse proxy or identity provider to authenticate the user.  
Your reverse proxy adds:

```
X-RSSO-USER: <loginName>
```

The proxy does not perform credential checks.  
Instead, it only:
- extracts the username from the header  
- queries Helix for groups  
- maps groups → role  
- forwards user + role to Grafana

## Required Settings
```
AUTH_MODE=rsso
RSSO_HEADER_NAME=X-RSSO-USER
```

## Reverse Proxy Examples

### Apache
```
RequestHeader set X-RSSO-USER %{REMOTE_USER}s
ProxyPass / http://your-proxy:8081/
ProxyPassReverse / http://your-proxy:8081/
```

### NGINX
```
proxy_set_header X-RSSO-USER $remote_user;
proxy_pass http://your-proxy:8081;
```

## When to Use
- You already run RSSO/HSSO in your environment  
- You want SSO but do **not** want Grafana to be an OAuth client  
- Seamless login without redirects

---

# 3. Passthrough OIDC from RSSO/HSSO (ID Token Forward Mode)

This is **not** Grafana OAuth — Grafana remains unaware.  
Instead:
- RSSO/HSSO performs the OIDC authentication
- Reverse proxy extracts the ID token (JWT)
- Reverse proxy forwards a verified claim (e.g., loginName) as header:

```
X-OIDC-USER: <sub or preferred_username>
```

- Auth proxy trusts **only** the username, not the whole ID token
- Auth proxy performs group lookup in Helix as usual

## Required Settings
```
AUTH_MODE=oidc
OIDC_HEADER_NAME=X-OIDC-USER
OIDC_CLIENT_ID=<stored in Secret>
OIDC_CLIENT_SECRET=<stored in Secret>
OIDC_ISSUER_URL=https://rsso.example.com/auth/realms/<realm>
```

## Comparison vs RSSO Header Mode
| Feature | RSSO/HSSO Header | OIDC Passthrough |
|--------|------------------|------------------|
| Requires reverse proxy | Yes | Yes |
| Uses ID token | No | Yes (but only validated, not forwarded) |
| Stronger identity assurance | Medium | High |
| Grafana involved in OAuth? | No | No |
| Recommended for production | ✔️ | ✔️✔️ |

---

# 4. Choosing the Right Authentication Mode

| Use Case | Best Mode |
|----------|-----------|
| Simple on-prem test | `local` |
| Existing RSSO/HSSO deployment | `rsso` |
| Strong identity, federation, or MFA | `oidc` |
| Want Grafana login screen removed | `rsso` or `oidc` |
| Want full user impersonation in Helix (always supported) | All modes |

---

# 5. Switching Authentication Mode

Simply change the environment variable and redeploy:

```
AUTH_MODE=rsso   # or local / oidc
```

The proxy automatically:
- switches middleware  
- enables/disables login UI  
- changes which headers are accepted  
- updates request validation logic

No changes needed in Grafana.

---

# 6. Security Notes

- Never send RSSO/OIDC headers directly from a browser  
- Always place a reverse proxy in front  
- Use HTTPS offloading  
- Rotate OIDC secrets in Kubernetes Secrets  
- Consider adding IP allowlists for trusted upstreams  

---

# 7. See also
- `03-helix-integration.md` – How group lookup works  
- `05-webhooks.md` – Automatic user/team sync  
- `06-rsso-hsso-oidc.md` – Deep dive with diagrams  