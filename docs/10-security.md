# Security Guide – Helix Grafana Auth Proxy

This document details the full security model for the Helix Grafana Auth Proxy, including authentication flows, data protection, secrets management, authorization, webhook validation, and best practices.

---

# 1. Security Architecture Overview

The proxy enforces strict separation of:

- **Authentication** (Local JWT, RSSO/HSSO header mode, or OIDC)
- **Authorization** (Helix group → Grafana role mapping)
- **Data Access Control** (Impersonated Helix requests)
- **User & Team Lifecycle Sync** (via validated webhooks)
- **Secret-bound trust relationships** (Helix ↔ Proxy ↔ Grafana)

All entry paths (login, datasource requests, webhooks, internal APIs) use dedicated validation, context propagation, and sanitization layers.

---

# 2. Authentication Security

## 2.1 Local Login (AUTH_MODE=local)
- Users authenticate using credentials stored in **Helix**.
- Proxy exchanges username/password for a **Helix JWT** via:
  ```
  POST /api/jwt/login
  ```
- JWT is never exposed to the browser; session tokens remain server-side.
- Passwords are never logged.

**Risks mitigated:**
- No passwords stored in Grafana.
- No client-side JWT leakage.

---

## 2.2 RSSO/HSSO Header Mode (AUTH_MODE=rsso)
The reverse proxy in front of the container injects:
```
X-RSSO-USER: <helix-login-name>
```

Security relies on:
- Reverse proxy enforcing trusted network boundaries.
- Only authenticated users receiving that header.
- Proxy rejecting all requests missing the header.

**Risks mitigated:**
- Credentials never touch the container.
- No reliance on browser cookies.
- Header spoofing blocked by internal network isolation.

---

## 2.3 RSSO/HSSO OIDC Mode (AUTH_MODE=oidc)

OIDC tokens are validated using:
- Issuer (`OIDC_ISSUER_URL`)
- Client credentials (`OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`)
- Signature (JWKS)
- Audiences
- Expiration and nonce

Token fields used:
```
preferred_username
email
groups (optional)
```

**Risks mitigated:**
- Token forgery resistance (JWKS signature)
- Replay protection (nonce)
- Session hijacking prevention (exp/iat validation)

---

# 3. Authorization Security

Grafana roles are determined exclusively through **Helix groups**, never user input.

Example mapping:
```
400001: Viewer
400002: Editor
400003: Admin
```

Rules:
- User cannot escalate their own permissions.
- Proxy always recomputes role on every login event.
- If no valid role found → user is downgraded to Viewer.
- Role is conveyed through `X-WEBAUTH-ROLE`.

**Risks mitigated:**
- Prevents privilege escalation.
- Prevents stale role assignments.
- Ensures Helix is the single authoritative group source.

---

# 4. Webhook Security

Helix calls two webhook endpoints:
```
/webhook/grafana/user
/webhook/grafana/team
```

## 4.1 Shared Secret Validation
Every webhook must include:
```json
"shared_secret": "<value>"
```
Matched against:
```
WEBHOOK_SHARED_SECRET
```

Requests failing validation return:
```
401 Unauthorized
```

## 4.2 Payload Validation
- Pydantic enforces strict field schemas.
- Group IDs and Login Names must be strings.
- Unknown forms are rejected.

**Risks mitigated:**
- Prevents spoofing
- Prevents malformed injections
- Ensures only valid Helix-origin data is processed

---

# 5. Impersonation Security

All Helix REST API calls are performed using:
- A service account AR-JWT token  
- Impersonated user via header:  
  ```
  X-AR-Impersonated-User: <login>
  ```

Guarantees:
- User only reads what they are allowed inside Helix.
- Proxy cannot read data not available to the impersonated user.
- Prevents privilege escalation by design.

---

# 6. Grafana API Security

Grafana operations require:
```
GRAFANA_API_TOKEN
```
stored in a Kubernetes/POD secret.

Token is used for:
- Creating/Updating users
- Creating/Updating teams
- Assigning memberships

Security rules:
- Token must be admin-level.
- Token never exposed to user traffic.
- Token only used server-side via internal API calls.

---

# 7. Secret Management

The following secrets must always be stored in Kubernetes secrets:

- `HELIX_ADMIN_USER`
- `HELIX_ADMIN_PASSWORD`
- `WEBHOOK_SHARED_SECRET`
- `GRAFANA_API_TOKEN`
- `OIDC_CLIENT_ID`
- `OIDC_CLIENT_SECRET`

These secrets:
- Are never logged.
- Are never exposed to clients.
- Are only read on container startup.

---

# 8. Transport Security

**Recommended deployment:**
- Reverse proxy terminates HTTPS.
- Pod communicates internally via trusted networks.
- All external ingress uses TLS 1.2+.

**Not recommended:**
- Exposing the auth proxy directly to the internet.
- Using plain HTTP outside internal networks.

---

# 9. Threat Model

The proxy protects against:

| Threat | Protected? | Notes |
|--------|------------|-------|
| Password theft | Yes | Password never reaches Grafana |
| Header spoofing | Yes | Requires trusted internal network |
| Token forgery | Yes | OIDC validation w/ signature |
| Privilege escalation | Yes | Helix authoritative for roles |
| Webhook spoofing | Yes | Shared secret + schema verification |
| Replay attacks | Partial | OIDC prevents; webhooks idempotent |
| User injection | Yes | Strict Pydantic schemas |

---

# 10. Security Best Practices

### 10.1 Harden Reverse Proxy
- Strip all inbound `X-*` headers from public traffic.
- Inject SSO headers only after auth is complete.

### 10.2 Harden RSSO/HSSO
- Use HTTPS only.
- Short token lifetimes.
- Strong client secrets.
- Audit authentication failures.

### 10.3 Harden Grafana
- Use unique admin API key.
- Restrict admin API key usage to proxy-only.
- Disable anonymous mode in Grafana.
- Disable basic auth if using proxy auth.

### 10.4 Harden Helix Integration
- Ensure your service account has minimal required permissions.
- Use impersonation for all user-specific queries.

---

# 11. Logging & Monitoring

### Logged:
- Authentication decisions
- Webhook sync operations
- Impersonation actions
- Grafana API errors
- Helix API errors

### Not Logged:
- Passwords  
- Tokens  
- Secrets  
- Sensitive field values  

---

# 12. Final Notes

The system is designed under strict principles:

- **No sensitive data leaves Helix**
- **Grafana trusts only the proxy**
- **The proxy trusts only Helix, OIDC issuer, and RSSO agent**
- **Users cannot influence their own permissions**
- **All sync operations are idempotent and replay‑safe**

This produces a secure, centralized, tamper‑resistant integration for enterprise environments.
