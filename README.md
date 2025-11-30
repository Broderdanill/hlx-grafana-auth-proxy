
# Helix Grafana Auth Proxy  
### Secure Authentication · Role Mapping · Helix Integration · Team & User Sync · Webhooks · OIDC/RSSO/HSSO Support

---

## 1. Overview

Helix Grafana Auth Proxy is a fully integrated authentication, authorization, and identity‑mapping layer built for **Grafana**, **BMC Helix ITSM**, and **RSSO/HSSO** environments.  
It ensures that:

- Users authenticate against **Helix** (local login) or **RSSO/HSSO** (OIDC or Header-based SSO).
- Users always receive the correct **Grafana role** based on Helix groups.
- User and team lifecycle events are synchronized via **Helix Webhooks**.
- Grafana dashboards persist via PVC storage.
- All Helix REST API calls impersonate the logged‑in user.

It consists of:

1. **Grafana**
2. **hlx-grafana-auth-proxy (FastAPI)**

Both run in the same Pod and communicate over localhost.

---

# 2. Key Features

### ✔ Local login (AUTH_MODE=local)  
Users authenticate via a built-in login page using Helix JWT authentication.

### ✔ RSSO / HSSO header-based authentication (AUTH_MODE=rsso)  
Users authenticated by RSSO/HSSO upstream load-balancer are passed into the proxy automatically.

### ✔ OIDC upstream authentication (AUTH_MODE=oidc-header)  
Proxy trusts an upstream OpenID Connect agent (RSSO/HSSO or reverse proxy) and reads username from headers.

### ✔ Automatic user & team provisioning in Grafana  
Helix webhooks send:
- User updates  
- Group updates  

The proxy ensures:
- Matching Grafana users exist
- Matching teams exist
- Membership is synchronized
- Roles are updated

### ✔ Group → Role Mapping in ConfigMap  
Map Helix group IDs to Grafana Viewer/Editor/Admin roles.

### ✔ Whitelisted Helix Forms  
Only approved Helix forms can be queried from Grafana.

### ✔ Secure impersonation  
Every Helix REST call uses:
- JWT from a Helix service account  
- `X-AR-Impersonated-User: <logged in user>`

### ✔ Persistent storage  
Grafana’s SQLite DB is mounted to a PVC.

---

# 3. Architecture

```
+---------------------+
|   End User          |
+----------+----------+
           |
           v
+---------------------+       +---------------------------+
| Reverse Proxy /     |       | RSSO / HSSO / OIDC IdP   |
| Load Balancer       |<----->| (optional)               |
| (sets headers)      |       +---------------------------+
+----------+----------+
           |
           v
+---------------------------+
| hlx-grafana-auth-proxy   |
|  - Auth (local/RSSO/OIDC) |
|  - Helix impersonation    |
|  - User/Team Sync         |
+-----------+---------------+
            |
 localhost   |
            v
+---------------------------+
|         Grafana           |
| Auth Proxy Mode Enabled   |
+---------------------------+
```

---

# 4. Authentication Modes

The proxy supports 3 authentication modes:

---

## 4.1 AUTH_MODE=local (Default)

Users authenticate using:
```
POST /login
username=...
password=...
```

The proxy:
- Logs in to Helix via `/api/jwt/login`
- Stores user session cookie
- Sets X-WEBAUTH-USER + X-WEBAUTH-ROLE headers for Grafana

---

## 4.2 AUTH_MODE=rsso (Legacy RSSO)

Upstream RSSO injects:

```
X-RSSO-USER: <login>
```

Proxy trusts header and skips login page.

Config:

```
AUTH_MODE=rsso
RSSO_HEADER_NAME=X-RSSO-USER
```

---

## 4.3 AUTH_MODE=oidc-header (Recommended for HSSO/RSSO OIDC)

This is the modern method.

Your reverse proxy / HSSO agent authenticates the user via OIDC and injects:

```
X-OIDC-USER: <subject or login>
X-OIDC-EMAIL: <optional>
X-OIDC-NAME: <optional>
```

Proxy settings:

```
AUTH_MODE=oidc-header
OIDC_HEADER_USER=X-OIDC-USER
OIDC_HEADER_EMAIL=X-OIDC-EMAIL
OIDC_HEADER_NAME=X-OIDC-NAME
```

The proxy does **not** do OAuth itself — it trusts the upstream agent.

---

# 5. Webhooks — Helix → Proxy → Grafana

The proxy exposes:

```
POST /webhook/grafana/user
POST /webhook/grafana/team
```

Helix sends JSON payloads for user and group changes.

### 5.1 User Payload Example
```
{
  "action": "update",
  "shared_secret": "...",
  "entry_details": {
      "Login Name": "john",
      "Full Name": "John Doe",
      "Email Address": "john@company.com",
      "Group List": "1;400003;410002;"
  }
}
```

### 5.2 Team Payload Example
```
{
  "action": "update",
  "entry_details": {
    "Group Name": "GRP_Grafana_DevOps",
    "Group ID": "410002"
  }
}
```

The proxy:

- Creates user in Grafana (if missing)
- Updates role based on `Group List`
- Creates teams if needed
- Adds/removes users to/from teams

---

# 6. Group → Role Mapping

In ConfigMap:

```
HELIX_GROUP_ROLE_MAPPING: "400001:Viewer,400002:Editor,400003:Admin"
```

If user belongs to multiple mapped groups:
- Highest role wins (`Admin > Editor > Viewer`)

If no match:
- Fallback:
```
HELIX_DEFAULT_GRAFANA_ROLE=Viewer
```

---

# 7. Helix REST Integration

The proxy:

- Logs in using Helix admin service account (JWT)
- Uses:
```
X-AR-Impersonated-User: <logged in user>
```
- Queries Helix forms only if listed in:
```
HELIX_ALLOWED_FORMS="User,Group,..."
```

---

# 8. Deployment (Podman/Kubernetes)

The repo contains a `hlx-grafana-auth-proxy-pod.yaml` that runs:

- Grafana
- Auth Proxy

Both share:
- ConfigMap
- Secrets
- PVC storage

You deploy with:

```
podman play kube hlx-grafana-auth-proxy-pod.yaml
```

Update config:

```
podman play kube --down hlx-grafana-auth-proxy-pod.yaml
podman play kube hlx-grafana-auth-proxy-pod.yaml
```

---

# 9. Configuration Files

## 9.1 ConfigMap
Contains:
- AUTH_MODE
- Helix URLs
- Role mappings
- Whitelisted forms
- OIDC header mappings

## 9.2 Secrets
Contains:
- HELIX_ADMIN_USER
- HELIX_ADMIN_PASSWORD
- WEBHOOK_SHARED_SECRET
- OIDC_CLIENT_ID (optional future)
- OIDC_CLIENT_SECRET (optional future)

## 9.3 PVC
Stores Grafana state.

---

# 10. OIDC Integration (RSSO / HSSO)

### Why OIDC-header mode?
Because HSSO provides the identity — not Grafana.

### Requirements:
1. Configure HSSO realm with OIDC client  
2. Configure your reverse proxy to authenticate users  
3. Proxy injects headers:
```
X-OIDC-USER
X-OIDC-EMAIL
X-OIDC-NAME
```
4. Auth proxy uses them just like RSSO header mode

This is the recommended setup for enterprise identity.

---

# 11. Full Documentation

All expanded documentation is available in the `docs/` directory:

- [00 – Introduction](docs/00-introduction.md)
- [01 – Deployment Guide](docs/01-deployment.md)
- [02 – Authentication Modes](docs/02-authentication-modes.md)
- [03 – Helix Integration](docs/03-helix-integration.md)
- [04 – Grafana Integration](docs/04-grafana-integration.md)
- [05 – Webhooks](docs/05-webhooks.md)
- [06 – RSSO / HSSO / OIDC Guide](docs/06-rsso-hsso-oidc.md)
- [07 – Architecture Overview](docs/07-architecture.md)
- [08 – Troubleshooting](docs/08-troubleshooting.md)
- [09 – API Reference](docs/09-api-reference.md)
- [10 – Security Guide](docs/10-security.md)

Each section contains detailed explanations, examples, diagrams, and configuration snippets.

---

# 12. Support & Contributions

Contributions and improvements are welcome!

Please open:
- Issues for bugs
- PRs for new features or documentation
- Discussions for design changes

