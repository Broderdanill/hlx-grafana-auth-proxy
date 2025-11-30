# Grafana Integration Guide

## 1. Overview
This document explains how Grafana integrates with the **Helix Grafana Auth Proxy**, including:
- Authentication flow
- Authorization model (roles & teams)
- Provisioning
- Data source configuration
- API token usage
- Expected request/response patterns

---

## 2. Authentication Flow in Grafana
Grafana itself does **not** authenticate users directly when using this proxy. Instead:

1. User accesses Grafana endpoint (proxied through `/` on the auth proxy)
2. Proxy performs one of the following depending on `AUTH_MODE`:
   - **local** → internal login page, validates against Helix JWT auth
   - **rsso** → reverse-proxy-injected header, `X-RSSO-USER`
   - **oidc** → HSSO/RSSO-backed OpenID Connect validation
3. Proxy determines the final user identity and group list
4. Proxy sets:
   - `X-WEBAUTH-USER`
   - `X-WEBAUTH-ROLE`
   - `X-WEBAUTH-GROUPS`
5. Grafana accepts these via **Auth Proxy** authentication mode

### Required Grafana Environment Variables
```yaml
GF_AUTH_PROXY_ENABLED: "true"
GF_AUTH_PROXY_HEADER_NAME: "X-WEBAUTH-USER"
GF_AUTH_PROXY_HEADER_PROPERTY: "username"
GF_AUTH_PROXY_AUTO_SIGN_UP: "false"
GF_AUTH_PROXY_HEADERS: "Role:X-WEBAUTH-ROLE,Groups:X-WEBAUTH-GROUPS"
```

---

## 3. Role Assignment
Proxy determines the Grafana role using:

- `HELIX_GROUP_ROLE_MAPPING`
- User’s Helix `Group List`

Mapping example in YAML:
```yaml
HELIX_GROUP_ROLE_MAPPING: "400001:Viewer,400002:Editor,400003:Admin"
```

Proxy logic picks the **highest privilege role** if multiple groups match.

---

## 4. Team Synchronization (Grafana Teams)
Grafana teams are created dynamically via webhook synchronization from Helix.

### Example Helix Group
```
Group Name: GRP_Grafana_Monitoring
Group ID: 410002
```

Proxy:
- Creates team if not exists
- Updates display name when changed
- Keeps a mapping cache
- Adds users to appropriate teams at login or via webhook

Teams created by the proxy always include metadata:
```
autoManaged: true
source: "helix"
sourceGroupId: 410002
```

---

## 5. Provisioned Data Source
The recommended data source is **marcusolsson-json-datasource**, configured to proxy all Helix API queries through:

```
http://127.0.0.1:8080/helix-api
```

### Example provisioning file
```yaml
apiVersion: 1

datasources:
  - name: Helix REST (JSON API)
    type: marcusolsson-json-datasource
    access: proxy
    url: http://127.0.0.1:8080/helix-api
    isDefault: false
    jsonData: {}
```

Grafana → Auth Proxy → Helix REST API

The proxy applies authentication and impersonation using `X-AR-Impersonated-User`.

---

## 6. Grafana API Token Management
The proxy **requires a Grafana API token** with admin permissions to:
- Look up users
- Create/modify teams
- Add team members

Token must be stored in a Kubernetes Secret:
```yaml
stringData:
  GRAFANA_API_TOKEN: "glsa_xyz..."
```

---

## 7. Grafana User Lifecycle
### When a user logs in:
1. Proxy receives username  
2. Looks up Helix user → retrieves groups  
3. Determines Grafana role  
4. Ensures user exists in Grafana  
5. Ensures team membership is correct  
6. Returns authenticated session to Grafana

### When webhooks update a user:
- Same logic as login, but executed headless

---

## 8. Common Queries in Grafana Dashboards
Examples (JSON Datasource):

### Query all users
```
/User
```

### Query specific fields
Transform:
```
entries[*].values.Full Name
entries[*].values.Login Name
entries[*].values.Group List
```

### Filtering
```json
{
  "query": {
    "qualification": "'Login Name'="alice""
  }
}
```

---

## 9. Troubleshooting Grafana Integration
### Login works but no dashboards visible
- User role missing → verify mapping in `HELIX_GROUP_ROLE_MAPPING`

### Teams not created
Check:
```
POST /webhook/grafana/team
```

### Users not joining teams
Verify:
- User’s `Group List` in Helix
- Team exists in Grafana
- Proxy logs: `TeamSync: member added`

### API Token Invalid
Grafana log will show:
```
API key is invalid
```
Fix:
- Regenerate API token
- Update Secret
- Restart pod

---

## 10. Summary
Grafana is not responsible for authentication — the proxy handles:
- Login (local, rsso, oidc)
- Role assignment
- Team creation
- Impersonated Helix queries

Grafana receives:
- Pre-authenticated identity
- Role
- Team membership
- A consistent data source

This creates a full Helix-managed RBAC model inside Grafana with no manual administration.