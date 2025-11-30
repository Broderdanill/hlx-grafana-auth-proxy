# Helix Grafana Auth Proxy  
FastAPI-based authentication and integration layer between **BMC Helix** and **Grafana**

This project provides a secure authentication proxy and a Helix → Grafana synchronization layer.  
It enables:

- Login via **BMC Helix** (Local credentials)  
- Login via **BMC RSSO** (SSO header mode)  
- Impersonated AR REST API requests using a Helix service account  
- Automatic creation of Grafana users (via auth proxy)  
- Automatic creation and syncing of Grafana teams based on Helix Groups  
- Automatic assignment of Grafana roles based on Helix Group List  
- Webhook-driven updates for User + Group changes  
- Persistent storage of dashboards via PVC  

The proxy and Grafana run together inside one Pod.

---

# 1. Architecture

```
Browser
   │
   ▼
(Reverse Proxy + optional RSSO)
   │   X-RSSO-USER=<login>
   ▼
Helix Grafana Auth Proxy (FastAPI)
   │   X-WEBAUTH-USER=<login>
   │   X-WEBAUTH-ROLE=<Viewer|Editor|Admin>
   ▼
Grafana
```

The Auth Proxy acts as:

### ✔ Authentication Gateway  
- Local login (`AUTH_MODE=local`)  
- RSSO header-based auth (`AUTH_MODE=rsso`)  
- Grafana never sees passwords — only trusted headers  

### ✔ Helix Impersonation Layer  
All data source queries use:
- AR-JWT from service account  
- `X-AR-Impersonated-User: <username>`  

### ✔ Team & Role Synchronization Engine  
Based on Helix Groups:
- Creates missing Grafana Teams  
- Updates Team names  
- Adds/Removes user memberships  
- Maps Helix → Grafana roles  

### ✔ Webhook Endpoint  
Helix Webhook events POST to:

```
/webhook/grafana/user
/webhook/grafana/team
```

---

# 2. Containers

| Container | Description |
|----------|-------------|
| **Grafana** | The UI |
| **hlx-grafana-auth-proxy** | Auth + Helix integration |

Communication:
```
Grafana → http://127.0.0.1:8080/helix-api
Proxy → http://127.0.0.1:3000
```

---

# 3. Configuration

## 3.1 Authentication Modes
```
AUTH_MODE=local
AUTH_MODE=rsso
RSSO_HEADER_NAME=X-RSSO-USER
```

---

# 4. Environment Variables

### Required
```
HELIX_BASE_URL
HELIX_JWT_LOGIN_URL
HELIX_ALLOWED_FORMS
HELIX_USER_FORM
HELIX_USER_LOGIN_FIELD
HELIX_USER_GROUP_FIELD
HELIX_DEFAULT_GRAFANA_ROLE
```

### Group → Role Mapping
```
HELIX_GROUP_ROLE_MAPPING="400001:Viewer,400002:Editor,400003:Admin"
```

### Secrets
```
HELIX_ADMIN_USER
HELIX_ADMIN_PASSWORD
WEBHOOK_SHARED_SECRET
GRAFANA_API_TOKEN
```

---

# 5. Webhook Behavior

### `/webhook/grafana/user`
Handles new users, updates, group list changes.

### `/webhook/grafana/team`
Handles team creation, rename, membership recompute.

Headers required:
```
Content-Type: application/json
```

JSON must include:
```
"shared_secret": "<WEBHOOK_SHARED_SECRET>"
```

---

# 6. Webhook Examples

## User Webhook Example
```json
{
  "record_id":"AGG...",
  "webhook_id":"WBH000000000603",
  "entry_details":{
    "Login Name":"dice",
    "Full Name":"Dice M",
    "Email Address":"dice@example.com",
    "Group List":"1;400003;410002;"
  },
  "action":"update",
  "shared_secret":"super-secret",
  "entry_event":"Update",
  "form_name":"User",
  "entry_id":"000000000001581"
}
```

## Group Webhook Example
```json
{
  "record_id":"AGG...",
  "webhook_id":"WBH000000000601",
  "entry_details":{
    "Group Name":"GRP_Grafana_FolderPermission01",
    "Group ID":"410001"
  },
  "action":"update",
  "shared_secret":"super-secret",
  "entry_event":"Update",
  "form_name":"Group",
  "entry_id":"000000100007862",
  "email":"noreply@me.com"
}
```

---

# 7. Grafana Data Source Usage

```
/helix-api/<form-name>
```

Field access:
```
entries[*].values.Full Name
entries[*].values.Login Name
entries[*].values["Group List"]
```

---

# 8. Authentication Flows

## Local Mode
- User visits `/login`
- Authenticate via Helix JWT
- Proxy sets cookie
- Grafana receives headers

## RSSO Mode
Reverse proxy must set:
```
X-RSSO-USER: dice
```

Proxy uses this as authenticated identity.

---

# 9. Team Sync & Membership Logic

### Implemented Today
- User webhook triggers membership updates  
- Team webhook also triggers recompute  
- Membership = from `Group List` field  

This keeps state correct **as long as both user and group webhooks fire**.

---

# 10. Optional Startup Full Sync (Recommended)

Not implemented unless added manually.

Proposed behavior:
1. Load all Helix users  
2. Load all groups  
3. Ensure all Grafana teams exist  
4. Sync membership and roles  
5. Save state cache  

This prevents “lost state” on Pod restart.

---

# 11. Running the Pod

Start:
```
podman play kube helix-grafana-with-config.yaml
```

Restart:
```
podman play kube --down helix-grafana-with-config.yaml
podman play kube helix-grafana-with-config.yaml
```

---

# 12. RSSO Integration Guide

## 1. Set ENV
```
AUTH_MODE=rsso
RSSO_HEADER_NAME=X-RSSO-USER
```

## 2. In RSSO Admin Console
- Create application  
- Point it to your auth realm  
- Ensure login attribute matches Helix “Login Name”  

## 3. Reverse Proxy Configuration

### Apache
```apache
RequestHeader set X-RSSO-USER %{REMOTE_USER}s
ProxyPass / http://helix-grafana-pod:8081/
ProxyPassReverse / http://helix-grafana-pod:8081/
```

### Nginx
```nginx
proxy_set_header X-RSSO-USER $remote_user;
proxy_pass http://helix-grafana-pod:8081;
```

## 4. Verify
Proxy logs should show:
```
resolve_username: X-RSSO-USER=dice
```

---

# 13. Persistent Storage

Grafana uses:
```
/var/lib/grafana
```

Mounted via:
```
grafana-disk-pvc
```

---

# 14. Summary

This container provides:

- Secure Helix-based Authentication  
- RSSO support  
- Impersonated Helix REST API  
- Automatic Team + Role sync  
- Webhook-driven updates  
- Optional startup full sync  
- Persistent Grafana data  

All inside a single Pod for easy deployment.
