
# API Reference – hlx-grafana-auth-proxy

This document defines every public HTTP endpoint exposed by the **Helix Grafana Auth Proxy**, including authentication behavior, request/response models, role propagation, and error codes.

---

# 1. Overview

The proxy exposes four primary API domains:

| Domain | Purpose |
|--------|---------|
| **/login** | Local authentication against Helix JWT |
| **/helix-api/** | Impersonated data queries to Helix forms |
| **/webhook/grafana/** | Webhooks from Helix (User/Group sync) |
| **/internal/** | Internal Grafana API proxy helpers |

Every endpoint supports:  
- JSON request bodies  
- JSON responses  
- Standardized error format  

---

# 2. Authentication Endpoints

## 2.1 `POST /login` (local mode only)

Authenticates the user using Helix JWT login.

### Request Body
```json
{
  "username": "demo",
  "password": "P@ssw0rd"
}
```

### Response
```json
{
  "status": "ok",
  "user": "demo"
}
```

### Errors
| Code | Meaning |
|------|---------|
| 401 | Invalid credentials |
| 503 | Helix unavailable |

---

# 3. Helix API Proxy Endpoints

Form queries are routed through:

## 3.1 `GET /helix-api/<form>`

Fetches Helix entries impersonating the logged-in user.

### Example
```
GET /helix-api/User?fields=Login%20Name,Full%20Name
```

### Response Sample
```json
{
  "entries": [
    {
      "entryId": "000000000000123",
      "values": {
        "Login Name": "demo",
        "Full Name": "Demo User"
      }
    }
  ]
}
```

### Errors
| Code | Meaning |
|------|---------|
| 403 | Form not in HELIX_ALLOWED_FORMS |
| 401 | Not authenticated |
| 502 | Helix error |

---

# 4. Webhook Endpoints

Used by Helix AR System Webhook Registration.

## 4.1 `POST /webhook/grafana/user`

Synchronizes a user (create/update/disable).

### Payload Example
```json
{
  "form_name": "User",
  "entry_details": {
    "Login Name": "demo",
    "Full Name": "Demo User",
    "Email Address": "demo@example.com",
    "Group List": "1;400002;400003;"
  },
  "shared_secret": "<secret>"
}
```

### Behavior
- Validates secret  
- Maps groups → roles  
- Creates or updates Grafana user  
- Syncs team memberships  
- Returns 200 on success  

---

## 4.2 `POST /webhook/grafana/team`

Synchronizes a group/team.

### Payload Example
```json
{
  "form_name": "Group",
  "entry_details": {
    "Group Name": "GRP_Grafana_Editors",
    "Group ID": "400002"
  },
  "shared_secret": "<secret>"
}
```

### Behavior
- Ensures Grafana team exists  
- Updates team display name  
- Sync membership for all known users  

---

# 5. Internal Proxy Endpoints

These are never called by users. Only the system calls them.

## 5.1 `GET /internal/grafana/userlookup?login=<name>`

Looks up (or creates) user in Grafana.

Response:
```json
{
  "exists": true,
  "id": 7
}
```

---

# 6. Error Format

Every error returns JSON:

```json
{
  "error": "Message",
  "details": "Optional details",
  "status": 400
}
```

---

# 7. Status Codes Reference

| Code | Meaning |
|------|---------|
| 200 | OK |
| 201 | Created (teams) |
| 204 | No Content |
| 400 | Validation error |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 409 | Conflict (duplicate team) |
| 500 | Internal Proxy Error |
| 502 | Helix API failure |

---

# 8. Rate Limits

The proxy currently has no built-in rate limiting but relies on:

- Grafana backend throttling
- Helix REST API limits
- Container-level CPU throttling

---

# 9. Webhook Delivery Guarantees

The proxy is fully stateless:  
- All sync is idempotent  
- Calling the same webhook twice is safe  
- On cold start, reconciliation re-synchronizes everything  

---

# 10. Future Extensions

Planned upcoming endpoints:

- `/webhook/grafana/roles`
- `/internal/helix/cache`
- `/session/debug`

---

This concludes the full API reference.