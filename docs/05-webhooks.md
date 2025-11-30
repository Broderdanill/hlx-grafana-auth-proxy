# Webhooks Integration Guide

This document provides a complete, detailed description of how the **Helix Grafana Auth Proxy** integrates with BMC Helix via Webhooks.  
User and Group synchronization is a core part of keeping Grafana’s state aligned with Helix.

---

# 1. Overview

BMC Helix AR System Webhooks allow the platform to notify external systems when specific forms are created, updated, or deleted.  
The proxy uses these notifications to keep **Grafana users**, **teams**, and **team memberships** synchronized automatically.

Supported webhook flows:

- **User Sync**  
  - Create user  
  - Update user  
  - Disable user  
  - Update group membership  

- **Group/Team Sync**  
  - Create team in Grafana  
  - Rename team  
  - Sync user membership into teams  

All webhook calls are authenticated using a **shared secret**.

---

# 2. Webhook Format (Helix → Proxy)

Helix sends JSON like:

```json
{
  "record_id": "AGGB7Y82DDNI2ATGG2PZTGG2PZ2SN2",
  "webhook_id": "WBH000000000603",
  "entry_details": {
    "Login Name": "dice",
    "Full Name": "Dice User",
    "Email Address": "dice@example.com",
    "Group List": "1;400003;410002;"
  },
  "action": "update",
  "shared_secret": "super-secret-example",
  "entry_event": "Update",
  "form_name": "User",
  "entry_id": "000000000001581"
}
```

Group webhook example:

```json
{
  "record_id": "AGGD859EFAN7WATG9L4QTG9L4QNBZC",
  "webhook_id": "WBH000000000601",
  "entry_details": {
    "Group Name": "GRP_Grafana_Admins",
    "Group ID": "400003"
  },
  "action": "update",
  "shared_secret": "super-secret-example",
  "entry_event": "Update",
  "form_name": "Group",
  "entry_id": "000000100007862",
  "email": "noreply@me.com"
}
```

---

# 3. Shared Secret Authentication

Each webhook contains:

```
"shared_secret": "<your-value>"
```

Your proxy compares this to:

```
WEBHOOK_SHARED_SECRET
```

If incorrect → returns **401 Unauthorized**.

---

# 4. Endpoints

The proxy exposes:

| Endpoint | Purpose |
|---------|---------|
| `POST /webhook/grafana/user` | Sync users (create/update/disable) |
| `POST /webhook/grafana/team` | Sync groups/teams and memberships |

### Example request:

```
POST http://<proxy>:8080/webhook/grafana/user
Content-Type: application/json
```

---

# 5. User Sync Logic

### 5.1 Create or Update User

The proxy does:

1. Validate secret  
2. Parse JSON  
3. Look up Grafana user via API  
4. If not found → **create user**  
5. Update:  
   - Display name  
   - Email  
   - Role (Viewer, Editor, Admin)  
6. Sync team memberships based on `Group List`

### 5.2 Disable User

If “Status” or similar field indicates disabled → user is set to:

- Disabled in Grafana  
- Removed from teams  

---

# 6. Group/Team Sync Logic

Performed when form_name=`Group`.

### 6.1 Team creation flow
1. Validate secret  
2. Check if team exists in Grafana  
3. If missing → create team  
4. Update team name if changed  
5. Set metadata (e.g., external reference ID)

### 6.2 Membership Sync

The proxy uses:

```
Group List → Grafana team membership
```

If a user belongs to `410002`, the webhook ensures:

- Team exists  
- User is added  

If user no longer belongs → removed.

---

# 7. Cold Start Recovery

At startup, the proxy can run:

```
/sync/full
```

Which:

- Lists all Helix Users  
- Lists all Helix Groups  
- Validates all Grafana users  
- Validates all team memberships  
- Creates missing teams  
- Fixes role assignments  
- Removes stale memberships  

This ensures the proxy survives restarts even without historical webhooks.

---

# 8. Error Handling

| Code | Meaning |
|------|---------|
| 200 | Successfully processed |
| 400 | Validation error (field missing) |
| 401 | Invalid shared secret |
| 404 | Team not found / user not found |
| 500 | Unexpected exception |

All errors are logged.

Example:

```
2025-11-30 ERROR Validation error: Login Name is required
```

---

# 9. Security Notes

- Secrets never logged  
- Webhook secret must be stored in Kubernetes Secret  
- Ensure IP restrictions if Helix runs outside cluster  
- Prefer HTTPS + authentication proxy if external exposure required  

---

# 10. Webhook Setup in Helix AR System

Navigate to:

```
AR System Administration Console → Webhook Registration
```

Fields to set:

| Field | Value |
|-------|-------|
| **URL** | `http://<proxy>:8080/webhook/grafana/user` (or `/team`) |
| **HTTP Method** | POST |
| **Content-Type** | application/json |
| **Payload** | default |
| **Headers** | (leave empty – proxy does not rely on headers) |
| **Shared Secret** | must match `WEBHOOK_SHARED_SECRET` |

---

# 11. Example Curl Tests

### User webhook test

```bash
curl -X POST http://localhost:8081/webhook/grafana/user   -H "Content-Type: application/json"   -d '{
        "shared_secret": "super-secret",
        "form_name": "User",
        "entry_details": {
          "Login Name": "testuser",
          "Full Name": "Test User",
          "Email Address": "test@example.com",
          "Group List": "400003;410002;"
        }
      }'
```

### Group webhook test

```bash
curl -X POST http://localhost:8081/webhook/grafana/team   -H "Content-Type: application/json"   -d '{
        "shared_secret": "super-secret",
        "form_name": "Group",
        "entry_details": {
          "Group Name": "GRP_Grafana_Viewers",
          "Group ID": "400001"
        }
      }'
```

---

# 12. Appendix – Troubleshooting Webhooks

### Missing “Login Name”
Ensure the webhook form includes:

- Login Name  
- Full Name  
- Email Address  
- Group List  

### Unexpected 401  
Shared secret mismatch.

### Grafana returns 404 “team not found”
Create team form event may have failed; check logs.

### Double membership
Resolve by running:
```
/sync/full
```

---

End of Webhook Integration Guide.