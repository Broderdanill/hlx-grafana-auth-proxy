# 03 – Helix Integration Guide

## Overview
This document explains how the Helix Grafana Auth Proxy integrates with **BMC Helix AR System** for:
- Authentication (local login via AR-JWT)
- Impersonated REST API access
- User and group synchronization
- Webhook-driven real‑time updates
- Role mapping and team provisioning in Grafana

This guide assumes familiarity with:
- Helix AR REST API
- Helix forms and field IDs
- Helix permissions model
- JWT authentication flows

---

# 1. Helix Authentication Model

The proxy supports two Helix-facing authentication modes:

### **1. Local login (default)**
User logs into `/login` with:
- Helix *Login Name*
- Helix password

The proxy exchanges these credentials with Helix at:
```
POST /api/jwt/login
```
and receives an `AR-JWT` token.

This token is then used for:
- Fetching the user record
- Querying group membership
- Impersonated REST requests

---

# 2. Service Account (Admin User)

Several actions require a privileged Helix user:
- Reading any Helix form
- Resolving group membership
- Creating/Updating users/roles in Grafana (via webhook integration)
- Validating impersonation flows

These credentials are stored in `helix-admin-credentials` secret:
```
HELIX_ADMIN_USER
HELIX_ADMIN_PASSWORD
```

The proxy logs in automatically at startup and caches the resulting JWT.

---

# 3. Impersonated REST API Access

The proxy issues REST API queries with:
```
X-AR-Impersonated-User: <helix login name>
Authorization: AR-JWT <admin jwt>
```

This allows:
- Row-level permissions to function correctly
- Dashboards to show only the data the Helix user is allowed to see
- Full auditing with Helix seeing the *real* user

Example call to `/helix-api/User`:
```
GET /helix-api/User?_pageSize=100
X-Grafana-User: dice
```

Internal proxy call:
```
GET /api/arsys/v1/entry/User
Authorization: AR-JWT eyJhb...
X-AR-Impersonated-User: dice
```

---

# 4. Allowed Forms

The proxy restricts which Helix forms Grafana may query:
```
HELIX_ALLOWED_FORMS=User,Group,HPD:IncidentInterface
```

If Grafana’s JSON datasource calls a form not in the whitelist:
→ `403 Forbidden` is returned.

This prevents dashboard creators from querying sensitive forms unless explicitly enabled.

---

# 5. User Lookup Flow

When a user logs in (local or OIDC/RSSO mode), the proxy fetches:

### **1. User entry**
From form:
```
HELIX_USER_FORM=User
```

### **2. Login field**
```
HELIX_USER_LOGIN_FIELD=Login Name
```

### **3. Groups field**
```
HELIX_USER_GROUP_FIELD=Group List
```

Example REST response:
```
"values": {
  "Login Name": "dice",
  "Full Name": "Daniel",
  "Group List": "1;400003;410002;"
}
```

---

# 6. Group → Grafana Role Mapping

Configured in:
```
HELIX_GROUP_ROLE_MAPPING="400003:Admin,400002:Editor,400001:Viewer"
```

Evaluation order:
1. Parse Helix group list  
2. Match any group ID from the mapping  
3. Assign *highest privilege* role found  
4. If none match → use fallback  
```
HELIX_DEFAULT_GRAFANA_ROLE=Viewer
```

---

# 7. Webhook Integration (User Sync)

The following webhook is created in Helix:
```
URL: http://<proxy>/webhook/grafana/user
Method: POST
Headers:
  X-Webhook-Token: <secret>
```

When User form changes, Helix sends:
```
{
  "entry_event": "Update",
  "entry_details": {
    "Login Name": "dice",
    "Full Name": "Daniel",
    "Email Address": "daniel@example.com",
    "Group List": "1;400003;410002;"
  }
}
```

The proxy then:
1. Updates Grafana user (auto-create if missing)  
2. Assigns correct role  
3. Assigns team memberships based on group list  

---

# 8. Webhook Integration (Group Sync)

Group changes are sent to:
```
/webhook/grafana/team
```

Example payload:
```
{
  "entry_event": "Update",
  "entry_details": {
    "Group Name": "GRP_Grafana_ReportEditors",
    "Group ID": "410002"
  }
}
```

The proxy ensures:
- Team exists in Grafana
- Membership for all users is updated

---

# 9. Initial Sync Logic (Cold Start Recovery)

If the pod restarts, user → team relations might not reflect prior webhook events.

To avoid this:
- Proxy scans all users on startup
- For each user, fetches group list
- Ensures each team exists
- Assigns user to correct Grafana teams

This ensures consistency even after:
- Pod redeployment
- PVC restoration
- Grafana DB rebuild

---

# 10. Example Configuration

### Environment variables (ConfigMap)
```
HELIX_BASE_URL=http://arserver:8008
HELIX_JWT_LOGIN_URL=http://arserver:8008/api/jwt/login
HELIX_ALLOWED_FORMS=User,Group
HELIX_USER_FORM=User
HELIX_USER_LOGIN_FIELD=Login Name
HELIX_USER_GROUP_FIELD=Group List
HELIX_GROUP_ROLE_MAPPING=400003:Admin,400002:Editor,400001:Viewer
```

### Secrets
```
HELIX_ADMIN_USER=Demo
HELIX_ADMIN_PASSWORD=P@ssw0rd
WEBHOOK_SHARED_SECRET=supersecret
```

---

# 11. Troubleshooting

### Issue: “Not authorized to get entry”
Cause: impersonation user lacks permission  
Fix: verify permissions for:
- Base form
- Row-level permissions
- Field-level permissions

### Issue: "403 Forbidden – Form not allowed"
Fix: Add form to allowed list:
```
HELIX_ALLOWED_FORMS=User,Group,YourForm
```

### Issue: Wrong role assigned
Check:
- User’s Group List
- HELIX_GROUP_ROLE_MAPPING

---

# 12. Summary

The proxy integrates Helix and Grafana by:
- Using AR-JWT for login
- Proxying all REST calls with impersonation
- Mapping Helix groups to Grafana roles
- Syncing users and teams in real time
- Maintaining consistency after restarts

This ensures:
✔ Full Helix security model  
✔ Minimal configuration in Grafana  
✔ Automatic role + team assignment  
✔ Stable enterprise-ready integration  
