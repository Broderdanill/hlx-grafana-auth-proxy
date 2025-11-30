# Helix Grafana Auth Proxy  

FastAPI-based authentication and integration layer between **BMC Helix** and **Grafana**.

This project provides a secure authentication proxy and a Helix → Grafana synchronization layer.  
It enables:

- Login via **BMC Helix** (Local credentials)
- Login via **BMC RSSO** (SSO / Trusted Authentication via HTTP header)
- Impersonated AR REST API requests using a Helix service account
- Automatic creation of Grafana users (via auth proxy)
- Automatic creation and syncing of Grafana teams based on Helix Groups
- Automatic assignment of Grafana roles based on Helix Group List
- Webhook-driven updates for User + Group changes
- Persistent storage of dashboards via PVC

The proxy and Grafana run together inside a single Pod.

---

## 1. Architecture

```text
Browser
   │
   ▼
(Reverse Proxy + optional RSSO)
   │   X-RSSO-USER=<login>
   ▼
Helix Grafana Auth Proxy (FastAPI)
   │   X-WEBAUTH-USER=<login>
   │   X-WEBAUTH-ROLE=<Viewer|Editor|Admin>
   │   X-WEBAUTH-GROUPS=<team1,team2,...>
   ▼
Grafana
```

The Auth Proxy acts as:

### Authentication Gateway  
- Local login (`AUTH_MODE=local`)
- RSSO header-based auth (`AUTH_MODE=rsso`)
- Grafana never sees passwords — only trusted headers  
  (`X-WEBAUTH-USER`, `X-WEBAUTH-ROLE`, `X-WEBAUTH-GROUPS`)

### Helix Impersonation Layer  
All data source queries use:

- AR-JWT from a Helix service account
- `X-AR-Impersonated-User: <base64(username)>`

So Helix REST calls are executed as the logged-in user, but authenticated using the service account.

### Team & Role Synchronization Engine  

Based on Helix Group membership:

- Creates missing Grafana Teams
- Updates Team names on change
- Adds/Removes user memberships in Teams
- Maps Helix Groups → Grafana roles (Viewer / Editor / Admin)

### Webhook Endpoints  

Helix Webhook events POST to:

- `/webhook/grafana/user`
- `/webhook/grafana/team`

These endpoints update Grafana Users + Teams in real time.

---

## 2. Containers

Inside one Pod:

| Container                  | Description                                  |
|---------------------------|----------------------------------------------|
| **grafana**               | Grafana UI + data source plugins             |
| **hlx-grafana-auth-proxy**| FastAPI app doing auth + Helix integration   |

Internal communication:

```text
Grafana → http://127.0.0.1:8080/helix-api   # JSON API plugin → proxy → Helix
Proxy   → http://127.0.0.1:3000             # Proxy → Grafana HTTP API
```

---

## 3. Configuration Overview

Most config is done via:

- `ConfigMap` for non-secret values
- `Secret` for passwords / tokens
- Pod `envFrom` to load both into the auth proxy

### 3.1 Authentication Modes

```text
AUTH_MODE=local     # Login page served by proxy
AUTH_MODE=rsso      # No login page; trust RSSO header
RSSO_HEADER_NAME=X-RSSO-USER
```

In `local` mode:

- `/login` is available
- Proxy authenticates against `HELIX_JWT_LOGIN_URL`
- A cookie is set (`HLX_USER`) and used to resolve the username

In `rsso` mode:

- `/login` is effectively bypassed (only for diagnostics)
- Reverse proxy in front must inject a user header, e.g.:

```http
X-RSSO-USER: dice
```

The value **must match** the Helix “Login Name” field so group lookups work.

---

## 4. Environment Variables

### 4.1 Helix Configuration

```text
HELIX_BASE_URL=http://arserver:8008
HELIX_JWT_LOGIN_URL=http://arserver:8008/api/jwt/login
HELIX_ALLOWED_FORMS=User,Group
HELIX_USER_FORM=User
HELIX_USER_LOGIN_FIELD=Login Name
HELIX_USER_GROUP_FIELD=Group List
HELIX_DEFAULT_GRAFANA_ROLE=Viewer
```

- `HELIX_ALLOWED_FORMS` is a comma-separated whitelist of forms
  that can be queried via `/helix-api/<form-name>`.
- `HELIX_USER_FORM`, `HELIX_USER_LOGIN_FIELD`, `HELIX_USER_GROUP_FIELD`
  control how the proxy looks up group membership for a user.

### 4.2 Group → Role / Team Mapping

```text
HELIX_GROUP_ROLE_MAPPING="400001:Viewer,400002:Editor,400003:Admin,410001:GrafanaRole01,410002:GrafanaRole02"
```

- Entries mapping to `Viewer` / `Editor` / `Admin` are used as **Grafana Org Roles**.
- All other entries are treated as **Grafana Teams / Groups**:
  - e.g. `410001:GrafanaRole01` → Helix Group ID `410001` maps to Grafana Team named `GrafanaRole01`.

Internally this is split into two dictionaries:

- `GROUP_ROLE_MAPPING`: groupID → role (Viewer / Editor / Admin)
- `GROUP_TEAM_MAPPING`: groupID → teamName (non-role entries)

### 4.3 Service Account + Secrets

From a Kubernetes `Secret` (or Podman equivalent):

```text
HELIX_ADMIN_USER
HELIX_ADMIN_PASSWORD
WEBHOOK_SHARED_SECRET
GRAFANA_API_TOKEN   # optional if you want static token instead of bootstrap
```

- `HELIX_ADMIN_USER` / `HELIX_ADMIN_PASSWORD` are used to obtain an AR-JWT token from Helix.
- `WEBHOOK_SHARED_SECRET` is validated inside the webhook payload (`shared_secret` field).
- `GRAFANA_API_TOKEN` is used to call Grafana’s admin API to create/update users and teams.

### 4.4 Logging

```text
LOG_LEVEL=DEBUG | INFO | WARNING | ERROR | CRITICAL
```

---

## 5. Webhook Behavior

The proxy exposes two main webhook endpoints which Helix should call via **AR System Webhook Registration**.

### 5.1 `/webhook/grafana/user`

Handles:

- New user creation in Grafana
- Updates of user display name / email
- Role recalculation based on `Group List`
- Team membership sync based on group → team mapping

Expected JSON structure from Helix:

```json
{
  "record_id": "AGG...",
  "webhook_id": "WBH000000000603",
  "entry_details": {
    "Login Name": "dice",
    "Full Name": "Dice User",
    "Email Address": "dice@example.com",
    "Group List": "1;400003;410002;"
  },
  "action": "update",
  "shared_secret": "super-hemligt-värde-här",
  "entry_event": "Update",
  "form_name": "User",
  "entry_id": "000000000001581"
}
```

**Security:**  
- The proxy **reads `shared_secret` from the JSON body** and compares it with `WEBHOOK_SHARED_SECRET`.  
- If they differ or are missing → **401 Unauthorized**.

**What happens inside:**
1. Log the incoming request at DEBUG (method, URL, headers, body).  
2. Validate `shared_secret`.  
3. Parse the payload into a `UserSyncPayload` model.  
4. Lookup Grafana user via `/api/users/lookup?loginOrEmail=<login>`.  
5. If `action == "delete"`:
   - Delete the user in Grafana via `/api/admin/users/{id}`.  
6. If `action == "create"` and user does not exist:
   - Create user via `/api/admin/users`.  
7. Update basic user info (name, email).  
8. Compute Grafana org role:
   - Parse `Group List` → pick best role using `ROLE_PRIORITY`.  
9. Compute teams from groups:
   - Using `GROUP_TEAM_MAPPING` and `TEAM_ID_MAP`.  
10. Sync membership:
    - Add user to teams they should be in.  
    - Remove user from teams they no longer belong to.  

Returns a JSON summary:

```json
{
  "status": "ok",
  "user_id": 3,
  "role": "Admin",
  "update_status": 200,
  "role_status": 200,
  "teams": {
    "added": [...],
    "removed": [...],
    "missing_teams": []
  }
}
```

### 5.2 `/webhook/grafana/team`

Handles:

- Creating/updating/deleting Grafana Teams (mapping from Helix Group)
- Keeping `TEAM_ID_MAP` up to date: `groupId → grafanaTeamName`
- Triggering resync of user memberships for that group

Expected JSON structure:

```json
{
  "record_id": "AGG...",
  "webhook_id": "WBH000000000601",
  "entry_details": {
    "Group Name": "GRP_Grafana_FolderPermission01",
    "Group ID": 410001
  },
  "action": "update",
  "shared_secret": "super-hemligt-värde-här",
  "entry_event": "Update",
  "form_name": "Group",
  "entry_id": "000000100007862",
  "email": "noreply@example.com"
}
```

Notes:

- `Group ID` might come as an `int` or `string`; the proxy normalizes it to `str`.
- `shared_secret` is again validated against `WEBHOOK_SHARED_SECRET`.

Internal flow:

1. Log incoming request.  
2. Validate `shared_secret`.  
3. Parse payload into `TeamSyncPayload`.  
4. Attempt to find Grafana team by name via `/api/teams/search?name=<Group Name>`.  
5. If `action == "delete"`:
   - If exists → delete via `/api/teams/{teamId}`.  
   - Remove entry from `TEAM_ID_MAP`.  
6. If `action == "create"` and team does not exist:
   - Create via `POST /api/teams`.  
7. If `action in ("create", "update")`:
   - Ensure team email/name is up to date.  
   - Update `TEAM_ID_MAP[group_id] = group_name`.  
   - Call `resync_users_for_group_id(group_id)` to ensure all relevant users are added to this team.  

Return example:

```json
{
  "status": "ok",
  "team_id": 2,
  "update_status": 200,
  "group_id": "410001"
}
```

---

## 6. Sync Logic – Users, Roles and Teams

### 6.1 Role selection (`pick_role_from_groups`)

Given a `Group List` such as:

```text
"1;400003;12321;"
```

and a mapping:

```text
400001:Viewer,400002:Editor,400003:Admin
```

The function:

1. Splits by `;` and cleans empty parts.  
2. For each Group ID in the list:
   - Checks if it exists in `GROUP_ROLE_MAPPING`.  
   - Chooses the highest priority according to `ROLE_PRIORITY` (`Admin > Editor > Viewer`).  

If no matched roles are found, falls back to `HELIX_DEFAULT_GRAFANA_ROLE`.

### 6.2 Team selection (`pick_teams_from_groups`)

Given a `Group List` and the combination of:

- Static `GROUP_TEAM_MAPPING` from environment  
- Dynamic `TEAM_ID_MAP` updated by team webhooks

it produces a list of Grafana team names the user should be a member of.

### 6.3 Caching

The proxy caches:

- `_ROLE_CACHE[username] = role`
- `_GROUP_LIST_CACHE[username] = groupList`
- `_TEAM_CACHE[username] = "comma,separated,teams"`

to avoid excessive Helix or Grafana calls.

### 6.4 Resync on new team (`resync_users_for_group_id`)

To handle the case where:

- Users already have a Helix group ID in their `Group List`, but  
- The Grafana team for that group was created later

the proxy does:

1. When `/webhook/grafana/team` is processed and a group_id is known:  
   - Update `TEAM_ID_MAP[group_id] = teamName`.  
   - Call `resync_users_for_group_id(group_id)`.  
2. `resync_users_for_group_id` calls Helix to find all users whose `Group List` contains that group ID, e.g.:  
   - `'Group List' LIKE "%;410002;%"`  
3. For each such user:
   - Update `_GROUP_LIST_CACHE[login]`  
   - Call `sync_user_teams_for_login(login, group_list)` which:  
     - Ensures existing Grafana user  
     - Looks up all desired team IDs  
     - Adds/removes membership accordingly  

This makes the system robust against ordering issues (user updated before team exists, etc.) and against pod restarts.

---

## 7. Grafana Data Source Usage (JSON API Plugin)

Grafana is configured with the **marcusolsson-json-datasource** plugin pointing at:

```text
http://127.0.0.1:8080/helix-api
```

### 7.1 Path

The path in the data source query corresponds to the Helix form name:

```text
/User
/Group
```

Full URL called by Grafana:

```text
http://127.0.0.1:8080/helix-api/User
```

### 7.2 Fields

Helix REST returns (simplified):

```json
{
  "entries": [
    {
      "values": {
        "Login Name": "dice",
        "Full Name": "Dice User",
        "Group List": "1;400003;410002;"
      }
    }
  ]
}
```

In the JSON API plugin, you may reference:

```text
entries[*].values["Full Name"]
entries[*].values["Login Name"]
entries[*].values["Group List"]
```

### 7.3 Recommended Transformations

- **Group by** for counting incidents/users/groups.  
- **Organize fields** to rename and reorder fields.  
- **Filter data by query** to limit output.  

---

## 8. Authentication Flows

### 8.1 Local Login Mode (`AUTH_MODE=local`)

1. Unauthenticated user requests `/` (Grafana).  
2. Proxy doesn’t see any username (no `X-Grafana-User`, no RSSO header, no cookie).  
3. User is redirected to `/login`.  
4. `/login` presents an HTML form (username/password).  
5. On submit, proxy calls `HELIX_JWT_LOGIN_URL` with `username`/`password`.  
6. If Helix returns 200, the user is considered authenticated:  
   - Proxy sets cookie `HLX_USER=<loginName>`.  
7. Subsequent requests:
   - `resolve_username()` picks up `HLX_USER` cookie.  
   - Role + teams are computed from Helix groups.  
   - Headers are set to Grafana:  
     ```http
     X-WEBAUTH-USER: <login>
     X-WEBAUTH-ROLE: <role>
     X-WEBAUTH-GROUPS: team1,team2
     ```  

### 8.2 RSSO Mode (`AUTH_MODE=rsso`)

In RSSO mode, there is **no login page**. Instead:

1. Browser hits front-end reverse proxy (Apache/Nginx) at e.g. `https://grafana.example.com/`.  
2. RSSO module forces authentication (Kerberos, LDAP, SAML, OIDC, etc.).  
3. After success, RSSO sets a server-side identity (`REMOTE_USER`).  
4. Reverse proxy forwards it to the FastAPI proxy in a header, e.g.:  
   ```http
   X-RSSO-USER: dice
   ```  
5. FastAPI proxy reads `RSSO_HEADER_NAME` and uses that as the login name.  
6. Remaining steps are identical to local mode: Helix group fetch, role/teams mapping, Grafana auth proxy headers.

If no user header is present in `rsso` mode, the proxy responds with 401 and an explanation instead of redirecting to `/login`.

---

## 9. RSSO Integration Guide (Trusted Authentication)

This container supports **RSSO Trusted Authentication** using a header (`X-RSSO-USER`) sent from a reverse proxy that is integrated with BMC RSSO.

### 9.1 Configure the container

In your ConfigMap (or env vars):

```text
AUTH_MODE=rsso
RSSO_HEADER_NAME=X-RSSO-USER
```

### 9.2 Configure RSSO (Realm → Agents)

In the RSSO Admin Console:

1. Go to **Realm → Agents**.  
2. Click **Add Agent**.  
3. Choose **Agent Type: Trusted Agent / Web Agent** (depending on version).  
4. Set e.g.:  
   - **Agent ID:** `grafana-proxy`  
   - **Host URL:** `https://grafana.example.com/`  
   - **Trusted Authentication:** Enabled  
5. Under **Mapped Attributes**, ensure that an attribute representing Helix Login Name is available (e.g. `sAMAccountName`, `userPrincipalName`, or another mapped attribute).  
6. Under **Trusted Agents / Allowed Hosts**, add the front-end reverse proxy host/IP as trusted.  
7. Save changes.

The RSSO agent is now permitted to cosign/authenticate web requests for Grafana.

### 9.3 Configure Reverse Proxy

Your front-end reverse proxy (Apache/Nginx/etc.) sits **in front** of the FastAPI proxy and is the one talking to RSSO. Once RSSO has authenticated the request and set `REMOTE_USER`, the proxy forwards this into a header.

#### Apache Example

```apache
# RSSO configuration (simplified, real config depends on BMC module)
RSSOAgentID grafana-proxy
RSSOEnableAuth On

# Require authenticated user
Require valid-user

# Forward username from REMOTE_USER to backend
RequestHeader set X-RSSO-USER %{REMOTE_USER}s

# Proxy to FastAPI auth proxy
ProxyPass        / http://helix-grafana-pod:8081/
ProxyPassReverse / http://helix-grafana-pod:8081/
```

#### Nginx Example

```nginx
location / {
    # RSSO auth happens before / outside this block, so $remote_user is set.
    proxy_set_header X-RSSO-USER $remote_user;
    proxy_pass http://helix-grafana-pod:8081;
}
```

### 9.4 Verify

1. Log in via browser using SSO.  
2. Check FastAPI logs (LOG_LEVEL=DEBUG) for lines like:

```text
resolve_username: headers={... 'X-RSSO-USER': 'dice', ...}
get_grafana_role_for_user: user=dice, role=Admin
```

3. User should land inside Grafana without ever seeing `/login`.  

---

## 10. Persistent Storage

Grafana stores data (dashboards, users, teams when using built-in auth) in:

```text
/var/lib/grafana
```

The Pod uses a `PersistentVolumeClaim` such as:

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: grafana-disk-pvc
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
```

and mounts it into the Grafana container:

```yaml
volumeMounts:
  - name: grafana-storage
    mountPath: /var/lib/grafana
```

This ensures dashboards persist across restarts.

---

## 11. Running the Pod (Podman/Kubernetes)

### 11.1 Start

```bash
podman play kube helix-grafana-with-config.yaml
```

or in Kubernetes:

```bash
kubectl apply -f helix-grafana-with-config.yaml
```

### 11.2 Update Configuration

After editing the ConfigMap or Secret, restart the Pod (example with Podman):

```bash
podman play kube --down helix-grafana-with-config.yaml
podman play kube helix-grafana-with-config.yaml
```

or in Kubernetes:

```bash
kubectl rollout restart pod/helix-grafana-pod
```

---

## 12. Optional Startup Full Sync (Design)

> **Note:** This is an optional enhancement, not implemented by default.

To avoid losing in-memory caches at pod restart and to guarantee full consistency even before any webhook fires, you can design a background “full sync” routine:

1. On startup, the proxy calls Helix to:  
   - Fetch all users (or relevant subset).  
   - Fetch all groups / teams used in Grafana.  
2. For each user:  
   - Determine Helix group list.  
   - Determine Grafana role + teams.  
   - Ensure Grafana user exists and is configured.  
3. For each group ID mapped to a team:  
   - Ensure Grafana team exists.  
   - Ensure all matching users are members.  

After the full sync, the existing webhook logic keeps everything up-to-date incrementally.

---

## 13. Troubleshooting

### 13.1 Webhook returns 401 (Invalid or missing X-Webhook-Token / shared_secret)

- Ensure your Helix webhook payload contains the JSON field:  
  ```json
  "shared_secret": "<WEBHOOK_SHARED_SECRET>"
  ```
- Ensure the value matches the environment variable `WEBHOOK_SHARED_SECRET` in the auth proxy.  
- NOTE: This implementation validates the **body field**, not a header like `X-Webhook-Token`.

### 13.2 User created but not added to team

Possible causes:

- The Helix group was not mapped in `HELIX_GROUP_ROLE_MAPPING`.  
- The Grafana team for a group ID did not exist when the user webhook ran (fixed by team-webhook + `resync_users_for_group_id`).  
- `Group List` field didn’t contain the expected group ID (`410002` etc.).  

Check logs:

- `/webhook/grafana/user` logs group list and computed teams.  
- `/webhook/grafana/team` logs `TEAM_ID_MAP[groupId] = teamName`.  

### 13.3 RSSO: Getting 401 from proxy in `AUTH_MODE=rsso`

- Check that the reverse proxy is actually setting `X-RSSO-USER`.  
- Confirm `RSSO_HEADER_NAME` matches the header name.  
- Ensure RSSO agent configuration (trusted app, allowed host) is correct.  
- With `LOG_LEVEL=DEBUG`, the proxy logs all incoming headers.

### 13.4 Grafana API key invalid

If logs show:

```text
[info] Failed to authenticate request [api-key.invalid]
```

then:

- The `GRAFANA_API_TOKEN` is missing or incorrect.  
- Create a new API key in Grafana (Admin → Service Accounts or API Keys).  
- Update the Secret / env var in your Pod and restart the auth proxy.  

---

## 14. Summary

The **Helix Grafana Auth Proxy** provides:

- Secure Helix-based authentication for Grafana (local or RSSO)
- Helix impersonation for REST API calls
- Dynamic role and team mapping from Helix Groups
- Webhook-driven user and team synchronization
- Optional robust resync patterns for production environments
- Persistent Grafana storage via PVC
- A clean separation of concerns: Helix as identity/role provider, Grafana as visualization

You can start minimal (local login, basic mapping) and gradually grow into:

- RSSO-based SSO
- Full webhook integration
- Advanced team and folder permission concepts driven 100% by Helix data.