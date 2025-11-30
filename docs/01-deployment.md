
# Deployment Guide  
This guide describes how to deploy the **Helix Grafana Auth Proxy** and Grafana together as a unified Pod.  
It includes all required Kubernetes objects, configuration details, secrets, and deployment instructions.

---

# 1. Architecture Overview  

Deployment consists of a single Pod containing two containers:

| Component | Purpose |
|----------|---------|
| **Grafana** | Dashboard UI, JSON API data source |
| **Auth Proxy (FastAPI)** | Authentication, authorization, Helix integration, proxying |

The Pod also uses:
- **ConfigMap** – general configuration  
- **Secrets** – sensitive credentials  
- **PersistentVolumeClaim** – stores Grafana’s SQLite DB  
- **Helix Webhooks** – sync users & teams  

The containers communicate via localhost inside the Pod:
```
Grafana → 127.0.0.1:8080 (Auth Proxy)
Auth Proxy → 127.0.0.1:3000 (Grafana)
Auth Proxy → Helix server
```

---

# 2. Prerequisites  

Before deploying, ensure:

## 2.1 Helix Requirements
- REST API enabled  
- Admin service account created  
- Webhooks enabled (Helix Innovation Suite 20.08+)  
- Forms **User** and **Group** must contain:
  - Login Name  
  - Full Name  
  - Email Address  
  - Group List  

## 2.2 Kubernetes / Podman Requirements
- Kubernetes cluster or Podman 4+  
- Network where Helix is reachable  
- Ability to create Secrets, ConfigMaps, PVCs  

## 2.3 Grafana Requirements
- No internal auth providers enabled  
- Auth Proxy mode enabled via environment variables  
- JSON API plugin installed  

---

# 3. Required Kubernetes Objects

Deployment includes:

1. **ConfigMap** – general configuration  
2. **Secrets** – Helix admin, OIDC secrets, Grafana API token  
3. **PVC** – persistent Grafana storage  
4. **Pod** – runs Grafana + Proxy  

Directory structure:
```
hlx-grafana-auth-proxy/
│
├─ app.py
├─ hlx-grafana-auth-proxy-pod.yaml
└─ docs/
```

---

# 4. ConfigMap – Main Configuration

The ConfigMap controls:

- Logging  
- Helix endpoints  
- User/Group form names  
- Field mappings  
- Allowed Helix forms  
- Group → Role mapping  
- Authentication mode (local, rsso, oidc)  

Example:

```
LOG_LEVEL: "DEBUG"
HELIX_BASE_URL: "http://arserver:8008"
HELIX_ALLOWED_FORMS: "User,Group"
AUTH_MODE: "local"
HELIX_USER_FORM: "User"
HELIX_USER_LOGIN_FIELD: "Login Name"
HELIX_USER_GROUP_FIELD: "Group List"
HELIX_GROUP_ROLE_MAPPING: "400001:Viewer,400002:Editor"
```

---

# 5. Secrets – Sensitive Credentials

You must store:

### 5.1 Helix Admin Credentials
```
HELIX_ADMIN_USER: "Demo"
HELIX_ADMIN_PASSWORD: "P@ssw0rd"
```

### 5.2 Webhook Shared Secret
```
WEBHOOK_SHARED_SECRET: "<your-secret>"
```

### 5.3 Grafana API Token
This is used internally for creating users & teams:

```
GRAFANA_API_TOKEN: "<generated-token>"
```

### 5.4 OIDC (Optional for AUTH_MODE=oidc)
```
OIDC_CLIENT_ID: grafana-proxy
OIDC_CLIENT_SECRET: <secret>
```

---

# 6. PersistentVolumeClaim

The PVC ensures:
- dashboards  
- users  
- team definitions  
- datasource config  

persist across restarts.

Example:
```
resources:
  requests:
    storage: 1Gi
```

---

# 7. Pod Deployment

The Pod includes two containers:

## 7.1 Grafana Container

Key settings:
```
GF_AUTH_PROXY_ENABLED=true
GF_AUTH_PROXY_HEADER_NAME=X-WEBAUTH-USER
GF_AUTH_PROXY_HEADERS="Role:X-WEBAUTH-ROLE"
GF_DATAPROXY_SEND_USER_HEADER=true
```

The JSON API plugin is installed:
```
GF_INSTALL_PLUGINS="marcusolsson-json-datasource"
```

Container exposes port **3000** internally.

---

## 7.2 Auth Proxy Container

Environment variables include:

- All items from ConfigMap  
- All items from Secrets  
- Internal Grafana URL:
```
GRAFANA_INTERNAL_URL=http://127.0.0.1:3000
```

Container exposes:
- port **8080** internally  
- optional hostPort for debugging  

---

# 8. Deployment Command

To deploy using Podman:

```
podman play kube hlx-grafana-auth-proxy-pod.yaml
```

To remove:
```
podman play kube --down hlx-grafana-auth-proxy-pod.yaml
```

To restart:
```
podman play kube --down hlx-grafana-auth-proxy-pod.yaml && podman play kube hlx-grafana-auth-proxy-pod.yaml
```

---

# 9. Verifying Deployment

## 9.1 Proxy Startup Logs
Look for:
```
Application startup complete.
Loaded Helix config...
Authentication mode: local/rsso/oidc
```

## 9.2 Grafana Logs
Look for:
```
Auth proxy enabled
```

## 9.3 Access Grafana
Open:
```
http://<host>:3000
```

Depending on AUTH_MODE:

| Mode | Result |
|------|--------|
| local | Login UI appears |
| rsso | User logged in automatically |
| oidc | Seamless login via reverse proxy |

---

# 10. Troubleshooting

See detailed guide in:

👉 `08-troubleshooting.md`

### Common Issues:

| Error | Cause | Fix |
|-------|--------|------|
| 401 Unauthorized | Wrong auth mode | Check AUTH_MODE |
| 500 Internal Server Error | Missing secret | Check kubectl describe pod |
| Webhooks failing | Wrong shared secret | Update Helix webhook config |
| Query errors | Form not whitelisted | Update HELIX_ALLOWED_FORMS |

---

# 11. Related Documentation

- `02-authentication-modes.md`  
- `05-webhooks.md`  
- `07-architecture.md`  
- `10-security.md`
