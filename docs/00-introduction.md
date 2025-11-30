
# Introduction  
Welcome to the **Helix Grafana Auth Proxy** documentation.  
This solution integrates **BMC Helix** identity, authorization, and data access models with **Grafana**, enabling seamless dashboards powered by Helix while enforcing enterprise-grade security and permissions.

The system runs as a dual-container Pod:
- **Grafana**
- **Helix Grafana Auth Proxy (FastAPI)**

The proxy acts as:
- an **authentication gateway**  
- a **Helix-aware authorization engine**  
- a **data proxy**  
- a **synchronization controller** (via Helix Webhooks)

It ensures that:
- Only authenticated users access Grafana  
- Their identity is resolved correctly (Helix login)  
- Their groups from Helix are mapped to Grafana roles  
- Team membership stays synchronized  
- Data queries are executed as the impersonated Helix user  
- No credentials or tokens are exposed to the client browser  

---

# Why This Project Exists  
Grafana provides amazing visualization capabilities, but lacks:
- native SSO integration with Helix/RSSO/HSSO  
- native Helix role enforcement  
- impersonated user access for Helix REST API  
- automatic user & team synchronization from Helix  

This project bridges that gap using a clean, maintainable design.

---

# Key Features

## ✔ 1. Authentication Options  
Choose the mode that fits your deployment:

| Mode | Description | Best For |
|------|-------------|----------|
| **local** | User enters Helix credentials | Labs, small setups |
| **rsso** | Reverse proxy injects RSSO user header | Existing RSSO/HSSO |
| **oidc** | Reverse proxy validates ID token, forwards username | Enterprise, MFA, modern SSO |

All modes share the same authorization logic.

---

## ✔ 2. Helix Group → Grafana Role Mapping  
The proxy reads the user’s **Group List** from the Helix User form.  
You define mappings like:

```
400001:Viewer
400002:Editor
400003:Admin
```

Multiple groups can map to the same role.

---

## ✔ 3. Full User & Team Synchronization  
Using **Helix Webhooks**, the proxy automatically updates Grafana:

- New users are created  
- Updated users sync their role  
- Groups become Grafana teams  
- Team membership is automatically maintained  

This allows real identity-driven access control without managing Grafana manually.

---

## ✔ 4. Impersonation for Helix REST API Queries  
All Grafana queries run through:

```
/helix-api/<form>
```

The proxy:
1. uses admin service account to fetch AR-JWT  
2. impersonates the logged-in user  
3. executes the request against Helix  
4. returns JSON to Grafana’s data source  

Grafana users never see or handle real credentials.

---

## ✔ 5. Secure-by-Design Architecture  
- No direct access to Helix from Grafana  
- No Helix credentials stored in the browser  
- All secrets are stored in Kubernetes Secrets  
- All identity flows terminate at the proxy  
- Reverse proxy headers validated rigorously  

---

# High-Level Architecture

User → Reverse Proxy (optional) → **Auth Proxy** → Grafana  
          → Helix (impersonated requests)

Webhooks → Auth Proxy → Grafana (teams/users)

---

# Who Should Use This?  
This project is ideal for:

- Organizations running BMC Helix  
- Teams that want secure dashboards with real SSO  
- Admins who want user/team synchronization from Helix  
- Enterprises preferring OIDC-based SSO  
- Anyone wanting Helix data in Grafana with correct permissions  

---

# What This Documentation Covers

## You will find:
- Deployment instructions  
- Pod + ConfigMap + Secret reference  
- Authentication mode deep dives  
- RSSO/HSSO/OIDC advanced setup  
- Webhook integration and payload examples  
- Architecture diagrams  
- Troubleshooting guides  
- Security considerations  

---

# Next Steps  
Continue to the deployment guide:

👉 `01-deployment.md`
