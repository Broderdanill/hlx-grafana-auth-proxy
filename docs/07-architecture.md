# Architecture Overview

## 1. Introduction

The **Helix Grafana Auth Proxy** architecture is designed to unify authentication, authorization, data access, and user lifecycle synchronization between:

- **BMC Helix ITSM / Innovation Suite (REST API)**
- **Grafana**
- **RSSO / HSSO (optional OIDC-based SSO)**
- **Webhook-based synchronization pipelines**
- **Local login fallback**

This document provides a complete architectural exploration of how all components interact, the data flows, sequence diagrams, and the internal responsibilities of each subsystem.

---

# 2. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       BMC Helix Platform                    │
│                                                             │
│  ┌──────────────┐     ┌─────────────┐      ┌────────────┐  │
│  │  Helix User  │<--->│ Helix Groups│<---->│   Webhooks  │  │
│  └──────────────┘     └─────────────┘      └────────────┘  │
│         ^                       ^                 |          │
└─────────|───────────────────────|─────────────────|──────────┘
          |                       |                 |
          | User & Group Lookup   | Group Mapping   | Webhook POST
          v                       v                 v
┌─────────────────────────────────────────────────────────────┐
│             hlx-grafana-auth-proxy (FastAPI)                │
│                                                             │
│  Authentication Modes:                                      │
│     - local login (JWT to Helix)                            │
│     - rsso header mode                                      │
│     - oidc (via RSSO/HSSO)                                  │
│                                                             │
│  Responsibilities:                                          │
│    • Session management                                      │
│    • Helix impersonation (AR-JWT + X-AR-Impersonated-User) │
│    • Grafana API calls                                       │
│    • Synchronizing Users and Teams                           │
│    • Webhook validation & routing                            │
│    • Cold-start recovery                                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                              |
                              | Auth Proxy Headers
                              v
┌─────────────────────────────────────────────────────────────┐
│                          Grafana                            │
│                                                             │
│   - Auth Proxy Mode Enabled (X-WEBAUTH-USER)                │
│   - Teams & Users Managed via API                           │
│   - JSON API Data Source → hlx-grafana-auth-proxy           │
│                                                             │
└─────────────────────────────────────────────────────────────┘