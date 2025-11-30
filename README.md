# README (English)

## Helix Grafana Auth Proxy – Installation and Configuration

This solution consists of two containers running inside the same Pod:
1. **Grafana**
2. **hlx-grafana-auth-proxy** (FastAPI)

The purpose is to:
- Authenticate users against BMC Helix (local login or RSSO)
- Impersonate the logged-in user for Helix REST API calls
- Map Helix groups to Grafana roles dynamically
- Proxy all Grafana traffic through a secure authentication layer
- Ensure dashboards persist using a PVC even after container restarts

## Features
- Manual login page via `/login` **(AUTH_MODE=local – default)**
- RSSO-based authentication supported via HTTP header **(AUTH_MODE=rsso)**
- Helix group → Grafana role mapping via ConfigMap
- Whitelisting of allowed Helix forms for queries
- Persistent storage of Grafana SQLite DB via PVC
- Impersonation using service account (AR-JWT + X-AR-Impersonated-User)

## Structure
- `ConfigMap`: general configuration
- `Secret`: stores Helix service account credentials
- `PVC`: persistent storage for Grafana data
- `Pod`: runs Grafana and the auth proxy containers together

## Important Environment Variables

### Authentication
```
AUTH_MODE=local | rsso
RSSO_HEADER_NAME=X-RSSO-USER
```

### Helix Configuration
```
HELIX_BASE_URL=https://helix.example.com
HELIX_JWT_LOGIN_URL=https://helix.example.com/api/jwt/login
HELIX_ALLOWED_FORMS=User,Group
```

### Service Account (from Secret)
```
HELIX_ADMIN_USER
HELIX_ADMIN_PASSWORD
```

### Group → Role Mapping
```
400001=Viewer
400002=Editor
400003=Admin
```

## Persistent Storage
All dashboards are stored inside `/var/lib/grafana` and are mounted using:
```
PersistentVolumeClaim: grafana-disk-pvc
```

## Run the Pod
```
podman play kube helix-grafana-with-config.yaml
```

## Update Configuration
After editing the ConfigMap or Secret:
```
podman play kube --down helix-grafana-with-config.yaml
podman play kube helix-grafana-with-config.yaml
```

## Enable RSSO Authentication
1. Update ConfigMap:
```
AUTH_MODE=rsso
RSSO_HEADER_NAME=X-RSSO-USER
```
2. Your reverse proxy must set the header with the Helix username.


## Grafana - Data Source
This default set up is using "marcusolsson-json-datasource" as data source
Below are some examples on how to use it.

### Path
Path defines the AR Form Name, for example:
/User
/Group

### Fields
The data source will get the complete json, therefor we need to specify correct path, for example:
entries[*].values.Full Name   -  Full Name Field in User Form

JSONata
JSONata är ett uttrycksspråk för att transformera JSON-data.
Tänk:

JSON → transformera → nytt JSON
filtrera
gruppera
mappa om fält
räkna saker
skapa nya objekt
slå ihop fält
summera
byta struktur helt
Och JSON API-pluginet låter dig köra JSONata direkt på resultatet från din HTTP-endpoint.