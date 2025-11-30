# README (Svenska)

## Helix Grafana Auth Proxy – Installation och Konfiguration

Denna lösning består av två komponenter i samma Pod:
1. **Grafana**
2. **hlx-grafana-auth-proxy** (FastAPI)

Syftet är att:
- Autentisera användare mot BMC Helix (lokalt eller via RSSO)
- Impersonera användare vid REST-anrop till Helix
- Styra Grafana-roller baserat på Helix-gruppmedlemskap
- Proxa all Grafana-trafik via ett säkert lager
- Göra det möjligt att skapa dashboards utan att tappa dem vid omstart (Persistent Storage)

## Funktioner
- Manuell inloggning via `/login` **(AUTH_MODE=local – default)**
- Alternativ inloggning via RSSO-header **(AUTH_MODE=rsso)**
- Helix-grupp → Grafana-roll-mappning via ConfigMap
- Whitelist av tillåtna Helix-formulär
- Persistent lagring av Grafanas SQLite-databas via PVC
- Impersonation via servicekonto (AR-JWT + X-AR-Impersonated-User)

## Struktur
- `ConfigMap`: generella inställningar
- `Secret`: servicekonto-lösenord
- `PVC`: lagring av dashboards & användardata
- `Pod`: Grafana & Auth-proxy

## Viktiga miljövariabler

### Authentication
```
AUTH_MODE=local | rsso
RSSO_HEADER_NAME=X-RSSO-USER
```

### Helix-konfiguration
```
HELIX_BASE_URL=https://helix.example.com
HELIX_JWT_LOGIN_URL=https://helix.example.com/api/jwt/login
HELIX_ALLOWED_FORMS=User,Group
```

### Servicekonto (från Secret)
```
HELIX_ADMIN_USER
HELIX_ADMIN_PASSWORD
```

### Grupp → roll-mappning
```
400001=Viewer
400002=Editor
400003=Admin
```

## Persistent Storage
Alla dashboards lagras i `/var/lib/grafana` och mountas via:
```
PersistentVolumeClaim: grafana-disk-pvc
```

## Starta podden
```
podman play kube helix-grafana-with-config.yaml
```

## Uppdatera konfiguration
Ändra ConfigMap eller Secret och kör:
```
podman play kube --down helix-grafana-with-config.yaml
podman play kube helix-grafana-with-config.yaml
```

## Om du vill aktivera RSSO
1. Ändra i ConfigMap:
```
AUTH_MODE=rsso
RSSO_HEADER_NAME=X-RSSO-USER
```
2. Se till att din Reverse Proxy sätter korrekt header.

## Filöversikt
- `README_sv.md` – den här filen (svenska)
- `README_en.md` – engelsk variant
