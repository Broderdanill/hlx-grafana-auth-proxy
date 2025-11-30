# Troubleshooting Guide

## 1. Overview
This guide provides detailed troubleshooting steps for authentication, Helix integration, Grafana authorization, webhook synchronization, and OIDC/RSSO/HSSO interoperability.

## 2. Common Issues

### 2.1 Cannot Log In (Local Mode)
**Symptoms**
- Login page returns "Invalid credentials"
- Proxy logs show: `JWT login failed`

**Causes**
- Wrong HELIX_JWT_LOGIN_URL
- Wrong HELIX_ADMIN_USER or HELIX_ADMIN_PASSWORD
- Helix is blocking from IP restrictions

**Fix**
- Verify JWT endpoint with curl:
  ```
  curl -X POST http://arserver:8008/api/jwt/login -d '{"username":"Demo","password":"P@ssw0rd"}'
  ```

### 2.2 RSSO/HSSO Login Does Not Work
**Symptoms**
- User is redirected indefinitely
- Proxy logs show `No SSO header found`
- User always becomes “anonymous”

**Fix**
- Ensure reverse-proxy injects correct header:
  ```
  X-RSSO-USER: <login>
  ```
- Check mapping in RSSO Agent:
  - Login Attribute → "Login Name"
  - Client secret matches container secret

### 2.3 OIDC (RSSO/HSSO) Authorization Failure
**Symptoms**
- Token rejected
- Error: “Invalid issuer” or “Signature verification failed”

**Fix**
- Verify `.well-known/openid-configuration` endpoint
- Ensure:
  ```
  OIDC_ISSUER_URL
  OIDC_CLIENT_ID
  OIDC_CLIENT_SECRET
  ```
  are correct.

## 3. Webhook Issues

### 3.1 401 Missing Shared Secret
**Fix**
Ensure Helix webhook body contains:
```
"shared_secret": "<value>"
```
And matches secret:
```
WEBHOOK_SHARED_SECRET
```

### 3.2 422 Payload Parsing Error
**Fix**
Helix field names must match Pydantic schema exactly.

For User:
```
"Login Name"
"Email Address"
"Group List"
```

For Group:
```
"Group Name"
"Group ID"
```

### 3.3 Teams Not Synced
**Fix**
- Ensure Group exists in Helix
- Ensure new Team name is valid (no special chars)
- Ensure webhook contains `Group ID`

## 4. Grafana Problems

### 4.1 User Role Incorrect
**Cause**
Group → Role mapping missing.

**Fix**
Check:
```
HELIX_GROUP_ROLE_MAPPING
```

### 4.2 Grafana API Token Invalid
**Fix**
Regenerate admin token:
```
grafana-cli admin api-keys create ...
```
Replace YAML secret:
```
GRAFANA_API_TOKEN
```

## 5. Cold Start Problems

### Issue
Reboot = lost memberships

### Fix
Enable cold-start recovery:
- Proxy reads all Helix users → syncs teams
- Requires:
  ```
  HELIX_USER_FORM
  HELIX_USER_GROUP_FIELD
  ```

## 6. Network Issues
- Ensure pod network can reach Helix
- Ensure Grafana listens on 3000 internally

## 7. Logging

Set:
```
LOG_LEVEL=DEBUG
```
Then inspect logs:
```
podman logs helix-grafana-pod
```

## 8. Support Checklist
- Verify environment variables
- Validate secrets
- Test Helix JWT
- Test RSSO header
- Test OIDC token
- Test Grafana API
- Test webhook delivery
- Test user synchronization
- Test team mapping

All problems can usually be diagnosed by enabling DEBUG and watching both containers.
