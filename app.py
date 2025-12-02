import os
import base64
import logging
import asyncio
import json
import secrets
from typing import Optional, Dict, List, Literal
from pydantic import BaseModel, Field
from urllib.parse import urlencode

from fastapi import HTTPException, Depends, FastAPI, Request, Response, Form, WebSocket, Query
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from fastapi.websockets import WebSocketDisconnect
import httpx

# =========================
#  LOGGING CONFIGURATION
# =========================

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)

logger = logging.getLogger("hlx-grafana-auth-proxy")
logger.info(f"Starting hlx-grafana-auth-proxy with LOG_LEVEL={LOG_LEVEL}")

# =========================
#  CONFIG / ENV
# =========================

# Internal URL where Grafana is reachable (inside the POD / network namespace)
GRAFANA_INTERNAL_URL = os.getenv("GRAFANA_INTERNAL_URL", "http://127.0.0.1:3000")

# API Token used to sync users and group from Helix
GRAFANA_API_TOKEN = os.getenv("GRAFANA_API_TOKEN")
GRAFANA_ADMIN_USER = os.getenv("GRAFANA_ADMIN_USER", "admin")
GRAFANA_ADMIN_PASSWORD = os.getenv("GRAFANA_ADMIN_PASSWORD", "changeme")

# Helix REST base URL
HELIX_BASE_URL = os.getenv("HELIX_BASE_URL", "https://helix.example.com")

# JWT login endpoint for both user and service account
# In most cases: https://<helix>/api/jwt/login
HELIX_JWT_LOGIN_URL = os.getenv(
    "HELIX_JWT_LOGIN_URL",
    f"{HELIX_BASE_URL}/api/jwt/login",
)

# Get Webhook Secret
WEBHOOK_SHARED_SECRET = os.getenv("WEBHOOK_SHARED_SECRET")

# Service account (admin / technical user) used for impersonation against Helix
HELIX_ADMIN_USER = os.getenv("HELIX_ADMIN_USER", "svc_helix_reports")
HELIX_ADMIN_PASSWORD = os.getenv("HELIX_ADMIN_PASSWORD", "changeme")

# Cookie name used to store the username for local login mode
HELIX_USER_COOKIE = "HLX_USER"

# AUTH_MODE controls how authentication is performed:
#  - "local" (default): own login page against Helix JWT-login (username + password)
#  - "rsso": user is authenticated externally via RSSO / reverse proxy header, e.g. X-RSSO-USER
AUTH_MODE = os.getenv("AUTH_MODE", "local").lower()

# RSSO_HEADER_NAME is only used when AUTH_MODE="rsso"
# Reverse proxy in front of this app should set e.g. X-RSSO-USER: <loginName>
RSSO_HEADER_NAME = os.getenv("RSSO_HEADER_NAME", "X-RSSO-USER")

# =========================
#  OIDC CONFIG (AUTH_MODE="oidc")
# =========================
# RSSO/HSSO will act as the OpenID Provider (OP).
# This service (hlx-grafana-auth-proxy) is the OIDC client (RP).

OIDC_ISSUER = os.getenv("OIDC_ISSUER")  # optional, for documentation
OIDC_AUTH_URL = os.getenv("OIDC_AUTH_URL")  # e.g. https://hsso/realms/helix/protocol/openid-connect/auth
OIDC_TOKEN_URL = os.getenv("OIDC_TOKEN_URL")  # .../token
OIDC_USERINFO_URL = os.getenv("OIDC_USERINFO_URL")  # .../userinfo

# These two come from Secret (not ConfigMap!)
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID")
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET")

# Where the IdP will send the user back after login
OIDC_REDIRECT_URI = os.getenv("OIDC_REDIRECT_URI")

# Scopes and which claim we use as "login name"
OIDC_SCOPE = os.getenv("OIDC_SCOPE", "openid profile email")
OIDC_USERNAME_CLAIM = os.getenv("OIDC_USERNAME_CLAIM", "preferred_username")

# Cookie to protect against CSRF in the auth code flow
OIDC_STATE_COOKIE = "HLX_OIDC_STATE"

# Setting for secure cookie
SECURE_COOKIES = os.getenv("SECURE_COOKIES", "true").lower() == "true"


# Whitelist of Helix forms (comma-separated)
# Example: "User,Group,HPD:IncidentInterface"
RAW_ALLOWED_FORMS = os.getenv("HELIX_ALLOWED_FORMS", "")

# Form + fields used to read the user's groups
# Default form: "User"
HELIX_USER_FORM = os.getenv("HELIX_USER_FORM", "User")
# Field containing the login name in the User form (Helix login name)
HELIX_USER_LOGIN_FIELD = os.getenv("HELIX_USER_LOGIN_FIELD", "Login Name")
# Field containing the group string, e.g. "1;400003;12321;"
HELIX_USER_GROUP_FIELD = os.getenv("HELIX_USER_GROUP_FIELD", "Group List")

# Mapping from Helix group ID → Grafana role
# Default example: 400001=Viewer, 400002=Editor, 400003=Admin
# Format: "400001:Viewer,400002:Editor,400003:Admin"
RAW_GROUP_ROLE_MAPPING = os.getenv(
    "HELIX_GROUP_ROLE_MAPPING",
    "400001:Viewer,400002:Editor,400003:Admin",
)

# Default Grafana role if no matching group is found or Helix query fails
HELIX_DEFAULT_GRAFANA_ROLE = os.getenv("HELIX_DEFAULT_GRAFANA_ROLE", "Viewer")


def parse_form_whitelist(value: str):
    """
    "User,Group,HPD:IncidentInterface"
    -> ["User", "Group", "HPD:IncidentInterface"]
    """
    forms = []
    for part in value.split(","):
        p = part.strip()
        if p:
            forms.append(p)
    return forms


def verify_webhook_data(data: dict):
    """
    Verifiera inkommande webhook genom att läsa shared_secret från JSON-dict.

    Förväntat format (i Helix Webhook Custom JSON-fältet):

      { "shared_secret": "super-hemligt-värde-här" }

    eller (om Helix lägger det under custom_json):

      {
        "custom_json": {
          "shared_secret": "super-hemligt-värde-här"
        },
        ...
      }
    """
    if not WEBHOOK_SHARED_SECRET:
        logger.warning("WEBHOOK_SHARED_SECRET is not configured – allowing all webhooks")
        return

    if not isinstance(data, dict):
        logger.warning("Webhook body is not a JSON object")
        raise HTTPException(status_code=400, detail="Invalid webhook body type")

    shared_secret = data.get("shared_secret")

    # fallback: custom_json.shared_secret
    if not shared_secret and isinstance(data.get("custom_json"), dict):
        shared_secret = data["custom_json"].get("shared_secret")

    if not shared_secret or shared_secret != WEBHOOK_SHARED_SECRET:
        logger.warning("Webhook call with invalid or missing shared_secret")
        raise HTTPException(status_code=401, detail="Invalid webhook shared secret")


def parse_group_role_mapping(value: str) -> Dict[str, str]:
    """
    "400001:Viewer,400002:Editor,400003:Admin"
    -> {"400001": "Viewer", "400002": "Editor", "400003": "Admin"}
    """
    mapping: Dict[str, str] = {}
    for part in value.split(","):
        p = part.strip()
        if not p:
            continue
        if ":" not in p:
            continue
        group_id, role = p.split(":", 1)
        group_id = group_id.strip()
        role = role.strip()
        if group_id and role:
            mapping[group_id] = role
    return mapping


ALLOWED_FORMS = parse_form_whitelist(RAW_ALLOWED_FORMS)
ALL_GROUP_MAPPING = parse_group_role_mapping(RAW_GROUP_ROLE_MAPPING)

GRAFANA_ORG_ROLES = {"Viewer", "Editor", "Admin"}

# Only mappings that point to a Grafana org role
GROUP_ROLE_MAPPING = {
    gid: role for gid, role in ALL_GROUP_MAPPING.items() if role in GRAFANA_ORG_ROLES
}

# All other mappings are treated as "Grafana groups" (used for teams/folder permissions)
GROUP_TEAM_MAPPING: Dict[str, str] = {
    gid: group_name
    for gid, group_name in ALL_GROUP_MAPPING.items()
    if group_name not in GRAFANA_ORG_ROLES
}

# Dynamisk karta: Helix Group ID -> Grafana team-namn
# Uppdateras i /webhook/grafana/team utifrån "Group Name" (t.ex. ...-410001)
TEAM_ID_MAP: Dict[str, str] = {}


logger.info(f"Allowed Helix forms: {ALLOWED_FORMS}")
logger.info(f"AUTH_MODE: {AUTH_MODE}, RSSO_HEADER_NAME: {RSSO_HEADER_NAME}")
logger.debug(f"GROUP_ROLE_MAPPING (org roles): {GROUP_ROLE_MAPPING}")
logger.debug(f"GROUP_TEAM_MAPPING (grafana groups): {GROUP_TEAM_MAPPING}")
logger.debug(f"HELIX_USER_FORM: {HELIX_USER_FORM}")
logger.debug(f"HELIX_USER_LOGIN_FIELD: {HELIX_USER_LOGIN_FIELD}")
logger.debug(f"HELIX_USER_GROUP_FIELD: {HELIX_USER_GROUP_FIELD}")
logger.info(f"HELIX_DEFAULT_GRAFANA_ROLE: {HELIX_DEFAULT_GRAFANA_ROLE}")


app = FastAPI()

# Cache for service account admin token (AR-JWT)
_ADMIN_TOKEN: Optional[str] = None

# Cache for Grafana role per user (username -> role)
_ROLE_CACHE: Dict[str, str] = {}

# Cache for user group list (raw Helix group string)
_GROUP_LIST_CACHE: Dict[str, str] = {}

# Cache for Grafana "groups" header per user (comma-separated string)
_TEAM_CACHE: Dict[str, str] = {}

# Simple priority for roles if user has multiple groups
ROLE_PRIORITY = {
    "Viewer": 1,
    "Editor": 2,
    "Admin": 3,
}


# =========================
#  HELPER FUNCTIONS
# =========================

def resolve_username(request: Request) -> Optional[str]:
    """
    Resolve the current user based on where the request comes from and AUTH_MODE.

    Priority:

    1) X-Grafana-User
       - When Grafana dataproxy calls this app (e.g. /helix-api/User) and
         GF_DATAPROXY_SEND_USER_HEADER=true, Grafana username is sent in this header.
       - This is the best source for "who executes the query?" in backend mode.

    2) RSSO header (if AUTH_MODE="rsso")
       - Reverse proxy or RSSO in front of this app sets e.g. X-RSSO-USER: <loginName>

    3) HLX_USER cookie
       - Only set in "local" mode (manual login via /login).
    """
    logger.debug(f"resolve_username: headers={dict(request.headers)}")

    # 1. Backend request from Grafana dataproxy
    hdr = request.headers.get("X-Grafana-User")
    if hdr:
        return hdr

    # 2. RSSO mode
    if AUTH_MODE == "rsso":
        hdr = request.headers.get(RSSO_HEADER_NAME)
        if hdr:
            return hdr

    # 3. Fallback: cookie
    return request.cookies.get(HELIX_USER_COOKIE)


def get_cookie_user(request: Request) -> Optional[str]:
    """
    Return user from HLX_USER cookie.
    Used only for browser login (/login) in local mode.
    """
    return request.cookies.get(HELIX_USER_COOKIE)


def build_oidc_authorization_url() -> tuple[str, str]:
    """
    Build the OIDC authorization URL and a random state value.

    Used when AUTH_MODE="oidc" to redirect the browser to RSSO/HSSO.
    """
    if not (OIDC_AUTH_URL and OIDC_CLIENT_ID and OIDC_REDIRECT_URI):
        logger.error("OIDC is not correctly configured (AUTH_URL / CLIENT_ID / REDIRECT_URI missing)")
        raise HTTPException(status_code=500, detail="OIDC is not correctly configured")

    state = secrets.token_urlsafe(32)

    params = {
        "response_type": "code",
        "client_id": OIDC_CLIENT_ID,
        "redirect_uri": OIDC_REDIRECT_URI,
        "scope": OIDC_SCOPE,
        "state": state,
    }

    url = f"{OIDC_AUTH_URL}?{urlencode(params)}"
    logger.debug(f"OIDC authorization URL built: {url}")
    return url, state


async def login_against_helix(username: str, password: str) -> bool:
    """
    LOCAL AUTH LOGIC:
    Validate user's Helix credentials by calling JWT login with username+password.
    We only check HTTP status code 200 vs non-200 to determine success.

    NOTE: The returned token is NOT used for queries (we use impersonation via service account).
    """
    logger.debug(f"Attempting Helix user login for '{username}'")

    async with httpx.AsyncClient(verify=False) as client:
        try:
            resp = await client.post(
                HELIX_JWT_LOGIN_URL,
                data={"username": username, "password": password},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10.0,
            )
        except httpx.RequestError as e:
            logger.error(f"Error calling HELIX_JWT_LOGIN_URL for user login: {e}")
            return False

    logger.debug(f"User login status: {resp.status_code}")
    if resp.status_code != 200:
        logger.warning(
            f"User login failed for '{username}', body: {resp.text[:500]}"
        )
        return False

    return True


async def get_admin_token(force_refresh: bool = False) -> Optional[str]:
    """
    Retrieve AR-JWT token for the service account (admin/service user) and cache it.
    If force_refresh=True we always log in again.

    This token is used together with X-AR-Impersonated-User (base64 encoded) to
    perform Helix REST calls "as" the actual user.
    """
    global _ADMIN_TOKEN

    if _ADMIN_TOKEN and not force_refresh:
        return _ADMIN_TOKEN

    logger.info("Fetching new admin AR-JWT token from Helix...")

    async with httpx.AsyncClient(verify=False) as client:
        try:
            resp = await client.post(
                HELIX_JWT_LOGIN_URL,
                data={"username": HELIX_ADMIN_USER, "password": HELIX_ADMIN_PASSWORD},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10.0,
            )
        except httpx.RequestError as e:
            logger.error(f"Error calling HELIX_JWT_LOGIN_URL for admin login: {e}")
            return None

    logger.debug(
        f"Admin login status: {resp.status_code}, body: {resp.text[:200]}"
    )
    if resp.status_code != 200:
        logger.error("Admin login failed")
        _ADMIN_TOKEN = None
        return None

    token = resp.text.strip()
    if not token or len(token) < 10:
        logger.error(f"Admin login: token looks invalid: {token[:20]}...")
        _ADMIN_TOKEN = None
        return None

    _ADMIN_TOKEN = token
    logger.info("Admin AR-JWT token acquired successfully")
    return _ADMIN_TOKEN


async def grafana_request(method: str, path: str,
                          json: dict | None = None,
                          params: dict | None = None):
    """
    Wrapper runt Grafanas HTTP-API.

    - Om GRAFANA_API_TOKEN finns -> använd Bearer-token
    - Annars -> använd Basic Auth med GRAFANA_ADMIN_USER / GRAFANA_ADMIN_PASSWORD
    """
    url = f"{GRAFANA_INTERNAL_URL}{path}"

    headers = {
        "Content-Type": "application/json",
    }

    auth = None
    if GRAFANA_API_TOKEN:
        headers["Authorization"] = f"Bearer {GRAFANA_API_TOKEN}"
    else:
        # Fallback: Basic Auth mot Grafana admin-kontot
        if not GRAFANA_ADMIN_USER or not GRAFANA_ADMIN_PASSWORD:
            raise RuntimeError("No Grafana API token or admin credentials configured")
        auth = (GRAFANA_ADMIN_USER, GRAFANA_ADMIN_PASSWORD)

    async with httpx.AsyncClient() as client:
        resp = await client.request(
            method,
            url,
            headers=headers,
            json=json,
            params=params,
            timeout=10.0,
            auth=auth,
        )

    logger.debug(f"Grafana API {method} {path} -> {resp.status_code}")
    return resp


async def fetch_user_groups(username: str) -> Optional[str]:
    """
    Fetch the 'Group List' (or configured group field) for a given user
    from the Helix User form.

    Uses the service account (admin token) and queries:
      GET /api/arsys/v1/entry/<HELIX_USER_FORM>
          ?q='Login Name'="<username>"
          &fields=values(Group List)

    On success returns the group list string (e.g. "1;400003;12321;").
    On failure returns None.
    """
    token = await get_admin_token()
    if not token:
        logger.error("fetch_user_groups: no admin token available")
        return None

    # Build query parameters according to Helix REST syntax
    qualification = f"'{HELIX_USER_LOGIN_FIELD}'=\"{username}\""
    params = {
        "q": qualification,
        # Only request the field we need
        "fields": f"values({HELIX_USER_GROUP_FIELD})",
    }

    url = f"{HELIX_BASE_URL}/api/arsys/v1/entry/{HELIX_USER_FORM}"

    logger.debug(
        f"fetch_user_groups: Helix request for user '{username}' → {url} with q={qualification}"
    )

    async with httpx.AsyncClient(verify=False) as client:
        try:
            resp = await client.get(
                url,
                headers={"Authorization": f"AR-JWT {token}"},
                params=params,
                timeout=15.0,
            )
        except httpx.RequestError as e:
            logger.error(f"fetch_user_groups: error calling Helix: {e}")
            return None

    if resp.status_code != 200:
        logger.error(
            f"fetch_user_groups: Helix error {resp.status_code}, body={resp.text[:500]}"
        )
        return None

    data = resp.json()
    entries = data.get("entries", [])
    if not entries:
        logger.warning(f"fetch_user_groups: no entries for user {username}")
        return None

    # Use the first match
    values = entries[0].get("values", {})
    group_list = values.get(HELIX_USER_GROUP_FIELD)
    if not group_list:
        logger.warning(
            f"fetch_user_groups: no '{HELIX_USER_GROUP_FIELD}' field found for user {username}"
        )
        return None

    if not isinstance(group_list, str):
        group_list = str(group_list)

    logger.debug(
        f"fetch_user_groups: user={username}, group_list={group_list}"
    )
    return group_list

async def get_user_group_list(username: str) -> Optional[str]:
    """
    Return the cached Helix group list for a user if available,
    otherwise fetch it from Helix and cache it.
    """
    if username in _GROUP_LIST_CACHE:
        return _GROUP_LIST_CACHE[username]

    group_list = await fetch_user_groups(username)
    if group_list:
        _GROUP_LIST_CACHE[username] = group_list
    return group_list



def pick_role_from_groups(group_list: str) -> str:
    """
    Take a semicolon-separated group string, e.g. "1;400003;12321;",
    and pick the best Grafana role according to GROUP_ROLE_MAPPING + ROLE_PRIORITY.

    Example:
      GROUP_ROLE_MAPPING = {"400001": "Viewer", "400002": "Editor", "400003": "Admin"}
      group_list = "1;400003;12321;" -> Admin (highest priority)
    """
    best_role = HELIX_DEFAULT_GRAFANA_ROLE
    best_score = ROLE_PRIORITY.get(best_role, 0)

    parts = [p.strip() for p in group_list.split(";") if p.strip()]
    for gid in parts:
        role = GROUP_ROLE_MAPPING.get(gid)
        if not role:
            continue
        score = ROLE_PRIORITY.get(role, 0)
        if score > best_score:
            best_role = role
            best_score = score

    return best_role

def pick_teams_from_groups(group_list: str) -> list[str]:
    """
    Extract Grafana team-namn från semikolonseparerad Helix-gruppsträng.

    Vi tittar både i:
      - TEAM_ID_MAP (dynamisk: Helix Group ID -> Grafana-teamnamn)
      - GROUP_TEAM_MAPPING (statisk via env, endast fallback)

    Exempel:
      TEAM_ID_MAP = {"410001": "GRP_Grafana_FolderPermission01"}
      GROUP_TEAM_MAPPING = {"410001": "GrafanaRole01"}
      group_list = "1;400003;410001;12321;"
      -> ["GRP_Grafana_FolderPermission01"]  (TEAM_ID_MAP vinner)
    """
    teams = set()
    parts = [p.strip() for p in group_list.split(";") if p.strip()]
    for gid in parts:
        # OBS: ändrad ordning här
        team = TEAM_ID_MAP.get(gid) or GROUP_TEAM_MAPPING.get(gid)
        if team:
            teams.add(team)
    return sorted(teams)




async def get_grafana_groups_for_user(username: str) -> str:
    """
    Return a comma-separated list of Grafana "groups" for a user, based on
    GROUP_TEAM_MAPPING and the user's Helix group membership.

    The returned string is intended to be sent in a header, e.g.:
      X-WEBAUTH-GROUPS: GrafanaRole01,GrafanaRoleSecOps
    """
    if username in _TEAM_CACHE:
        return _TEAM_CACHE[username]

    group_list = await get_user_group_list(username)
    if not group_list:
        logger.info(
            f"get_grafana_groups_for_user: no group list for {username}, no grafana groups"
        )
        groups_header = ""
        _TEAM_CACHE[username] = groups_header
        return groups_header

    teams = pick_teams_from_groups(group_list)
    groups_header = ",".join(teams)
    logger.info(
        f"get_grafana_groups_for_user: user={username}, teams={groups_header}"
    )
    _TEAM_CACHE[username] = groups_header
    return groups_header


async def get_grafana_role_for_user(username: str) -> str:
    """
    Return Grafana org role for a user based on Helix group membership.

    Uses GROUP_ROLE_MAPPING (Helix group ID → Viewer/Editor/Admin).
    Falls back to HELIX_DEFAULT_GRAFANA_ROLE if:
      - no group list is found, or
      - none of the groups map to a known org role.
    """
    if username in _ROLE_CACHE:
        return _ROLE_CACHE[username]

    group_list = await get_user_group_list(username)
    if not group_list:
        role = HELIX_DEFAULT_GRAFANA_ROLE
        logger.warning(
            f"get_grafana_role_for_user: no group list for {username}, using default {role}"
        )
        _ROLE_CACHE[username] = role
        return role

    role = pick_role_from_groups(group_list)
    logger.info(
        f"get_grafana_role_for_user: user={username}, groups={group_list}, role={role}"
    )
    _ROLE_CACHE[username] = role
    return role



async def proxy_to_grafana(path: str, request: Request) -> Response:
    """
    Proxy all Grafana traffic (everything not /login, /logout or /helix-api/*):

    - Resolve username via resolve_username()
    - Look up Grafana role based on Helix groups
    - Set:
        * X-WEBAUTH-USER  (who the user is)
        * X-WEBAUTH-ROLE  (which Grafana role the user should have)
    - If no user:
        * AUTH_MODE=local → redirect to /login
        * AUTH_MODE=rsso  → return 401 with a brief error message
    """
    username = resolve_username(request)
    if not username:
        if AUTH_MODE == "rsso":
            # In RSSO mode we expect authentication to be done by reverse proxy.
            # If we cannot see the user here, RSSO configuration is most likely wrong.
            logger.error(
                "No user found in X-Grafana-User, RSSO header or cookie in RSSO mode"
            )
            return HTMLResponse(
                "Ingen användare hittades i varken X-Grafana-User, "
                f"{RSSO_HEADER_NAME} eller {HELIX_USER_COOKIE}-cookie. "
                "Kontrollera RSSO / reverse proxy-konfigurationen.",
                status_code=401,
            )
        else:
            # Local mode: send to our login page.
            logger.info("No user in local mode → redirecting to /login")
            return RedirectResponse(url="/login", status_code=302)

    # Resolve Grafana role + extra Grafana groups based on Helix groups
    role = await get_grafana_role_for_user(username)
    groups_header = await get_grafana_groups_for_user(username)

    # Build URL to Grafana internally
    url = f"{GRAFANA_INTERNAL_URL}/{path}".rstrip("/")

    logger.debug(
        f"Proxying request to Grafana path='{path}' as user='{username}' "
        f"with role='{role}' and groups='{groups_header}'"
    )

    # Copy headers (except Host) + auth proxy headers
    headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}
    headers["X-WEBAUTH-USER"] = username
    # This header is picked up by Grafana via GF_AUTH_PROXY_HEADERS="Role:X-WEBAUTH-ROLE"
    headers["X-WEBAUTH-ROLE"] = role
    # Optional: send comma-separated grafana groups
    if groups_header:
        headers["X-WEBAUTH-GROUPS"] = groups_header


    body = await request.body()

    try:
        async with httpx.AsyncClient(follow_redirects=False, verify=False) as client:
            grafana_resp = await client.request(
                method=request.method,
                url=url,
                headers=headers,
                content=body,
                params=request.query_params,
            )
    except httpx.RequestError as e:
        logger.error(f"Error calling Grafana at {url}: {e}")
        return HTMLResponse(
            f"Kunde inte nå Grafana på {GRAFANA_INTERNAL_URL}. "
            "Troligen startar Grafana fortfarande eller är nedstängd.",
            status_code=502,
        )

    excluded_headers = {"content-encoding", "transfer-encoding", "connection"}
    response_headers = {
        k: v
        for k, v in grafana_resp.headers.items()
        if k.lower() not in excluded_headers
    }

    return Response(
        content=grafana_resp.content,
        status_code=grafana_resp.status_code,
        headers=response_headers,
    )


# =========================
#  LOGIN / LOGOUT (LOCAL MODE)
# =========================

@app.get("/oidc/callback")
async def oidc_callback(
    request: Request,
    code: str = Query(...),
    state: Optional[str] = Query(None),
):
    """
    OIDC callback endpoint.

    Flow:
      1) Verify state against cookie (CSRF protection)
      2) Exchange code for tokens at OIDC_TOKEN_URL
      3) Call OIDC_USERINFO_URL with access token
      4) Read username from OIDC_USERNAME_CLAIM
      5) Set HLX_USER cookie and redirect to "/"
    """
    if AUTH_MODE != "oidc":
        logger.warning("Received /oidc/callback but AUTH_MODE is not 'oidc'")
        return HTMLResponse("OIDC mode is not enabled", status_code=400)

    cookie_state = request.cookies.get(OIDC_STATE_COOKIE)
    if cookie_state and state and cookie_state != state:
        logger.error(f"OIDC state mismatch: cookie={cookie_state}, query={state}")
        return HTMLResponse("Invalid OIDC state", status_code=400)

    if not (OIDC_TOKEN_URL and OIDC_USERINFO_URL and OIDC_CLIENT_ID and OIDC_CLIENT_SECRET):
        logger.error("OIDC token/userinfo endpoints or client credentials are not configured")
        return HTMLResponse("OIDC configuration error", status_code=500)

    # 1) Exchange code for token
    async with httpx.AsyncClient(verify=False) as client:
        try:
            token_resp = await client.post(
                OIDC_TOKEN_URL,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": OIDC_REDIRECT_URI,
                    "client_id": OIDC_CLIENT_ID,
                    "client_secret": OIDC_CLIENT_SECRET,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10.0,
            )
        except httpx.RequestError as e:
            logger.error(f"Error calling OIDC token endpoint: {e}")
            return HTMLResponse("OIDC token request failed", status_code=502)

    if token_resp.status_code != 200:
        logger.error(f"OIDC token endpoint error: {token_resp.status_code} {token_resp.text[:500]}")
        return HTMLResponse("OIDC token endpoint error", status_code=502)

    token_data = token_resp.json()
    access_token = token_data.get("access_token")
    if not access_token:
        logger.error(f"No access_token in OIDC token response: {token_data}")
        return HTMLResponse("OIDC token response missing access_token", status_code=502)

    # 2) Fetch userinfo
    async with httpx.AsyncClient(verify=False) as client:
        try:
            userinfo_resp = await client.get(
                OIDC_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10.0,
            )
        except httpx.RequestError as e:
            logger.error(f"Error calling OIDC userinfo endpoint: {e}")
            return HTMLResponse("OIDC userinfo request failed", status_code=502)

    if userinfo_resp.status_code != 200:
        logger.error(f"OIDC userinfo endpoint error: {userinfo_resp.status_code} {userinfo_resp.text[:500]}")
        return HTMLResponse("OIDC userinfo endpoint error", status_code=502)

    userinfo = userinfo_resp.json()
    username = (
        userinfo.get(OIDC_USERNAME_CLAIM)
        or userinfo.get("preferred_username")
        or userinfo.get("sub")
    )

    if not username:
        logger.error(f"Could not extract username from userinfo: {userinfo}")
        return HTMLResponse("OIDC userinfo response missing username", status_code=502)

    logger.info(f"OIDC login successful for user '{username}'")

    # 3) Set cookie + redirect to root (Grafana UI)
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(
        HELIX_USER_COOKIE,
        username,
        httponly=True,
        secure=SECURE_COOKIES,
        samesite="lax",
    )
    # Clear state cookie
    response.delete_cookie(OIDC_STATE_COOKIE)
    return response


@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    """
    /login:
    - In AUTH_MODE="local": show the visual login page where the user enters
      Helix username + password. We validate via HELIX_JWT_LOGIN_URL and set HLX_USER cookie.
    - In AUTH_MODE="rsso": normally not used; if accessed, show a short info message.
    - In AUTH_MODE="oidc": start OIDC authorization code flow against RSSO/HSSO.
    """
    if AUTH_MODE == "rsso":
        return HTMLResponse(
            "<h2>RSSO-läge är aktiverat</h2>"
            "<p>Autentisering hanteras av RSSO / reverse proxy framför denna tjänst."
            " /login används endast i AUTH_MODE=local eller AUTH_MODE=oidc.</p>",
            status_code=200,
        )

    if AUTH_MODE == "oidc":
        # If user already has a cookie, just go to Grafana
        username = get_cookie_user(request)
        if username:
            logger.debug(f"User '{username}' already logged in via OIDC → redirecting to /")
            return RedirectResponse(url="/", status_code=302)

        # Otherwise start OIDC flow
        auth_url, state = build_oidc_authorization_url()
        logger.info(f"Starting OIDC login, redirecting to IdP, state={state}")

        response = RedirectResponse(url=auth_url, status_code=302)
        # Protect against CSRF: store state in a secure cookie
        response.set_cookie(
            OIDC_STATE_COOKIE,
            state,
            httponly=True,
            secure=SECURE_COOKIES,
            samesite="lax",
        )
        return response

    # AUTH_MODE="local" (default) – existing behavior
    username = get_cookie_user(request)
    if username:
        logger.debug(f"User '{username}' already logged in → redirecting to /")
        return RedirectResponse(url="/", status_code=302)
    # Fancy, responsive login page (only in local mode)
    html = """
    <!DOCTYPE html>
    <html lang="sv">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>Helix Grafana Proxy – Login</title>
      <style>
        :root {
          --bg: #0f172a;
          --bg-card: #020617;
          --accent: #22c55e;
          --accent-soft: rgba(34, 197, 94, 0.15);
          --border: #1f2937;
          --text: #e5e7eb;
          --muted: #9ca3af;
        }

        * {
          box-sizing: border-box;
        }

        body {
          margin: 0;
          font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI",
                       sans-serif;
          background: radial-gradient(circle at top, #1f2937 0, #020617 55%);
          color: var(--text);
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 1.5rem;
        }

        .shell {
          width: 100%;
          max-width: 420px;
        }

        .card {
          background: linear-gradient(135deg, rgba(15,23,42,0.98), rgba(2,6,23,0.98));
          border-radius: 1.25rem;
          border: 1px solid var(--border);
          padding: 2.2rem 2rem 2.1rem;
          box-shadow:
            0 18px 45px rgba(0,0,0,0.65),
            0 0 0 1px rgba(15,23,42,0.8);
          backdrop-filter: blur(14px);
        }

        .badge {
          display: inline-flex;
          align-items: center;
          gap: 0.4rem;
          padding: 0.2rem 0.7rem;
          border-radius: 999px;
          font-size: 0.7rem;
          text-transform: uppercase;
          letter-spacing: 0.12em;
          background: var(--accent-soft);
          color: var(--accent);
          margin-bottom: 0.8rem;
        }

        .badge-dot {
          width: 7px;
          height: 7px;
          border-radius: 999px;
          background: var(--accent);
          box-shadow: 0 0 0 4px rgba(34,197,94,0.25);
        }

        h1 {
          margin: 0 0 0.35rem;
          font-size: 1.5rem;
          font-weight: 600;
        }

        .subtitle {
          margin: 0 0 1.8rem;
          font-size: 0.9rem;
          color: var(--muted);
        }

        .subtitle span {
          color: var(--accent);
        }

        form {
          display: flex;
          flex-direction: column;
          gap: 1rem;
        }

        label {
          font-size: 0.8rem;
          text-transform: uppercase;
          letter-spacing: 0.08em;
          color: var(--muted);
          margin-bottom: 0.25rem;
        }

        .field {
          display: flex;
          flex-direction: column;
        }

        input[type="text"],
        input[type="password"] {
          width: 100%;
          border-radius: 0.75rem;
          border: 1px solid var(--border);
          padding: 0.6rem 0.85rem;
          font-size: 0.9rem;
          background: rgba(15,23,42,0.9);
          color: var(--text);
          outline: none;
          transition: border-color 120ms ease, box-shadow 120ms ease,
                      background-color 120ms ease, transform 80ms ease;
        }

        input::placeholder {
          color: #6b7280;
        }

        input:focus {
          border-color: var(--accent);
          box-shadow: 0 0 0 1px rgba(34,197,94,0.35);
          background: rgba(15,23,42,1);
          transform: translateY(-1px);
        }

        .actions {
          margin-top: 0.6rem;
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
        }

        button {
          border: none;
          border-radius: 999px;
          padding: 0.65rem 1rem;
          font-size: 0.9rem;
          font-weight: 500;
          cursor: pointer;
          background: linear-gradient(135deg, #22c55e, #4ade80);
          color: #020617;
          display: inline-flex;
          align-items: center;
          justify-content: center;
          gap: 0.4rem;
          box-shadow:
            0 10px 25px rgba(34,197,94,0.35),
            0 0 0 1px rgba(15,23,42,0.6);
          transition: transform 80ms ease, box-shadow 80ms ease,
                      filter 80ms ease, background-position 80ms ease;
          background-size: 140% 140%;
          background-position: 0 50%;
        }

        button:hover {
          transform: translateY(-1px);
          box-shadow:
            0 14px 30px rgba(34,197,94,0.45),
            0 0 0 1px rgba(15,23,42,0.6);
          filter: brightness(1.02);
          background-position: 20% 50%;
        }

        button:active {
          transform: translateY(0);
          box-shadow:
            0 8px 20px rgba(34,197,94,0.32),
            0 0 0 1px rgba(15,23,42,0.6);
        }

        .button-icon {
          font-size: 1.05rem;
        }

        .footnote {
          font-size: 0.75rem;
          color: var(--muted);
          text-align: center;
        }

        .footnote span {
          color: var(--accent);
        }

        .brand {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 1.1rem;
          gap: 0.75rem;
        }

        .brand-mark {
          font-size: 0.8rem;
          color: var(--muted);
          text-align: right;
        }

        .brand-mark strong {
          color: var(--accent);
          font-weight: 500;
        }

        @media (max-width: 480px) {
          .card {
            padding: 1.7rem 1.4rem 1.6rem;
            border-radius: 1rem;
          }
          h1 {
            font-size: 1.25rem;
          }
        }
      </style>
    </head>
    <body>
      <div class="shell">
        <div class="card">
          <div class="brand">
            <div>
              <div class="badge">
                <span class="badge-dot"></span>
                <span>Secure Access</span>
              </div>
              <h1>Helix Grafana Proxy</h1>
              <p class="subtitle">
                Logga in med ditt <span>Helix-konto</span> för att komma åt dashboards.
              </p>
            </div>
            <div class="brand-mark">
              <strong>Helix</strong><br/>
              Grafana Bridge
            </div>
          </div>

          <form method="post" action="/login">
            <div class="field">
              <label for="username">Användarnamn</label>
              <input
                type="text"
                id="username"
                name="username"
                placeholder="t.ex. jdoe"
                autocomplete="username"
                required
              />
            </div>

            <div class="field">
              <label for="password">Lösenord</label>
              <input
                type="password"
                id="password"
                name="password"
                placeholder="Ditt Helix-lösenord"
                autocomplete="current-password"
                required
              />
            </div>

            <div class="actions">
              <button type="submit">
                <span class="button-icon">⮕</span>
                <span>Logga in och öppna Grafana</span>
              </button>
              <p class="footnote">
                Inloggningen används för att köra BMC Helix REST API-anrop
                som <span>din användare</span> i Grafana (via impersonation)
                och sätta rätt <span>Grafana-roll</span> baserat på Helix-grupper.
              </p>
            </div>
          </form>
        </div>
      </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.post("/login")
async def login_submit(username: str = Form(...), password: str = Form(...)):
    """
    Handle login form submission (only in AUTH_MODE=local), validate Helix
    credentials via JWT login, and set a cookie with Helix login name (HLX_USER).
    """
    if AUTH_MODE == "rsso":
        return JSONResponse(
            {"error": "Login via form is disabled in AUTH_MODE=rsso"},
            status_code=400,
        )

    logger.info(f"Login attempt for user '{username}'")

    ok = await login_against_helix(username, password)
    if not ok:
        logger.warning(f"Login failed for user '{username}'")
        html = """
        <html>
          <body>
            <h2>Inloggning misslyckades</h2>
            <a href="/login">Försök igen</a>
          </body>
        </html>
        """
        return HTMLResponse(content=html, status_code=401)

    logger.info(f"User '{username}' logged in successfully")

    resp = RedirectResponse(url="/", status_code=302)
    # In production: set secure=True and samesite according to your environment
    resp.set_cookie(HELIX_USER_COOKIE, username, httponly=False)
    return resp


@app.get("/logout")
async def logout():
    """
    Log out from the proxy (remove our own user cookie).
    Applies only to AUTH_MODE=local. In RSSO mode, logout is normally
    handled by RSSO itself.
    """
    resp = RedirectResponse(url="/login", status_code=302)
    resp.delete_cookie(HELIX_USER_COOKIE)
    return resp


# =========================
#  HELIX DATA-ENDPOINT
# =========================

@app.api_route("/helix-api/{form_name}", methods=["GET", "POST"])
async def helix_form_proxy(form_name: str, request: Request):
    logger.debug(
        f"helix_form_proxy: method={request.method}, "
        f"path={request.url.path}, query={dict(request.query_params)}"
    )

    # ENDA sättet att få user: header (X-Grafana-User), RSSO eller cookie
    username = resolve_username(request)

    if not username:
        logger.warning("helix_form_proxy: no logged in user (no header/cookie)")
        return JSONResponse({"error": "Not logged in to proxy"}, status_code=401)

    if form_name not in ALLOWED_FORMS:
        logger.warning(f"helix_form_proxy: form '{form_name}' not in allowed list")
        return JSONResponse({"error": "Form not allowed"}, status_code=403)

    helix_url = f"{HELIX_BASE_URL}/api/arsys/v1/entry/{form_name}"
    logger.debug(f"helix_form_proxy: user={username}, url={helix_url}")

    token = await get_admin_token()
    if not token:
        return JSONResponse({"error": "Failed to get admin token"}, status_code=502)

    impersonated_b64 = base64.b64encode(username.encode("utf-8")).decode("ascii")

    # Skicka vidare original-queryn (minus ev. interna parametrar om du lägger till såna)
    original_params = dict(request.query_params)

    async with httpx.AsyncClient(verify=False) as client:
        resp = await client.get(
            helix_url,
            headers={
                "Authorization": f"AR-JWT {token}",
                "X-AR-Impersonated-User": impersonated_b64,
            },
            params=original_params,
            timeout=15.0,
        )

        if resp.status_code in (401, 403):
            logger.warning("Admin token possibly expired, refreshing...")
            new_token = await get_admin_token(force_refresh=True)
            if not new_token:
                return JSONResponse(
                    {"error": "Failed to refresh admin token"},
                    status_code=502,
                )
            resp = await client.get(
                helix_url,
                headers={
                    "Authorization": f"AR-JWT {new_token}",
                    "X-AR-Impersonated-User": impersonated_b64,
                },
                params=original_params,
                timeout=15.0,
            )

    if resp.status_code != 200:
        logger.error(
            f"Helix REST error for form '{form_name}' as user='{username}': "
            f"status={resp.status_code}, body={resp.text[:500]}"
        )
        return JSONResponse(
            {
                "error": "Helix REST error",
                "status_code": resp.status_code,
                "body": resp.text[:500],
            },
            status_code=resp.status_code,
        )

    return JSONResponse(resp.json())

class UserSyncPayload(BaseModel):
    action: Literal["create", "update", "delete"]

    # Helix-fält, men med Python-vänliga namn + alias
    login_name: str = Field(alias="Login Name")
    full_name: Optional[str] = Field(None, alias="Full Name")
    email_address: Optional[str] = Field(None, alias="Email Address")
    group_list: Optional[str] = Field(None, alias="Group List")


class TeamSyncPayload(BaseModel):
    action: Literal["create", "update", "delete"]

    # Helix-fältnamn via alias
    group_name: str = Field(alias="Group Name")
    # Kan komma som int eller str → tillåt båda
    group_id: Optional[str | int] = Field(None, alias="Group ID")

    # email kan komma från Helix (antingen i entry_details eller top-level)
    email: Optional[str] = None



@app.post("/webhook/grafana/user")
async def sync_user(request: Request):
    """
    Webhook som Helix kan anropa för att skapa/uppdatera/ta bort användare i Grafana.

    Payload från Helix ser ut ungefär så här:
    {
      "record_id": "...",
      "webhook_id": "...",
      "entry_details": {
        "Login Name": "Demo",
        "Full Name": "Demo User",
        "Email Address": "demo@example.com",
        "Group List": "400001;410001;420001;"
      },
      "action": "update",
      "shared_secret": "super-hemligt-värde-här",
      "entry_event": "Update",
      "form_name": "User",
      "entry_id": "..."
    }
    """
    raw_body = await request.body()
    logger.debug(
        "Webhook /webhook/grafana/user – incoming request\n"
        f"  method: {request.method}\n"
        f"  url   : {request.url}\n"
        f"  headers: {dict(request.headers)}\n"
        f"  body  : {raw_body.decode('utf-8', 'ignore')}"
    )

    # 1) JSON-dekod
    try:
        data = json.loads(raw_body.decode("utf-8"))
    except json.JSONDecodeError as e:
        logger.warning(f"Invalid JSON in /webhook/grafana/user: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # 2) Verifiera shared_secret i toppnivån (eller ev. custom_json)
    verify_webhook_data(data)

    # 3) Plocka ut entry_details (själva Helix-recordet)
    entry_details = data.get("entry_details") or {}
    if not isinstance(entry_details, dict):
        logger.warning("entry_details saknas eller är inte ett objekt")
        raise HTTPException(status_code=400, detail="Missing or invalid entry_details")

    action = data.get("action")
    if not action:
        logger.warning("Webhook saknar 'action'-fält")
        raise HTTPException(status_code=400, detail="Missing action in webhook payload")

    # 4) Bygg dict: action + alla fält i entry_details
    payload_data = {"action": action}
    payload_data.update(entry_details)

    # 5) Låt Pydantic göra jobbet med aliasen ("Login Name" etc.)
    try:
        payload = UserSyncPayload.model_validate(payload_data)
    except Exception as e:
        logger.error(f"Validation error in UserSyncPayload: {e}")
        raise HTTPException(status_code=400, detail="Invalid user payload")

    # ====== härifrån är din tidigare logik som innan ======

    login = payload.login_name
    name = payload.full_name or payload.login_name
    email = payload.email_address or f"{login}@local"
    group_list = payload.group_list or ""

    # Cacha Group List för användaren (för senare resync när nya teams dyker upp)
    _GROUP_LIST_CACHE[login] = group_list


    # 1) Slå upp användaren på login
    lookup = await grafana_request(
        "GET", "/api/users/lookup", params={"loginOrEmail": login}
    )

    existing_user = None
    if lookup.status_code == 200:
        existing_user = lookup.json()  # innehåller bl.a. "id"

    # DELETE
    if payload.action == "delete":
        if not existing_user:
            return {"status": "ok", "info": "user not found, nothing to delete"}

        uid = existing_user["id"]
        resp = await grafana_request("DELETE", f"/api/admin/users/{uid}")
        return {"status": "ok", "grafana_status": resp.status_code}

    # CREATE (om user saknas och action=create eller update)
    if payload.action in ("create", "update") and not existing_user:
        body = {
            "name": name,
            "login": login,
            "email": email,
            "password": "changeme-not-used",
        }
        resp = await grafana_request("POST", "/api/admin/users", json=body)
        if resp.status_code not in (200, 201):
            return JSONResponse(
                {"error": "failed to create user in grafana", "body": resp.text},
                status_code=500,
            )
        existing_user = resp.json()

    # Om vi fortfarande inte har en user här är det fel (t.ex. action=update på icke-befintlig)
    if not existing_user:
        return JSONResponse(
            {"error": "user does not exist in grafana", "login": login},
            status_code=404,
        )

    uid = existing_user["id"]

    # 2) Uppdatera basic info
    resp_update = None
    if payload.action in ("create", "update"):
        body = {
            "name": name or existing_user.get("name") or login,
            "login": login,
            "email": email or existing_user.get("email") or f"{login}@local",
        }
        resp_update = await grafana_request(
            "PUT", f"/api/admin/users/{uid}", json=body
        )

    # 3) Beräkna org-roll + teams från Group List
    role = pick_role_from_groups(group_list) if group_list else HELIX_DEFAULT_GRAFANA_ROLE
    teams = pick_teams_from_groups(group_list) if group_list else []

    # 3a) Sätt org-roll
    resp_role = None
    if role:
        body_role = {"role": role}
        resp_role = await grafana_request(
            "PATCH", f"/api/org/users/{uid}", json=body_role
        )

    # 3b) Synka team-medlemskap baserat på teams-listan
    team_sync_result = None
    if teams and payload.action in ("create", "update"):
        desired_names = set(teams)

        # Slå upp alla önskade teams
        desired_ids: set[int] = set()
        missing_teams: list[str] = []

        for name_ in desired_names:
            team = await grafana_find_team_by_name(name_)
            if not team:
                logger.warning(f"Team '{name_}' finns inte i Grafana (hoppar över).")
                missing_teams.append(name_)
                continue
            desired_ids.add(team["id"])

        # Hämta nuvarande medlemskap
        current = await grafana_get_user_teams(uid)
        current_ids = {t["teamId"] for t in current}

        to_add = desired_ids - current_ids
        to_remove = current_ids - desired_ids

        add_results = []
        for tid in to_add:
            body = {"userId": uid, "role": "Member"}
            r = await grafana_request("POST", f"/api/teams/{tid}/members", json=body)
            add_results.append({"team_id": tid, "status": r.status_code})

        remove_results = []
        for tid in to_remove:
            r = await grafana_request("DELETE", f"/api/teams/{tid}/members/{uid}")
            remove_results.append({"team_id": tid, "status": r.status_code})

        team_sync_result = {
            "added": add_results,
            "removed": remove_results,
            "missing_teams": missing_teams,
        }

    return {
        "status": "ok",
        "user_id": uid,
        "role": role,
        "update_status": resp_update.status_code if resp_update else None,
        "role_status": resp_role.status_code if resp_role else None,
        "teams": team_sync_result,
    }


async def grafana_find_team_by_name(name: str):
    resp = await grafana_request("GET", "/api/teams/search", params={"name": name})
    if resp.status_code != 200:
        logger.error(f"Failed to search team '{name}': {resp.text[:200]}")
        return None
    data = resp.json()
    teams = data.get("teams") or []
    return teams[0] if teams else None

async def grafana_get_user_teams(user_id: int):
    resp = await grafana_request("GET", f"/api/teams/user/{user_id}")
    if resp.status_code != 200:
        logger.error(f"Failed to get teams for user {user_id}: {resp.text[:200]}")
        return []
    return resp.json()  # lista med { teamId, teamName, ... }


async def sync_user_teams_for_login(login: str, group_list: str):
    """
    Synka Grafana-team-medlemskap för en användare baserat på Helix Group List.

    Används:
      - indirekt från team-webhooken när ett nytt team skapas för ett Group ID
        som vissa användare redan har i sin group_list.
    """
    teams = pick_teams_from_groups(group_list)
    if not teams:
        logger.info(f"sync_user_teams_for_login: user={login} har inga teams att synka")
        return

    # 1) Slå upp Grafana-user
    lookup = await grafana_request(
        "GET", "/api/users/lookup", params={"loginOrEmail": login}
    )
    if lookup.status_code != 200:
        logger.warning(
            f"sync_user_teams_for_login: kunde inte slå upp user '{login}' i Grafana, "
            f"status={lookup.status_code}, body={lookup.text[:200]}"
        )
        return

    user = lookup.json()
    uid = user.get("id")
    if uid is None:
        logger.warning(
            f"sync_user_teams_for_login: lookup-result saknar 'id' för login={login}"
        )
        return

    desired_names = set(teams)

    # 2) Slå upp alla önskade teams i Grafana
    desired_ids: set[int] = set()
    missing_teams: list[str] = []

    for name in desired_names:
        team = await grafana_find_team_by_name(name)
        if not team:
            logger.warning(
                f"sync_user_teams_for_login: Team '{name}' finns inte i Grafana (hoppar över)."
            )
            missing_teams.append(name)
            continue
        desired_ids.add(team["id"])

    if not desired_ids:
        logger.info(
            f"sync_user_teams_for_login: user={login} har inga befintliga Grafana-teams att synka"
        )
        return

    # 3) Hämta nuvarande medlemskap
    current = await grafana_get_user_teams(uid)
    current_ids = {t["teamId"] for t in current}

    to_add = desired_ids - current_ids
    to_remove = current_ids - desired_ids

    add_results = []
    for tid in to_add:
        body = {"userId": uid, "role": "Member"}
        r = await grafana_request("POST", f"/api/teams/{tid}/members", json=body)
        add_results.append({"team_id": tid, "status": r.status_code})

    remove_results = []
    for tid in to_remove:
        r = await grafana_request("DELETE", f"/api/teams/{tid}/members/{uid}")
        remove_results.append({"team_id": tid, "status": r.status_code})

    logger.info(
        "sync_user_teams_for_login: färdig sync "
        f"user={login}, added={add_results}, removed={remove_results}, "
        f"missing={missing_teams}"
    )

async def resync_users_for_group_id(group_id: str):
    """
    När ett nytt team skapas/uppdateras för ett visst Helix Group ID
    (t.ex. 410002) vill vi synka alla användare som har den gruppen i sin
    Group List – även om podden precis startat och vår cache är tom.

    Vi frågar Helix User-formen efter alla users vars Group List innehåller
    ;<group_id>; och synkar sedan deras team-medlemskap i Grafana.
    """
    token = await get_admin_token()
    if not token:
        logger.error("resync_users_for_group_id: no admin token available")
        return

    # Bygg Helix-qualification:
    #   'Group List' LIKE "%;410002;%"
    pattern = f"%;{group_id};%"
    qualification = f"'{HELIX_USER_GROUP_FIELD}' LIKE \"{pattern}\""

    params = {
        "q": qualification,
        "fields": f"values({HELIX_USER_LOGIN_FIELD},{HELIX_USER_GROUP_FIELD})",
    }

    url = f"{HELIX_BASE_URL}/api/arsys/v1/entry/{HELIX_USER_FORM}"

    logger.info(
        f"resync_users_for_group_id: hämtar users från Helix med group_id={group_id}, "
        f"q={qualification}"
    )

    async with httpx.AsyncClient(verify=False) as client:
        try:
            resp = await client.get(
                url,
                headers={"Authorization": f"AR-JWT {token}"},
                params=params,
                timeout=20.0,
            )
        except httpx.RequestError as e:
            logger.error(f"resync_users_for_group_id: error calling Helix: {e}")
            return

    if resp.status_code != 200:
        logger.error(
            f"resync_users_for_group_id: Helix error {resp.status_code}, body={resp.text[:500]}"
        )
        return

    data = resp.json()
    entries = data.get("entries", [])

    if not entries:
        logger.info(
            f"resync_users_for_group_id: inga users i Helix med group_id={group_id}"
        )
        return

    affected_users: list[str] = []

    for entry in entries:
        values = entry.get("values", {})
        login = values.get(HELIX_USER_LOGIN_FIELD)
        group_list = values.get(HELIX_USER_GROUP_FIELD)

        if not login or not group_list:
            continue

        if not isinstance(group_list, str):
            group_list = str(group_list)

        affected_users.append(login)

        # Uppdatera cache så den är “up to date”
        _GROUP_LIST_CACHE[login] = group_list

        try:
            await sync_user_teams_for_login(login, group_list)
        except Exception as e:
            logger.error(
                f"resync_users_for_group_id: fel vid sync för user={login}: {e}"
            )

    logger.info(
        f"resync_users_for_group_id: färdig resync för group_id={group_id}, "
        f"users={affected_users}"
    )



@app.post("/webhook/grafana/team")
async def sync_team(request: Request):
    """
    Webhook för att skapa/uppdatera/ta bort Grafana-teams (grupper).

    Typisk payload från Helix:
    {
      "record_id": "...",
      "webhook_id": "...",
      "entry_details": {
        "Group Name": "GRP_Grafana_FolderPermission01",
        "Group ID": 410001
      },
      "action": "update",
      "shared_secret": "super-hemligt-värde-här",
      "entry_event": "Update",
      "form_name": "Group",
      "entry_id": "...",
      "email": "noreply@me.com"
    }
    """
    raw_body = await request.body()
    logger.debug(
        "Webhook /webhook/grafana/team – incoming request\n"
        f"  method: {request.method}\n"
        f"  url   : {request.url}\n"
        f"  headers: {dict(request.headers)}\n"
        f"  body  : {raw_body.decode('utf-8', 'ignore')}"
    )

    try:
        data = json.loads(raw_body.decode("utf-8"))
    except json.JSONDecodeError as e:
        logger.warning(f"Invalid JSON in /webhook/grafana/team: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Verifiera shared_secret på toppnivån
    verify_webhook_data(data)

    entry_details = data.get("entry_details") or {}
    if not isinstance(entry_details, dict):
        logger.warning("entry_details saknas eller är inte ett objekt (team)")
        raise HTTPException(status_code=400, detail="Missing or invalid entry_details")

    action = data.get("action")
    if not action:
        logger.warning("Team-webhook saknar 'action'-fält")
        raise HTTPException(status_code=400, detail="Missing action in webhook payload")

    # Bygg payload_data: action + entry_details (+ ev. email från toppnivån)
    payload_data = {"action": action}
    payload_data.update(entry_details)

    # Top-level email från Helix (om den finns)
    if "email" in data and "email" not in payload_data:
        payload_data["email"] = data["email"]

    try:
        payload = TeamSyncPayload.model_validate(payload_data)
    except Exception as e:
        logger.error(f"Validation error in TeamSyncPayload: {e}")
        raise HTTPException(status_code=400, detail="Invalid team payload")

    name = payload.group_name
    email = payload.email or ""

    # Normalisera group_id till str (Helix skickar ofta 410001 som int)
    raw_group_id = payload.group_id
    group_id = str(raw_group_id).strip() if raw_group_id not in (None, "") else None

    # Slå upp teamet i Grafana
    existing = await grafana_find_team_by_name(name)

    # DELETE
    if payload.action == "delete":
        if not existing:
            # Rensa ev. cache om vi har ett id
            if group_id and group_id in TEAM_ID_MAP:
                TEAM_ID_MAP.pop(group_id, None)
            return {"status": "ok", "info": "team not found, nothing to delete"}

        tid = existing["id"]
        resp = await grafana_request("DELETE", f"/api/teams/{tid}")

        if group_id and group_id in TEAM_ID_MAP:
            TEAM_ID_MAP.pop(group_id, None)

        return {"status": "ok", "grafana_status": resp.status_code}

    # CREATE (om team saknas och action=create eller update)
    if payload.action in ("create", "update") and not existing:
        body = {
            "name": name,
            "email": email,
        }
        resp = await grafana_request("POST", "/api/teams", json=body)
        logger.debug(
            f"Grafana API POST /api/teams -> {resp.status_code}, body={resp.text[:200]}"
        )
        if resp.status_code not in (200, 201):
            return JSONResponse(
                {"error": "failed to create team in grafana", "body": resp.text},
                status_code=500,
            )

        # Viktigt: POST-svaret innehåller bara message + teamId, så
        # vi hämtar teamet igen för att få full info inkl. 'id'.
        existing = await grafana_find_team_by_name(name)
        if not existing:
            logger.error(
                "Team created in Grafana men kunde inte hittas via /api/teams/search"
            )
            return JSONResponse(
                {
                    "error": "team created but not found in grafana",
                    "name": name,
                    "grafana_response": resp.text[:200],
                },
                status_code=500,
            )

    if not existing:
        return JSONResponse(
            {"error": "team does not exist in grafana", "name": name},
            status_code=404,
        )

    # UPDATE (ändra mail/namn – i ditt fall framför allt mail)
    tid = existing["id"]
    if payload.action in ("create", "update"):
        body = {
            "name": name,
            "email": email or existing.get("email") or "",
        }
        resp_upd = await grafana_request("PUT", f"/api/teams/{tid}", json=body)

        # Uppdatera vår karta Helix Group ID -> Grafana-teamnamn
        if group_id:
            TEAM_ID_MAP[group_id] = name
            logger.info(f"TEAM_ID_MAP[{group_id}] = {name}")

            # Nyckeln: resynca alla cachade användare som har denna grupp
            await resync_users_for_group_id(group_id)

        return {
            "status": "ok",
            "team_id": tid,
            "update_status": resp_upd.status_code,
            "group_id": group_id,
        }


    return {"status": "ok"}


# =========================
#  HEALTH CHECK
# =========================

@app.get("/healthz")
async def healthz():
    """Simple health endpoint for liveness/readiness checks."""
    return {"status": "ok"}


# =========================
#  GRAFANA LIVE WEBSOCKET STUB
# =========================

@app.websocket("/api/live/ws")
async def grafana_live_stub(websocket: WebSocket):
    """
    Stub endpoint for Grafana Live WebSocket.

    - Accepts the WebSocket connection so Grafana does not see 403.
    - Does not actively read or write any messages.
    - Just keeps the connection open until the client disconnects.

    This avoids noisy 403 logs from uvicorn when Grafana frontend
    tries to connect to /api/live/ws.
    """
    await websocket.accept()
    logger.debug("Grafana Live WebSocket connected (stub)")

    try:
        # Keep the connection open until the client disconnects.
        # We don't need to read any data, just sleep in a loop.
        while True:
            await asyncio.sleep(60)
    except WebSocketDisconnect:
        logger.debug("Grafana Live WebSocket disconnected (stub)")
    except Exception as e:
        # In case of cancellation or other unexpected errors
        logger.debug(f"Grafana Live WebSocket closed with error (stub): {e}")


# =========================
#  CATCH-ALL → GRAFANA
# =========================

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def grafana_catch_all(path: str, request: Request):
    """
    All traffic that does not match /login, /logout, /helix-api/* or /api/live/ws
    is proxied to Grafana.
    """
    return await proxy_to_grafana(path, request)
