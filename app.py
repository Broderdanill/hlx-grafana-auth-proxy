import os
import base64
import logging
import asyncio
from typing import Optional, Dict

from fastapi import FastAPI, Request, Response, Form, WebSocket
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

# Helix REST base URL
HELIX_BASE_URL = os.getenv("HELIX_BASE_URL", "https://helix.example.com")

# JWT login endpoint for both user and service account
# In most cases: https://<helix>/api/jwt/login
HELIX_JWT_LOGIN_URL = os.getenv(
    "HELIX_JWT_LOGIN_URL",
    f"{HELIX_BASE_URL}/api/jwt/login",
)

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
GROUP_ROLE_MAPPING = parse_group_role_mapping(RAW_GROUP_ROLE_MAPPING)

logger.info(f"Allowed Helix forms: {ALLOWED_FORMS}")
logger.info(f"AUTH_MODE: {AUTH_MODE}, RSSO_HEADER_NAME: {RSSO_HEADER_NAME}")
logger.debug(f"GROUP_ROLE_MAPPING: {GROUP_ROLE_MAPPING}")
logger.debug(f"HELIX_USER_FORM: {HELIX_USER_FORM}")
logger.debug(f"HELIX_USER_LOGIN_FIELD: {HELIX_USER_LOGIN_FIELD}")
logger.debug(f"HELIX_USER_GROUP_FIELD: {HELIX_USER_GROUP_FIELD}")
logger.info(f"HELIX_DEFAULT_GRAFANA_ROLE: {HELIX_DEFAULT_GRAFANA_ROLE}")

app = FastAPI()

# Cache for service account admin token (AR-JWT)
_ADMIN_TOKEN: Optional[str] = None

# Cache for Grafana role per user (username -> role)
_ROLE_CACHE: Dict[str, str] = {}

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


async def get_grafana_role_for_user(username: str) -> str:
    """
    Return Grafana role for a user based on Helix group membership.

    Flow:
      - Check cache (_ROLE_CACHE)
      - If not cached:
          * Read group list from Helix User form
          * Map group IDs → role via GROUP_ROLE_MAPPING
          * Store in cache and return

    On error or if no groups match:
      - Return HELIX_DEFAULT_GRAFANA_ROLE (e.g. "Viewer").
    """
    if username in _ROLE_CACHE:
        return _ROLE_CACHE[username]

    group_list = await fetch_user_groups(username)
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

    # Resolve Grafana role based on Helix groups
    role = await get_grafana_role_for_user(username)

    # Build URL to Grafana internally
    url = f"{GRAFANA_INTERNAL_URL}/{path}".rstrip("/")

    logger.debug(
        f"Proxying request to Grafana path='{path}' as user='{username}' with role='{role}'"
    )

    # Copy headers (except Host) + auth proxy headers
    headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}
    headers["X-WEBAUTH-USER"] = username
    # This header is picked up by Grafana via GF_AUTH_PROXY_HEADERS="Role:X-WEBAUTH-ROLE"
    headers["X-WEBAUTH-ROLE"] = role

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

@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    """
    /login:
    - In AUTH_MODE="local": show the visual login page where the user enters
      Helix username + password. We validate via HELIX_JWT_LOGIN_URL and set HLX_USER cookie.
    - In AUTH_MODE="rsso": normally not used; if accessed, show a short info message.
    """
    if AUTH_MODE == "rsso":
        return HTMLResponse(
            "<h2>RSSO-läge är aktiverat</h2>"
            "<p>Autentisering hanteras av RSSO / reverse proxy framför denna tjänst."
            " /login används endast i AUTH_MODE=local.</p>",
            status_code=200,
        )

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
