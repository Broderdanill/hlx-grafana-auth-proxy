import os
import base64
from typing import Optional, Dict

from fastapi import FastAPI, Request, Response, Form
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
import httpx

# =========================
#  KONFIGURATION / ENV
# =========================

# Intern URL där Grafana lyssnar (inne i POD:en / network namespace)
GRAFANA_INTERNAL_URL = os.getenv("GRAFANA_INTERNAL_URL", "http://127.0.0.1:3000")

# Helix REST-bas
HELIX_BASE_URL = os.getenv("HELIX_BASE_URL", "https://helix.example.com")

# JWT-login endpoint för både användare och servicekonto
# I de flesta fall: https://<helix>/api/jwt/login
HELIX_JWT_LOGIN_URL = os.getenv(
    "HELIX_JWT_LOGIN_URL",
    f"{HELIX_BASE_URL}/api/jwt/login",
)

# Servicekonto (admin / technical user) som används för impersonation mot Helix
HELIX_ADMIN_USER = os.getenv("HELIX_ADMIN_USER", "svc_helix_reports")
HELIX_ADMIN_PASSWORD = os.getenv("HELIX_ADMIN_PASSWORD", "changeme")

# Cookie-namn där vi lagrar användarnamnet vid "local" login
HELIX_USER_COOKIE = "HLX_USER"

# AUTH_MODE styr hur autentisering görs:
#  - "local" (default): egen login-sida mot Helix JWT-login (username + password)
#  - "rsso": användare autentiseras externt via RSSO / reverse proxy, t.ex. header X-RSSO-USER
AUTH_MODE = os.getenv("AUTH_MODE", "local").lower()

# RSSO_HEADER_NAME används bara om AUTH_MODE="rsso"
# Reverse proxy framför denna app ska då sätta t.ex. X-RSSO-USER: <loginName>
RSSO_HEADER_NAME = os.getenv("RSSO_HEADER_NAME", "X-RSSO-USER")

# Whitelist av Helix-formulär (kommaseparerad lista)
# Exempel: "User,Group,HPD:IncidentInterface"
RAW_ALLOWED_FORMS = os.getenv("HELIX_ALLOWED_FORMS", "")

# Formulär + fält som används för att läsa användarens grupper
# Default-formulär: "User"
HELIX_USER_FORM = os.getenv("HELIX_USER_FORM", "User")
# Fältet för login-namnet i User-formuläret (som Helix använder)
HELIX_USER_LOGIN_FIELD = os.getenv("HELIX_USER_LOGIN_FIELD", "Login Name")
# Fältet som innehåller grupp-strängen, t.ex. "1;400003;12321;"
HELIX_USER_GROUP_FIELD = os.getenv("HELIX_USER_GROUP_FIELD", "Group List")

# Mappning från Helix-grupp-ID → Grafana-roll
# Default-exempel: 400001=Viewer, 400002=Editor, 400003=Admin
# Format: "400001:Viewer,400002:Editor,400003:Admin"
RAW_GROUP_ROLE_MAPPING = os.getenv(
    "HELIX_GROUP_ROLE_MAPPING",
    "400001:Viewer,400002:Editor,400003:Admin",
)

# Defaultroll om ingen matchande grupp hittas eller om Helix-queryn misslyckas
HELIX_DEFAULT_GRAFANA_ROLE = os.getenv("HELIX_DEFAULT_GRAFANA_ROLE", "Viewer")


def parse_form_whitelist(value: str):
    """
    'User,Group,HPD:IncidentInterface'
    -> ['User', 'Group', 'HPD:IncidentInterface']
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

print("Allowed Helix forms:", ALLOWED_FORMS)
print("AUTH_MODE:", AUTH_MODE, "RSSO_HEADER_NAME:", RSSO_HEADER_NAME)
print("GROUP_ROLE_MAPPING:", GROUP_ROLE_MAPPING)
print("HELIX_USER_FORM:", HELIX_USER_FORM)
print("HELIX_USER_LOGIN_FIELD:", HELIX_USER_LOGIN_FIELD)
print("HELIX_USER_GROUP_FIELD:", HELIX_USER_GROUP_FIELD)
print("HELIX_DEFAULT_GRAFANA_ROLE:", HELIX_DEFAULT_GRAFANA_ROLE)

app = FastAPI()

# Cache för servicekontots admin-token (AR-JWT)
_ADMIN_TOKEN: Optional[str] = None

# Cache för användarens grafana-roll (username -> role)
_ROLE_CACHE: Dict[str, str] = {}

# Enkel prioritering för roller om en användare har flera grupper
ROLE_PRIORITY = {
    "Viewer": 1,
    "Editor": 2,
    "Admin": 3,
}


# =========================
#  HJÄLPFUNKTIONER
# =========================

def resolve_username(request: Request) -> Optional[str]:
    """
    Hitta aktuell användare beroende på var anropet kommer ifrån och AUTH_MODE.

    Prioritet:

    1) X-Grafana-User
       - När Grafana dataproxy anropar denna app (t.ex. /helix-api/User) och
         GF_DATAPROXY_SEND_USER_HEADER=true, skickas grafana-username i denna header.
       - Detta är vår bästa källa för "vem kör queryn?" i backend-läge.

    2) RSSO-header (om AUTH_MODE="rsso")
       - Reverse proxy eller RSSO-agent framför denna app sätter t.ex. X-RSSO-USER: <loginName>

    3) HLX_USER-cookie
       - Sätts endast vid "local" login (manuell inloggning via /login).
    """
    # 1. Backend-anrop från Grafana dataproxy
    hdr = request.headers.get("X-Grafana-User")
    if hdr:
        return hdr

    # 2. RSSO-läge: lita på headern från reverse proxy
    if AUTH_MODE == "rsso":
        hdr = request.headers.get(RSSO_HEADER_NAME)
        if hdr:
            return hdr

    # 3. Fallback: vår egen cookie (framförallt i local-läge)
    return request.cookies.get(HELIX_USER_COOKIE)


def get_cookie_user(request: Request) -> Optional[str]:
    """
    Används endast vid browser-login (/login) i local-läge.
    """
    return request.cookies.get(HELIX_USER_COOKIE)


async def login_against_helix(username: str, password: str) -> bool:
    """
    LOCAL AUTH-LOGIK:
    Verifiera användarens Helix-login genom att anropa JWT-login med username+password.
    Vi använder bara statuskod 200/icke-200 för att avgöra om login lyckades.

    OBS: tokenet som returneras används INTE för queries (vi kör impersonation via servicekonto).
    """
    async with httpx.AsyncClient(verify=False) as client:
        try:
            resp = await client.post(
                HELIX_JWT_LOGIN_URL,
                data={"username": username, "password": password},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10.0,
            )
        except httpx.RequestError as e:
            print("Error calling HELIX_JWT_LOGIN_URL for user login:", e)
            return False

    print("User login status:", resp.status_code)
    if resp.status_code != 200:
        print("User login failed, body:", resp.text[:500])
        return False

    return True


async def get_admin_token(force_refresh: bool = False) -> Optional[str]:
    """
    Hämta AR-JWT-token för servicekontot (admin/service user) och cache:a det.
    Om force_refresh=True loggar vi alltid in på nytt.

    Detta token används tillsammans med X-AR-Impersonated-User (base64) för att köra
    Helix-REST-anrop som respektive användare.
    """
    global _ADMIN_TOKEN

    if _ADMIN_TOKEN and not force_refresh:
        return _ADMIN_TOKEN

    async with httpx.AsyncClient(verify=False) as client:
        try:
            resp = await client.post(
                HELIX_JWT_LOGIN_URL,
                data={"username": HELIX_ADMIN_USER, "password": HELIX_ADMIN_PASSWORD},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10.0,
            )
        except httpx.RequestError as e:
            print("Error calling HELIX_JWT_LOGIN_URL for admin login:", e)
            return None

    print("Admin login status:", resp.status_code, "body:", resp.text[:200])
    if resp.status_code != 200:
        _ADMIN_TOKEN = None
        return None

    token = resp.text.strip()
    if not token or len(token) < 10:
        print("Admin login: token looks invalid:", token)
        _ADMIN_TOKEN = None
        return None

    _ADMIN_TOKEN = token
    return _ADMIN_TOKEN


async def fetch_user_groups(username: str) -> Optional[str]:
    """
    Hämtar "Group List"-fältet för en given användare från Helix User-formuläret.

    Vi använder servicekontot (admin-token) och frågar mot:
      GET /api/arsys/v1/entry/<HELIX_USER_FORM>?q='Login Name'="<username>"&fields=values(Group List)

    Om allt går vägen returneras strängen med grupper, t.ex. "1;400003;12321;".
    Vid fel returneras None.
    """
    token = await get_admin_token()
    if not token:
        print("fetch_user_groups: no admin token")
        return None

    # Bygg query-parametrar enligt Helix REST-syntax
    # OBS: justera om ni har andra fältnamn/ID
    qualification = f"'{HELIX_USER_LOGIN_FIELD}'=\"{username}\""
    params = {
        "q": qualification,
        # Be bara om det fält vi behöver
        "fields": f"values({HELIX_USER_GROUP_FIELD})",
    }

    url = f"{HELIX_BASE_URL}/api/arsys/v1/entry/{HELIX_USER_FORM}"

    async with httpx.AsyncClient(verify=False) as client:
        try:
            resp = await client.get(
                url,
                headers={"Authorization": f"AR-JWT {token}"},
                params=params,
                timeout=15.0,
            )
        except httpx.RequestError as e:
            print("fetch_user_groups: error calling Helix:", e)
            return None

    if resp.status_code != 200:
        print("fetch_user_groups: Helix error", resp.status_code, resp.text[:500])
        return None

    data = resp.json()
    entries = data.get("entries", [])
    if not entries:
        print("fetch_user_groups: no entries for user", username)
        return None

    # Ta första matchningen
    values = entries[0].get("values", {})
    group_list = values.get(HELIX_USER_GROUP_FIELD)
    if not group_list:
        print("fetch_user_groups: no group field found for user", username)
        return None

    if not isinstance(group_list, str):
        group_list = str(group_list)

    return group_list


def pick_role_from_groups(group_list: str) -> str:
    """
    Tar en semikolonseparerad gruppsträng, t.ex. "1;400003;12321;"
    och plockar ut bästa Grafana-roll enligt GROUP_ROLE_MAPPING + ROLE_PRIORITY.

    Exempel:
      GROUP_ROLE_MAPPING = {"400001": "Viewer", "400002": "Editor", "400003": "Admin"}

      "1;400003;12321;" -> Admin (högsta prioritet)
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
    Returnerar Grafana-roll för användare baserat på Helix-grupper.

    Flöde:
      - Kolla cache (_ROLE_CACHE)
      - Om inte cachead:
          * Läs "Group List" från Helix User-formuläret
          * Mappa grupp-ID → roll via GROUP_ROLE_MAPPING
          * Spara i cache och returnera

    Vid fel eller om inga grupper matchar:
      - Returnera HELIX_DEFAULT_GRAFANA_ROLE (t.ex. "Viewer").
    """
    if username in _ROLE_CACHE:
        return _ROLE_CACHE[username]

    group_list = await fetch_user_groups(username)
    if not group_list:
        role = HELIX_DEFAULT_GRAFANA_ROLE
        print(f"get_grafana_role_for_user: no group list for {username}, using default {role}")
        _ROLE_CACHE[username] = role
        return role

    role = pick_role_from_groups(group_list)
    print(f"get_grafana_role_for_user: user={username}, groups={group_list}, role={role}")
    _ROLE_CACHE[username] = role
    return role


async def proxy_to_grafana(path: str, request: Request) -> Response:
    """
    Proxy för all Grafana-trafik (allt som inte är /login, /logout eller /helix-api/*):

    - Hämtar användarnamn via resolve_username()
    - Slår upp Grafana-roll baserat på Helix-grupper
    - Sätter:
        * X-WEBAUTH-USER  (vem användaren är)
        * X-WEBAUTH-ROLE  (vilken grafana-roll användaren ska ha)
    - Om ingen användare:
        * AUTH_MODE=local → redirect till /login
        * AUTH_MODE=rsso  → returnera 401 med enkel feltext
    """
    username = resolve_username(request)
    if not username:
        if AUTH_MODE == "rsso":
            # I RSSO-läge förväntas autentisering redan vara gjord av reverse proxy.
            # Om vi inte ser användaren här, är något fel i RSSO-konfigurationen.
            return HTMLResponse(
                "Ingen användare hittades i varken X-Grafana-User, "
                f"{RSSO_HEADER_NAME} eller {HELIX_USER_COOKIE}-cookie. "
                "Kontrollera RSSO / reverse proxy-konfigurationen.",
                status_code=401,
            )
        else:
            # Local-läge: skicka till vår egen login-sida.
            return RedirectResponse(url="/login", status_code=302)

    # Hämta grafana-roll baserat på Helix-grupper
    role = await get_grafana_role_for_user(username)

    # Bygg URL mot Grafana internt
    url = f"{GRAFANA_INTERNAL_URL}/{path}".rstrip("/")

    # Kopiera headers (utom Host) + auth-proxy headers
    headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}
    headers["X-WEBAUTH-USER"] = username
    # Denna header plockas upp av Grafana via GF_AUTH_PROXY_HEADERS="Role:X-WEBAUTH-ROLE"
    headers["X-WEBAUTH-ROLE"] = role

    body = await request.body()

    async with httpx.AsyncClient(follow_redirects=False) as client:
        grafana_resp = await client.request(
            method=request.method,
            url=url,
            headers=headers,
            content=body,
            params=request.query_params,
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
    - I AUTH_MODE="local": visuell login-sida där användaren skriver Helix-username + password.
      Vi validerar via HELIX_JWT_LOGIN_URL och sätter HLX_USER-cookie.
    - I AUTH_MODE="rsso": här ska man normalt sett aldrig hamna, men om man gör det
      visar vi bara ett kort meddelande.
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
        return RedirectResponse(url="/", status_code=302)

    # Snygg, responsiv login-sida (endast i local-läge)
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
    Tar emot login-formen (endast i AUTH_MODE=local), verifierar Helix-credentials via JWT-login,
    och sätter en cookie med Helix-loginName (HLX_USER).
    """
    if AUTH_MODE == "rsso":
        return JSONResponse(
            {"error": "Login via form is disabled in AUTH_MODE=rsso"},
            status_code=400,
        )

    ok = await login_against_helix(username, password)
    if not ok:
        html = """
        <html>
          <body>
            <h2>Inloggning misslyckades</h2>
            <a href="/login">Försök igen</a>
          </body>
        </html>
        """
        return HTMLResponse(content=html, status_code=401)

    resp = RedirectResponse(url="/", status_code=302)
    # I skarpt läge: sätt secure=True och samesite enligt din miljö
    resp.set_cookie(HELIX_USER_COOKIE, username, httponly=False)
    return resp


@app.get("/logout")
async def logout():
    """
    Logga ut ur proxyn (ta bort vår egen user-cookie).
    Gäller endast AUTH_MODE=local. I RSSO-läge hanteras utloggning normalt av RSSO själv.
    """
    resp = RedirectResponse(url="/login", status_code=302)
    resp.delete_cookie(HELIX_USER_COOKIE)
    return resp


# =========================
#  HELIX DATA-ENDPOINT
# =========================

@app.api_route("/helix-api/{form_name}", methods=["GET"])
async def helix_form_proxy(form_name: str, request: Request):
    """
    Generell, whitelistad proxy mot Helix-formulär:

    - form_name måste finnas i HELIX_ALLOWED_FORMS
    - varje anrop körs som aktuell användare via impersonation:
        Authorization: AR-JWT <admin-token>
        X-AR-Impersonated-User: base64(<username>)

    - username kommer från resolve_username(), dvs:
        * X-Grafana-User (dataproxy)
        * ev. RSSO-header (AUTH_MODE=rsso)
        * eller HLX_USER-cookie (AUTH_MODE=local)
    """
    username = resolve_username(request)
    if not username:
        return JSONResponse({"error": "Not logged in to proxy"}, status_code=401)

    if form_name not in ALLOWED_FORMS:
        return JSONResponse({"error": "Form not allowed"}, status_code=403)

    helix_url = f"{HELIX_BASE_URL}/api/arsys/v1/entry/{form_name}"

    # 1) Hämta ev. cache:ad admin-token
    token = await get_admin_token()
    if not token:
        return JSONResponse({"error": "Failed to get admin token"}, status_code=502)

    # X-AR-Impersonated-User måste vara base64-kodad enligt BMC-dokumentation
    impersonated_b64 = base64.b64encode(username.encode("utf-8")).decode("ascii")

    async with httpx.AsyncClient(verify=False) as client:
        # Första försök
        resp = await client.get(
            helix_url,
            headers={
                "Authorization": f"AR-JWT {token}",
                "X-AR-Impersonated-User": impersonated_b64,
            },
            params=request.query_params,
            timeout=15.0,
        )

        # Om tokenen blivit ogiltig (401/403) → logga in admin på nytt & prova en gång till
        if resp.status_code in (401, 403):
            print("Admin token possibly expired, refreshing...")
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
                params=request.query_params,
                timeout=15.0,
            )

    if resp.status_code != 200:
        print("Helix REST error:", resp.status_code, resp.text[:500])
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
#  CATCH-ALL → GRAFANA
# =========================

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def grafana_catch_all(path: str, request: Request):
    """
    All trafik som inte matchar /login, /logout eller /helix-api/*
    hamnar här och proxas vidare till Grafana.
    """
    return await proxy_to_grafana(path, request)
