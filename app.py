#!/usr/bin/env python3
import json
import os
import ssl
import sys
import time
from collections import deque
from http.cookiejar import CookieJar
from urllib.parse import urlencode
from urllib.request import Request, build_opener, HTTPCookieProcessor, HTTPSHandler
from urllib.error import HTTPError, URLError

# =========================
# Config (env vars)
# =========================
BASE = os.getenv("PEP_BASE", "https://192.168.50.1").rstrip("/")   # use https if router forces it
USERNAME = os.getenv("PEP_USER", "admin")
PASSWORD = os.getenv("PEP_PASS", "").strip()

# OAuth client/token (optional but supported)
CLIENT_NAME = os.getenv("PEP_CLIENT_NAME", "gps-client")
SCOPE = os.getenv("PEP_SCOPE", "api")  # <-- set this to "full api" scope your firmware expects
CLIENT_ID = os.getenv("PEP_CLIENT_ID", "").strip()
CLIENT_SECRET = os.getenv("PEP_CLIENT_SECRET", "").strip()

TIMEOUT = float(os.getenv("PEP_TIMEOUT", "8"))

POLL_SEC = float(os.getenv("PEP_POLL", "10"))
STOP_THRESHOLD = float(os.getenv("PEP_STOP_THRESHOLD", "0.2"))  # "close to zero"
MOVE_THRESHOLD = float(os.getenv("PEP_MOVE_THRESHOLD", "1.0"))  # moving
STOP_SAMPLES = int(os.getenv("PEP_STOP_SAMPLES", "5"))
MOVE_SAMPLES = int(os.getenv("PEP_MOVE_SAMPLES", "3"))

# If your API endpoints are different, change these:
PATH_LOGIN = "/api/login"
PATH_INFO = "/api/info.location"
PATH_AUTH_CLIENT = "/api/auth.client"
PATH_TOKEN_GRANT = "/api/auth.token.grant"
PATH_CMD_AP = "/api/cmd.ap"

# Router cert often doesn't match IP; ignore verification for LAN usage.
CTX = ssl._create_unverified_context()


def die(msg: str, payload=None, code=1):
    print(msg, file=sys.stderr)
    if payload is not None:
        try:
            print(json.dumps(payload, indent=2, ensure_ascii=False), file=sys.stderr)
        except Exception:
            print(repr(payload), file=sys.stderr)
    sys.exit(code)


class PeplinkAPI:
    def __init__(self, base: str):
        self.base = base
        self.cj = CookieJar()
        self.opener = build_opener(
            HTTPCookieProcessor(self.cj),
            HTTPSHandler(context=CTX),
        )

    def post_json(self, path: str, body: dict, query: dict | None = None) -> dict:
        url = f"{self.base}{path}"
        if query:
            url = f"{url}?{urlencode(query)}"
        data = json.dumps(body).encode("utf-8")
        req = Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        return self._do(req)

    def get_json(self, path: str, query: dict | None = None) -> dict:
        url = f"{self.base}{path}"
        if query:
            url = f"{url}?{urlencode(query)}"
        req = Request(url, headers={"Accept": "application/json"}, method="GET")
        return self._do(req)

    def _do(self, req: Request) -> dict:
        try:
            with self.opener.open(req, timeout=TIMEOUT) as r:
                raw = r.read().decode("utf-8", errors="replace")
            return json.loads(raw) if raw else {}
        except HTTPError as e:
            raw = e.read().decode("utf-8", errors="replace") if hasattr(e, "read") else ""
            try:
                detail = json.loads(raw) if raw else {"error": raw}
            except Exception:
                detail = {"error": raw}
            die(f"HTTPError {e.code} on {req.full_url}", detail)
        except URLError as e:
            die(f"URLError on {req.full_url}: {e}")
        except json.JSONDecodeError as e:
            die(f"Bad JSON from {req.full_url}: {e}")


def expect_ok(payload: dict, where: str) -> dict:
    if not isinstance(payload, dict):
        die(f"{where}: response is not a dict", payload)
    if payload.get("stat") != "ok":
        die(f"{where}: stat != ok", payload)
    resp = payload.get("response")
    return resp if isinstance(resp, dict) else payload


def extract_client_creds(resp: dict) -> tuple[str, str]:
    client_id = resp.get("clientId") or resp.get("client_id") or resp.get("id")
    client_secret = resp.get("clientSecret") or resp.get("client_secret") or resp.get("secret")

    if (not client_id or not client_secret) and isinstance(resp.get("client"), dict):
        c = resp["client"]
        client_id = client_id or c.get("clientId") or c.get("client_id") or c.get("id")
        client_secret = client_secret or c.get("clientSecret") or c.get("client_secret") or c.get("secret")

    if not client_id or not client_secret:
        die("Could not find clientId/clientSecret in auth.client response", resp)
    return str(client_id), str(client_secret)


def extract_token(resp: dict) -> str:
    token = resp.get("accessToken") or resp.get("access_token") or resp.get("token")
    if isinstance(token, str) and token.strip():
        return token.strip()

    if isinstance(resp.get("token"), dict):
        t = resp["token"]
        token = t.get("accessToken") or t.get("access_token")
        if isinstance(token, str) and token.strip():
            return token.strip()

    die("Could not find access token in auth.token.grant response", resp)
    return ""


def get_speed_from_info(info_resp: dict) -> float | None:
    # expected: { gps: bool, location: { latitude, longitude, speed } }
    loc = info_resp.get("location") if isinstance(info_resp.get("location"), dict) else None
    if not isinstance(loc, dict):
        return None
    spd = loc.get("speed")
    try:
        return float(spd) if spd is not None else None
    except Exception:
        return None


def main():
    if not PASSWORD:
        die("Set PEP_PASS env var (router password).")

    api = PeplinkAPI(BASE)

    # 1) login (cookie session)
    expect_ok(api.post_json(PATH_LOGIN, {"username": USERNAME, "password": PASSWORD}), "login")
    print("login ok", flush=True)

    # 2/3) token (optional but supported)
    token = ""
    cid = CLIENT_ID
    csec = CLIENT_SECRET

    if not (cid and csec):
        # Create client only if creds not provided.
        # Note: if firmware doesn't dedupe by name, this can create many clients across restarts.
        client_resp = expect_ok(
            api.post_json(PATH_AUTH_CLIENT, {"action": "add", "name": CLIENT_NAME, "scope": SCOPE}),
            "auth.client",
        )
        cid, csec = extract_client_creds(client_resp)
        print(f"created client: clientId={cid} clientSecret={csec}", flush=True)

    grant_resp = expect_ok(
        api.post_json(PATH_TOKEN_GRANT, {"clientId": cid, "clientSecret": csec, "scope": SCOPE}),
        "auth.token.grant",
    )
    token = extract_token(grant_resp)
    print("token granted", flush=True)

    # AP control helper: prefer cookie session (matches your curl -b cookies.txt).
    # If cmd.ap requires token on your firmware, fallback with accessToken.
    def set_ap(enable: bool):
        body = {"enable": bool(enable)}
        try:
            r = api.post_json(PATH_CMD_AP, body)
            expect_ok(r, "cmd.ap")
            return True
        except SystemExit:
            raise
        except Exception:
            pass

        # fallback: token as query param
        r = api.post_json(PATH_CMD_AP, body, query={"accessToken": token})
        expect_ok(r, "cmd.ap(token)")
        return True

    # State machine
    last_ap_state: bool | None = None  # unknown at start
    speeds = deque(maxlen=max(STOP_SAMPLES, MOVE_SAMPLES))

    print(
        json.dumps(
            {
                "poll_sec": POLL_SEC,
                "stop_threshold": STOP_THRESHOLD,
                "move_threshold": MOVE_THRESHOLD,
                "stop_samples": STOP_SAMPLES,
                "move_samples": MOVE_SAMPLES,
                "scope": SCOPE,
            }
        ),
        flush=True,
    )

    while True:
        # GPS read uses token (but cookie session would also likely work)
        info_payload = api.get_json(PATH_INFO, query={"accessToken": token})
        info_resp = expect_ok(info_payload, "info.location")
        spd = get_speed_from_info(info_resp)

        speeds.append(spd if spd is not None else float("nan"))

        # Determine conditions only if we have enough real samples
        recent = list(speeds)

        def is_number(x: float) -> bool:
            return x == x  # NaN check

        stop_window = [x for x in recent[-STOP_SAMPLES:] if is_number(x)] if len(recent) >= STOP_SAMPLES else []
        move_window = [x for x in recent[-MOVE_SAMPLES:] if is_number(x)] if len(recent) >= MOVE_SAMPLES else []

        should_enable = (
            len(stop_window) == STOP_SAMPLES and all(x <= STOP_THRESHOLD for x in stop_window)
        )
        should_disable = (
            len(move_window) == MOVE_SAMPLES and all(x >= MOVE_THRESHOLD for x in move_window)
        )

        # Decision + action
        action = None
        if should_disable and (last_ap_state is None or last_ap_state is True):
            set_ap(False)
            last_ap_state = False
            action = "ap_disable"
        elif should_enable and (last_ap_state is None or last_ap_state is False):
            set_ap(True)
            last_ap_state = True
            action = "ap_enable"

        # Log line
        out = {
            "ts": time.time(),
            "speed": spd,
            "stop_window": stop_window if stop_window else None,
            "move_window": move_window if move_window else None,
            "ap_state": last_ap_state,
            "action": action,
        }
        print(json.dumps(out), flush=True)

        time.sleep(POLL_SEC)


if __name__ == "__main__":
    main()
