"""Small, dependency-free Pi-hole v6 client used by the local dashboard.

The client owns the Pi-hole application password and session ID.  Neither is
ever returned by this module or exposed through the browser-facing API.
"""

from __future__ import annotations

import json
import os
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class PiHoleClientError(RuntimeError):
    """A safe-to-display integration error; it never includes credentials."""


def load_local_environment() -> None:
    """Load backend/.env without adding a runtime dependency.

    Existing process environment variables take precedence, which makes the
    application suitable for deployment as well as local development.
    """
    env_file = Path(__file__).resolve().parents[1] / ".env"
    if not env_file.exists():
        return
    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key:
            os.environ.setdefault(key, value.strip().strip('"').strip("'"))


@dataclass
class PiHoleSettings:
    base_url: str
    app_password: str
    verify_tls: bool

    @classmethod
    def from_environment(cls) -> "PiHoleSettings | None":
        load_local_environment()
        base_url = os.getenv("PIHOLE_BASE_URL", "").strip().rstrip("/")
        app_password = os.getenv("PIHOLE_APP_PASSWORD", "").strip()
        if not base_url or not app_password:
            return None
        if not base_url.startswith(("http://", "https://")):
            raise PiHoleClientError("PIHOLE_BASE_URL must start with http:// or https://.")
        verify_tls = os.getenv("PIHOLE_VERIFY_TLS", "true").strip().lower() not in {"0", "false", "no"}
        return cls(base_url=base_url, app_password=app_password, verify_tls=verify_tls)


class PiHoleClient:
    def __init__(self, settings: PiHoleSettings):
        self._settings = settings
        self._sid: str | None = None
        self._expires_at = 0.0

    def _context(self) -> ssl.SSLContext | None:
        if self._settings.base_url.startswith("https://") and not self._settings.verify_tls:
            return ssl._create_unverified_context()
        return None

    def _request(self, path: str, *, method: str = "GET", payload: dict | None = None, authenticated: bool = False) -> Any:
        headers = {"Accept": "application/json"}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if authenticated:
            self._authenticate_if_needed()
            headers["X-FTL-SID"] = self._sid or ""
        request = Request(f"{self._settings.base_url}{path}", data=body, headers=headers, method=method)
        try:
            with urlopen(request, timeout=10, context=self._context()) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            if error.code == 401 and authenticated:
                self._sid = None
                self._expires_at = 0.0
                raise PiHoleClientError("Pi-hole rejected the application password or session.") from None
            raise PiHoleClientError(f"Pi-hole API returned HTTP {error.code}.") from None
        except (URLError, TimeoutError, json.JSONDecodeError) as error:
            raise PiHoleClientError("Could not reach the Pi-hole API. Check its current hotspot IP and connection.") from error

    def _authenticate_if_needed(self) -> None:
        if self._sid and time.monotonic() < self._expires_at:
            return
        response = self._request("/api/auth", method="POST", payload={"password": self._settings.app_password})
        session = response.get("session", {}) if isinstance(response, dict) else {}
        sid = session.get("sid")
        if not sid:
            raise PiHoleClientError("Pi-hole did not return an API session.")
        self._sid = str(sid)
        # Renew a little before the server-side expiry to prevent race failures.
        self._expires_at = time.monotonic() + max(30, int(session.get("validity", 300)) - 15)

    def fetch_queries(self, limit: int = 100) -> list[dict[str, Any]]:
        response = self._request(f"/api/queries?{urlencode({'limit': limit})}", authenticated=True)
        if isinstance(response, dict):
            queries = response.get("queries", response.get("data", []))
        else:
            queries = response
        if not isinstance(queries, list):
            raise PiHoleClientError("Pi-hole returned an unexpected query-log response.")
        return [query for query in queries if isinstance(query, dict)]


def value_as_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, dict):
        for key in ("ip", "name", "domain", "url", "value"):
            if value.get(key):
                return str(value[key])
        return json.dumps(value, sort_keys=True)
    return str(value)


def query_is_blocked(query: dict[str, Any]) -> bool:
    if isinstance(query.get("blocked"), bool):
        return query["blocked"]
    status = query.get("status", query.get("reply", ""))
    if isinstance(status, dict):
        status = status.get("name", status.get("status", ""))
    value = str(status).upper()
    return any(marker in value for marker in ("BLOCK", "DENY", "GRAVITY", "REGEX", "EXACT"))


def normalize_query(query: dict[str, Any]) -> dict[str, Any] | None:
    domain = value_as_text(query.get("domain", query.get("query")))
    if not domain:
        return None
    status = value_as_text(query.get("status", query.get("reply"))) or "unknown"
    timestamp = query.get("timestamp", query.get("time", query.get("date")))
    client = value_as_text(query.get("client", query.get("client_ip")))
    query_type = value_as_text(query.get("type", query.get("query_type"))) or "A"
    matched_rule = value_as_text(query.get("rule", query.get("blocking_rule", query.get("regex"))))
    list_source = value_as_text(query.get("list", query.get("list_name", query.get("adlist"))))
    if not list_source:
        list_source = {
            "GRAVITY": "Pi-hole gravity blocklist",
            "REGEX": "Pi-hole regex denylist",
            "EXACT": "Pi-hole exact denylist",
        }.get(status.upper())
    source_id = value_as_text(query.get("id", query.get("query_id")))
    if not source_id:
        source_id = f"{timestamp}:{client}:{query_type}:{domain}:{status}"
    return {
        "domain": domain,
        "blocked": query_is_blocked(query),
        "client_ip": client,
        "query_type": query_type,
        "matched_rule": matched_rule,
        "list_source": list_source,
        "occurred_at": timestamp,
        "source_event_id": source_id[:160],
    }
