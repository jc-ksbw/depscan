"""Tiny JSON-over-HTTPS helper built on urllib.

depscan has no third-party dependencies on purpose: a tool whose job is to
police your supply chain should not widen it. urllib honours HTTP(S)_PROXY
from the environment and uses the system trust store, which is what corporate
networks need.
"""

from __future__ import annotations

import json
import socket
import ssl
import time
import urllib.error
import urllib.request

USER_AGENT = "depscan/1.0 (+https://github.com/jc-ksbw/depscan)"
RETRY_STATUS = {408, 425, 429, 500, 502, 503, 504}


class HttpError(RuntimeError):
    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def _context() -> ssl.SSLContext:
    return ssl.create_default_context()


def request_json(
    url: str,
    payload: dict | None = None,
    *,
    timeout: float = 45.0,
    retries: int = 4,
    headers: dict[str, str] | None = None,
) -> dict:
    """GET (payload=None) or POST a JSON body, with retry on transient errors."""
    body = None
    request_headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    request_headers.update(headers or {})

    last_error: Exception | None = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, data=body, headers=request_headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=_context()) as resp:
                raw = resp.read()
            return json.loads(raw.decode("utf-8")) if raw else {}
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code not in RETRY_STATUS or attempt == retries:
                detail = ""
                try:
                    detail = exc.read().decode("utf-8", "replace")[:300]
                except Exception:  # noqa: BLE001 - diagnostics only
                    pass
                raise HttpError(f"{url} -> HTTP {exc.code} {detail}".strip(), exc.code) from exc
            delay = _retry_after(exc) or _backoff(attempt)
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, ConnectionError, TimeoutError) as exc:
            last_error = exc
            if attempt == retries:
                raise HttpError(f"{url} -> {type(exc).__name__}: {exc}") from exc
            delay = _backoff(attempt)
        except json.JSONDecodeError as exc:
            raise HttpError(f"{url} -> malformed JSON response: {exc}") from exc
        time.sleep(delay)
    raise HttpError(f"{url} -> {last_error}")


def _backoff(attempt: int) -> float:
    return min(2.0 ** attempt, 16.0)


def _retry_after(exc: urllib.error.HTTPError) -> float | None:
    value = exc.headers.get("Retry-After") if exc.headers else None
    if not value:
        return None
    try:
        return min(float(value), 60.0)
    except ValueError:
        return None
