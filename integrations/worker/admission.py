"""Per-request admission guard.

The sandboxed scanner holds no worker key and no authorization state. Before
each connection to the customer's site it asks the root supervisor over a
private socket; the supervisor asks WordPress (signed ``admit`` route), which
atomically checks cancellation, expiry, lease and budget under the queue lock.

Fail-closed rules:

* No grant, no connection. Any error, timeout, malformed answer, protocol
  violation or unavailable store is a refusal.
* A grant is reserved and consumed in one step, is valid for at most
  ``MAX_VALID_SECONDS`` and covers exactly one connection and request.
* Only one grant may be outstanding. The supervisor kills the scanner if a
  request is not reported finished within ``MAX_REQUEST_SECONDS`` (plus a short
  grace), if the scanner skips the protocol, or if WordPress reports that the
  job is no longer live.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass

from .protocol import APIError


MAX_VALID_SECONDS = 1.0
MAX_REQUEST_SECONDS = 10.0
REQUEST_GRACE_SECONDS = 1.0
PROBE_INTERVAL_SECONDS = 2.0
MAX_ADMIT_WAIT_SECONDS = 4.0
BUSY_RETRY_SECONDS = 0.15
MAX_MESSAGE_BYTES = 256
CHILD_REPLY_TIMEOUT_SECONDS = 15.0
REASON_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
RETRYABLE_BUSY = {"queue_busy", "admission_write_failed"}


class AdmissionDenied(Exception):
    """A refusal with a log-safe reason. Never converted into permission."""

    def __init__(self, slug: str, *, retry_after_ms: int = 0):
        super().__init__(slug)
        self.slug = slug if REASON_RE.fullmatch(slug or "") else "admission_denied"
        self.retry_after_ms = retry_after_ms


@dataclass(frozen=True)
class Grant:
    sequence: int
    valid_seconds: float
    timeout_seconds: float
    remaining: int


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def parse_grant(value) -> Grant:
    """Strictly validate a WordPress grant and clamp it to the disclosed hard bounds."""
    expected = {"ok", "admitted", "sequence", "valid_ms", "timeout_ms", "http_remaining"}
    if not isinstance(value, dict) or set(value) != expected or value["ok"] is not True or value["admitted"] is not True:
        raise AdmissionDenied("admission_response_invalid")
    sequence, valid_ms, timeout_ms, remaining = (value[k] for k in ("sequence", "valid_ms", "timeout_ms", "http_remaining"))
    if not all(_is_int(item) for item in (sequence, valid_ms, timeout_ms, remaining)):
        raise AdmissionDenied("admission_response_invalid")
    if sequence < 1 or valid_ms < 1 or timeout_ms < 1 or remaining < 0:
        raise AdmissionDenied("admission_response_invalid")
    return Grant(
        sequence,
        min(valid_ms / 1000.0, MAX_VALID_SECONDS),
        min(timeout_ms / 1000.0, MAX_REQUEST_SECONDS),
        remaining,
    )


def parse_refusal(error: APIError) -> AdmissionDenied:
    """Turn a non-2xx answer into a refusal; unknown or malformed answers stay refusals."""
    payload = getattr(error, "payload", None)
    reason = payload.get("reason") if isinstance(payload, dict) else None
    if not isinstance(reason, str) or not REASON_RE.fullmatch(reason):
        reason = "guard_unavailable"
    retry = payload.get("retry_after_ms") if isinstance(payload, dict) else 0
    if not _is_int(retry) or retry < 0:
        retry = 0
    return AdmissionDenied(reason, retry_after_ms=min(retry, 1000))


class AdmissionGate:
    """Supervisor-side client for the WordPress admission route."""

    def __init__(self, api, claim, *, stop_event=None, clock=time.time, monotonic=time.monotonic):
        self.api = api
        self.claim = claim
        self.stop_event = stop_event
        self._clock = clock
        self._monotonic = monotonic

    def _wait(self, seconds: float):
        if self.stop_event is not None:
            if self.stop_event.wait(seconds):
                raise AdmissionDenied("worker_shutdown")
        else:
            time.sleep(seconds)

    def _check_local(self):
        if self.stop_event is not None and self.stop_event.is_set():
            raise AdmissionDenied("worker_shutdown")
        if self._clock() >= self.claim.expires_at.timestamp():
            raise AdmissionDenied("authorization_expired")

    def _call(self, kind: str):
        try:
            response = self.api.admit(self.claim, kind)
        except APIError as exc:
            if exc.status is None:
                raise AdmissionDenied("guard_unavailable") from exc
            raise parse_refusal(exc) from exc
        return response

    def admit(self) -> Grant:
        """Reserve exactly one request, or raise AdmissionDenied. Retries are bounded."""
        deadline = self._monotonic() + MAX_ADMIT_WAIT_SECONDS
        while True:
            self._check_local()
            try:
                return parse_grant(self._call("http"))
            except AdmissionDenied as denied:
                if self._monotonic() >= deadline:
                    raise
                if denied.slug == "rate_wait" and denied.retry_after_ms > 0:
                    self._wait(min(denied.retry_after_ms / 1000.0, 1.0))
                elif denied.slug in RETRYABLE_BUSY:
                    self._wait(BUSY_RETRY_SECONDS)
                else:
                    raise

    def probe(self):
        """Ask whether the job is still live. Consumes no budget and does not pace."""
        self._check_local()
        response = self._call("probe")
        if not isinstance(response, dict) or set(response) != {"ok", "live"} or response["ok"] is not True or response["live"] is not True:
            raise AdmissionDenied("admission_response_invalid")


class AdmissionPump:
    """Supervisor side of the scanner socket: a one-grant-at-a-time state machine.

    ``service`` and ``tick`` return a fatal reason slug when the scanner must be
    killed, and ``None`` otherwise. After a fatal reason the pump answers nothing.
    """

    def __init__(self, sock, gate, *, monotonic=time.monotonic):
        self.sock = sock
        self.gate = gate
        self._monotonic = monotonic
        self._buffer = bytearray()
        self._inflight_until = None
        self._last_probe = monotonic()
        self.grants = 0
        self.fatal = None
        self.closed = False

    @property
    def inflight(self) -> bool:
        return self._inflight_until is not None

    def _send(self, value) -> bool:
        data = json.dumps(value, separators=(",", ":")).encode("ascii") + b"\n"
        try:
            self.sock.settimeout(2.0)
            self.sock.sendall(data)
            return True
        except OSError:
            return False

    def _fail(self, slug: str):
        slug = slug if slug.startswith(("admission_", "request_")) else "admission_" + slug
        self.fatal = slug[:64] if REASON_RE.fullmatch(slug[:64]) else "admission_denied"
        return self.fatal

    def _handle(self, line: bytes):
        try:
            message = json.loads(line.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._fail("admission_protocol_violation")
        if not isinstance(message, dict):
            return self._fail("admission_protocol_violation")
        if message == {"op": "done"}:
            if not self.inflight:
                return self._fail("admission_protocol_violation")
            self._inflight_until = None
            return None
        if message == {"op": "admit", "kind": "http"}:
            if self.inflight:
                # One connection at a time: a second grant is never available.
                return self._fail("admission_protocol_violation")
            try:
                grant = self.gate.admit()
            except AdmissionDenied as denied:
                self._send({"ok": False, "reason": denied.slug})
                return self._fail(denied.slug)
            # The deadline starts when WordPress granted, before the reply is delivered.
            self._inflight_until = self._monotonic() + grant.timeout_seconds + REQUEST_GRACE_SECONDS
            self.grants += 1
            if not self._send({"ok": True, "valid_ms": int(grant.valid_seconds * 1000)}):
                return self._fail("admission_channel_failed")
            return None
        return self._fail("admission_protocol_violation")

    def service(self):
        """Read and handle whatever the scanner has sent. Call when the socket is readable."""
        if self.fatal:
            return self.fatal
        try:
            self.sock.settimeout(0)
            chunk = self.sock.recv(MAX_MESSAGE_BYTES + 1)
        except (BlockingIOError, InterruptedError):
            return None
        except OSError:
            self.closed = True
            return None
        if not chunk:
            self.closed = True
            return None
        self._buffer.extend(chunk)
        while b"\n" in self._buffer:
            line, _, rest = bytes(self._buffer).partition(b"\n")
            self._buffer = bytearray(rest)
            if len(line) > MAX_MESSAGE_BYTES:
                return self._fail("admission_protocol_violation")
            fatal = self._handle(line)
            if fatal:
                return fatal
        if len(self._buffer) > MAX_MESSAGE_BYTES:
            return self._fail("admission_protocol_violation")
        return None

    def tick(self):
        """Enforce the in-flight bound and watch for cancellation, expiry or revocation."""
        if self.fatal:
            return self.fatal
        now = self._monotonic()
        if self._inflight_until is not None and now > self._inflight_until:
            return self._fail("request_deadline_exceeded")
        if now - self._last_probe >= PROBE_INTERVAL_SECONDS:
            self._last_probe = now
            try:
                self.gate.probe()
            except AdmissionDenied as denied:
                # An unreachable guard does not abort the request already admitted (its own
                # ten-second bound applies), and the next admission fails closed. An explicit
                # refusal stops the scanner now.
                if denied.slug not in {"guard_unavailable", "admission_response_invalid"}:
                    return self._fail(denied.slug)
        return None


class AdmissionRefused(OSError):
    """Raised inside the scanner when no admission was granted. Subclasses OSError so
    that an unmodified checker treats it as a failed fetch and sends nothing."""


class ChildAdmission:
    """Scanner-side client of the supervisor socket. Holds no key and no state of record."""

    def __init__(self, sock, *, monotonic=time.monotonic):
        self.sock = sock
        self._monotonic = monotonic
        self._granted_at = None
        self._valid_seconds = 0.0
        self._outstanding = False

    def _read_line(self) -> bytes:
        deadline = self._monotonic() + CHILD_REPLY_TIMEOUT_SECONDS
        data = bytearray()
        while True:
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                raise AdmissionRefused("admission_timeout")
            self.sock.settimeout(remaining)
            try:
                chunk = self.sock.recv(1)
            except OSError as exc:
                raise AdmissionRefused("admission_channel_failed") from exc
            if not chunk:
                raise AdmissionRefused("admission_channel_closed")
            if chunk == b"\n":
                return bytes(data)
            data.extend(chunk)
            if len(data) > MAX_MESSAGE_BYTES:
                raise AdmissionRefused("admission_reply_invalid")

    def admit(self):
        if self._outstanding:
            raise AdmissionRefused("admission_outstanding")
        try:
            self.sock.settimeout(5.0)
            self.sock.sendall(b'{"op":"admit","kind":"http"}\n')
        except OSError as exc:
            raise AdmissionRefused("admission_channel_failed") from exc
        try:
            reply = json.loads(self._read_line().decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AdmissionRefused("admission_reply_invalid") from exc
        if not isinstance(reply, dict):
            raise AdmissionRefused("admission_reply_invalid")
        if reply.get("ok") is not True:
            reason = reply.get("reason")
            raise AdmissionRefused(reason if isinstance(reason, str) and REASON_RE.fullmatch(reason) else "admission_denied")
        valid_ms = reply.get("valid_ms")
        if set(reply) != {"ok", "valid_ms"} or not _is_int(valid_ms) or not 1 <= valid_ms <= int(MAX_VALID_SECONDS * 1000):
            raise AdmissionRefused("admission_reply_invalid")
        self._granted_at = self._monotonic()
        self._valid_seconds = valid_ms / 1000.0
        self._outstanding = True

    def ensure_fresh(self):
        """Call immediately before connecting: a stale grant is never used."""
        if not self._outstanding or self._granted_at is None:
            raise AdmissionRefused("admission_missing")
        if self._monotonic() - self._granted_at >= self._valid_seconds:
            raise AdmissionRefused("admission_expired")

    def done(self):
        """Report the request finished (success or failure). Idempotent."""
        if not self._outstanding:
            return
        self._outstanding = False
        self._granted_at = None
        try:
            self.sock.settimeout(2.0)
            self.sock.sendall(b'{"op":"done"}\n')
        except OSError:
            pass
