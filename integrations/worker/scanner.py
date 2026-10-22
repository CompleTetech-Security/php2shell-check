"""Unprivileged one-job scanner entry point. Invoked only by the supervisor."""

from __future__ import annotations

import json
import os
import signal
import socket
import sys

from dataclasses import asdict

from wordpress_check import Checker

from .admission import ChildAdmission
from .network import PinnedOpener, RequestOrigin


MAX_INPUT_BYTES = 8192
MAX_OUTPUT_BYTES = 32 * 1024
CHILD_WALL_SECONDS = 175
CONTACT = "https://complete.tech/services/website-security/"


def _write(value, exit_code: int) -> int:
    try:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        encoded = b'{"ok":false,"error":"invalid_scanner_output"}'
        exit_code = 2
    if len(encoded) > MAX_OUTPUT_BYTES:
        encoded = b'{"ok":false,"error":"output_overflow"}'
        exit_code = 2
    try:
        sys.stdout.buffer.write(encoded + b"\n")
        sys.stdout.buffer.flush()
    except OSError:
        return 2
    return exit_code


def _admission_channel():
    """Open the supervisor socket named by CT_ADMISSION_FD. Without it, nothing is contacted."""
    raw = os.environ.get("CT_ADMISSION_FD", "")
    if not raw.isdigit() or not 3 <= int(raw) <= 1023:
        return None
    try:
        channel = socket.socket(fileno=int(raw))
    except (OSError, ValueError):
        return None
    if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_STREAM:
        channel.close()
        return None
    return channel


def _timeout(_signum, _frame):
    raise TimeoutError("scanner_timeout")


def main() -> int:
    if not sys.platform.startswith("linux") or os.geteuid() != 65534:
        return _write({"ok": False, "error": "scanner_isolation_unavailable"}, 2)
    try:
        signal.signal(signal.SIGALRM, _timeout)
        signal.alarm(CHILD_WALL_SECONDS)
    except (AttributeError, OSError, ValueError):
        return _write({"ok": False, "error": "scanner_deadline_unavailable"}, 2)
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            return _write({"ok": False, "error": "scanner_input_too_large"}, 2)
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict) or set(data) != {"target"} or not isinstance(data["target"], str):
            return _write({"ok": False, "error": "invalid_scanner_input"}, 2)
        scope, target = RequestOrigin.from_target(data["target"])
        if target != data["target"]:
            return _write({"ok": False, "error": "invalid_scanner_input"}, 2)
        channel = _admission_channel()
        if channel is None:
            # Fail closed: a scanner that cannot ask for admission never sends a request.
            return _write({"ok": False, "error": "admission_channel_unavailable"}, 2)
        guard = ChildAdmission(channel)
        checker = Checker(timeout=10.0, delay=1.0, contact=CONTACT)
        checker.opener = PinnedOpener(scope, guard=guard)
        result = checker.check(target)
        return _write({"ok": True, "result": asdict(result)}, 0)
    except TimeoutError:
        return _write({"ok": False, "error": "scanner_timeout"}, 2)
    except BaseException:
        # The parent captures and discards stderr; never expose exception text here.
        return _write({"ok": False, "error": "scanner_failed"}, 2)
    finally:
        try:
            signal.alarm(0)
        except (AttributeError, OSError, ValueError):
            pass


if __name__ == "__main__":
    raise SystemExit(main())
