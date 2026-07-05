"""Append-only JSONL audit log of every policy decision, shared by both transports.

One line per decision, written with a single `os.write` to an `O_APPEND` fd under
a `threading.Lock` held across the seq increment, the rotation check and the
write. `AuditWriter.write` returns bool and never raises: an audit failure must
not be able to change a security decision, so callers build the record only
after the decision has already been computed.

Argument handling is the load-bearing choice. Default `args_mode=none` records a
keyed hash plus schema-only metadata. `AGENTPARRY_AUDIT_ARGS=preview` adds a
redacted preview, `=full` (the literal string only) adds raw arguments.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.inspector import OutputInspector
from src.models import (
    AuditAction,
    AuditArgsMode,
    AuditDirection,
    AuditFinding,
    AuditRecord,
    AuditTransport,
    Finding,
    max_severity,
)

DEFAULT_AUDIT_DIR = ".agentparry"
DEFAULT_AUDIT_FILENAME = "audit.jsonl"
DEFAULT_KEY_FILENAME = "audit.key"

KEY_BYTES = 32
KEY_ID_CHARS = 12

DEFAULT_MAX_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_LINE_BYTES = 64 * 1024

MAX_ARG_KEYS = 32
MAX_NAME_CHARS = 256
MAX_DETAIL_CHARS = 400
MAX_PREVIEW_CHARS = 512
MAX_FINDINGS = 20

MAX_FAILURE_WARNINGS = 3
MAX_CONSECUTIVE_FAILURES = 5

OMITTED = "[OMITTED]"

_SENSITIVE_KEY_RE = re.compile(
    r"pass|secret|token|key|auth|credential|cookie|session|signature|bearer|otp|pin|ssn|cvv|card",
    re.IGNORECASE,
)


class ShortWriteError(OSError):
    """A partial `os.write`, which on a log file means the filesystem is full."""


def _cap(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    if len(value) <= limit:
        return value
    return value[: limit - 1] + "…"


def _join_detail(existing: str, added: str) -> str:
    if not existing:
        return added
    return f"{existing}; {added}"


def utc_now_iso() -> str:
    """UTC ISO8601 with a literal Z suffix, which datetime.isoformat does not emit."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def canonical_json(value: Any) -> str:
    """Stable JSON for hashing and byte counting.

    `ensure_ascii=True` on purpose: the output feeds a UTF-8 encode, and JSON
    input can carry lone surrogates that would make that encode raise.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def audit_enabled() -> bool:
    return os.environ.get("AGENTPARRY_AUDIT", "").strip() != "0"


def resolve_args_mode() -> AuditArgsMode:
    """Resolve AGENTPARRY_AUDIT_ARGS.

    `full` must be spelled exactly, so `1`, `true` and `yes` all resolve to
    `none` and nobody enables raw-secret logging out of boolean-flag habit.
    """
    raw = os.environ.get("AGENTPARRY_AUDIT_ARGS", "").strip()
    if raw == "full":
        return AuditArgsMode.FULL
    if raw.lower() == "preview":
        return AuditArgsMode.PREVIEW
    return AuditArgsMode.NONE


def _home_dir() -> Path:
    try:
        return Path.home()
    except (RuntimeError, OSError):
        return Path(os.environ.get("TMPDIR", "/tmp"))


def default_audit_path() -> Path:
    override = os.environ.get("AGENTPARRY_AUDIT_PATH", "").strip()
    if override:
        return Path(override).expanduser()
    return _home_dir() / DEFAULT_AUDIT_DIR / DEFAULT_AUDIT_FILENAME


def default_key_path() -> Path:
    override = os.environ.get("AGENTPARRY_AUDIT_KEY_PATH", "").strip()
    if override:
        return Path(override).expanduser()
    return _home_dir() / DEFAULT_AUDIT_DIR / DEFAULT_KEY_FILENAME


def _chmod(path: Path, mode: int) -> None:
    if os.name == "nt":
        return
    with contextlib.suppress(OSError):
        os.chmod(path, mode)


def load_or_create_key(path: Path) -> bytes:
    """Return the persistent per-install HMAC key, creating it lazily at 0600.

    A per-run salt would break the main use case, correlating "this exact call
    happened again yesterday", so the key has to persist.
    """
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        data = b""
    if len(data) == KEY_BYTES:
        _chmod(path, 0o600)
        return data

    path.parent.mkdir(parents=True, exist_ok=True)
    _chmod(path.parent, 0o700)
    candidate = secrets.token_bytes(KEY_BYTES)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Another process won the race, or the file exists at the wrong length.
        existing = path.read_bytes()
        if len(existing) == KEY_BYTES:
            _chmod(path, 0o600)
            return existing
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        if os.name != "nt":
            with contextlib.suppress(OSError):
                os.fchmod(fd, 0o600)
        os.write(fd, candidate)
    finally:
        os.close(fd)
    _chmod(path, 0o600)
    return candidate


def key_id(key: bytes) -> str:
    """Short digest of the key so a reader can spot a rotated key."""
    return hashlib.sha256(b"agentparry-audit-key-id\x00" + key).hexdigest()[:KEY_ID_CHARS]


def arg_hash(key: bytes, tool_name: str, arguments: Any) -> str:
    """HMAC-SHA256 over tool_name \\0 canonical_json(arguments).

    Keyed, not plain SHA-256: a file path, an email address and a 9-digit SSN
    are all low-entropy and fall to a rainbow table instantly. The tool name is
    inside the message so identical arguments to different tools differ.
    """
    message = f"{tool_name}\x00{canonical_json(arguments)}".encode(errors="replace")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def omit_sensitive(value: Any) -> Any:
    """Replace values under sensitive-looking keys with a placeholder, at any depth."""
    if isinstance(value, dict):
        return {
            str(k): (OMITTED if _SENSITIVE_KEY_RE.search(str(k)) else omit_sensitive(v)) for k, v in value.items()
        }
    if isinstance(value, list):
        return [omit_sensitive(item) for item in value]
    return value


def build_preview(tool_name: str, arguments: dict[str, Any], inspector: OutputInspector) -> str:
    """Sensitive-key omission, then the real OutputInspector, then truncation.

    Reuses OutputInspector rather than adding a second redactor so the audit
    path and the response path can never disagree. That inspector knows exactly
    five patterns (SSN, credit card, `sk-`-style API keys, AWS access key ids,
    credentials in a URL) and will not catch bearer tokens, JWTs, private keys,
    names or addresses. `preview` is a debugging aid, not a safe-to-share mode.
    """
    filtered = omit_sensitive(arguments)
    if not isinstance(filtered, dict):
        filtered = {"arguments": filtered}
    sanitized, _findings = inspector.inspect(tool_name, filtered)
    text = json.dumps(sanitized, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    if len(text) > MAX_PREVIEW_CHARS:
        return text[: MAX_PREVIEW_CHARS - 1] + "…"
    return text


def _summarize_findings(findings: list[Finding] | None) -> tuple[list[AuditFinding], int, str | None]:
    if not findings:
        return [], 0, None
    summarized = [
        AuditFinding(
            severity=str(getattr(f, "severity", "low")),
            description=_cap(str(getattr(f, "description", "")), MAX_DETAIL_CHARS) or "",
            field=_cap(getattr(f, "field", None), MAX_NAME_CHARS),
            pattern=_cap(getattr(f, "matched_pattern", None), MAX_NAME_CHARS),
        )
        for f in findings[:MAX_FINDINGS]
    ]
    highest = max_severity(str(getattr(f, "severity", "low")) for f in findings)
    return summarized, len(findings), highest


def _failure_kind(exc: BaseException) -> str:
    if isinstance(exc, ShortWriteError):
        return "short write (disk full or quota)"
    if isinstance(exc, PermissionError):
        return "permission denied"
    if isinstance(exc, OSError):
        if exc.errno == errno.ENOSPC:
            return "disk full"
        if exc.errno == getattr(errno, "EDQUOT", None):
            return "quota exceeded"
        if exc.errno == errno.EROFS:
            return "read-only filesystem"
        if exc.errno == errno.EISDIR:
            return "path is a directory"
    return type(exc).__name__


class AuditWriter:
    """Writes AuditRecords as one JSONL line each. Never raises from `write`."""

    def __init__(
        self,
        *,
        transport: AuditTransport | str = AuditTransport.HTTP,
        path: Path | str | None = None,
        key_path: Path | str | None = None,
        enabled: bool | None = None,
        args_mode: AuditArgsMode | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
        max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
        output_inspector: OutputInspector | None = None,
        run_id: str | None = None,
    ) -> None:
        self.transport = AuditTransport(transport)
        self.path = Path(path).expanduser() if path is not None else default_audit_path()
        self.key_path = Path(key_path).expanduser() if key_path is not None else default_key_path()
        self.enabled = audit_enabled() if enabled is None else enabled
        self.args_mode = resolve_args_mode() if args_mode is None else args_mode
        self.max_bytes = max_bytes
        self.max_line_bytes = max_line_bytes
        self.run_id = run_id or uuid.uuid4().hex
        self.pid = os.getpid()

        self._inspector = output_inspector or OutputInspector()
        self._lock = threading.Lock()
        self._seq = 0
        self._fd: int | None = None
        self._failures = 0
        self._warnings = 0
        self._drops = 0
        self._key: bytes | None = None
        self._key_id: str | None = None
        self._key_failed = False

        if self.enabled and self.args_mode is AuditArgsMode.FULL:
            _warn_full_args_once(self.path)

    @property
    def drops(self) -> int:
        """Records that could not be written."""
        return self._drops

    @property
    def seq(self) -> int:
        """Sequence number of the last record written."""
        return self._seq

    def build(
        self,
        *,
        action: AuditAction,
        direction: AuditDirection = AuditDirection.CLIENT_TO_SERVER,
        method: str | None = None,
        tool: str | None = None,
        rule: str | None = None,
        request_id: Any = None,
        session_id: str | None = None,
        arguments: dict[str, Any] | None = None,
        findings: list[Finding] | None = None,
        pii_redactions: int | None = None,
        detail: str = "",
    ) -> AuditRecord:
        """Build a record for an already-computed decision. Never raises.

        `request_id` uses an `is None` check rather than truthiness: id 0 is a
        real JSON-RPC id, and stdio sees genuinely absent ids on notifications.
        """
        summarized, count, highest = _summarize_findings(findings)
        record = AuditRecord(
            ts=utc_now_iso(),
            run_id=self.run_id,
            pid=self.pid,
            transport=self.transport,
            direction=direction,
            action=action,
            method=_cap(method, MAX_NAME_CHARS),
            tool=_cap(tool, MAX_NAME_CHARS),
            rule=_cap(rule, MAX_NAME_CHARS),
            request_id=None if request_id is None else _cap(str(request_id), MAX_NAME_CHARS),
            session_id=_cap(session_id, MAX_NAME_CHARS),
            args_mode=self.args_mode,
            findings=summarized,
            finding_count=count,
            max_severity=highest,
            pii_redactions=pii_redactions,
            detail=_cap(detail, MAX_DETAIL_CHARS) or "",
        )
        if arguments is not None:
            self._stamp_arguments(record, tool or "", arguments)
        return record

    def _stamp_arguments(self, record: AuditRecord, tool_name: str, arguments: dict[str, Any]) -> None:
        try:
            record.arg_keys = [_cap(str(k), MAX_NAME_CHARS) or "" for k in sorted(map(str, arguments))][:MAX_ARG_KEYS]
            canonical = canonical_json(arguments)
            record.arg_bytes = len(canonical.encode("utf-8", errors="replace"))
            key = self._hmac_key()
            if key is not None:
                record.arg_hash = arg_hash(key, tool_name, arguments)
                record.arg_hash_key_id = self._key_id
            if self.args_mode is AuditArgsMode.PREVIEW:
                record.arg_preview = build_preview(tool_name, arguments, self._inspector)
            elif self.args_mode is AuditArgsMode.FULL:
                record.arguments = arguments
        except Exception as exc:
            record.detail = _join_detail(record.detail, f"argument metadata failed: {type(exc).__name__}")

    def _hmac_key(self) -> bytes | None:
        if self._key is not None:
            return self._key
        if self._key_failed:
            return None
        try:
            self._key = load_or_create_key(self.key_path)
            self._key_id = key_id(self._key)
        except Exception as exc:
            self._key_failed = True
            logging.getLogger(__name__).warning(
                "Audit key unavailable at %s (%s); records will omit arg_hash", self.key_path, _failure_kind(exc)
            )
            return None
        return self._key

    def write(self, record: AuditRecord) -> bool:
        """Append one line. Returns False on any failure and never raises."""
        if not self.enabled:
            return False
        with self._lock:
            try:
                record.seq = self._seq + 1
                line = self._encode(record)
                self._rotate_if_needed(len(line))
                fd = self._ensure_fd()
                written = os.write(fd, line)
                if written != len(line):
                    raise ShortWriteError(errno.ENOSPC, f"wrote {written} of {len(line)} bytes")
            except Exception as exc:
                with contextlib.suppress(Exception):
                    self._on_failure(exc)
                return False
            self._seq += 1
            self._failures = 0
            return True

    def _encode(self, record: AuditRecord) -> bytes:
        line = self._dump(record)
        if len(line) <= self.max_line_bytes:
            return line
        record.arguments = None
        record.arg_preview = None
        record.findings = []
        record.detail = _join_detail(
            record.detail, "audit record over line cap: arguments, preview and findings dropped"
        )
        return self._dump(record)

    def _dump(self, record: AuditRecord) -> bytes:
        text = json.dumps(record.model_dump(mode="json"), ensure_ascii=False, separators=(",", ":"))
        return (text + "\n").encode("utf-8", errors="replace")

    def _ensure_fd(self) -> int:
        if self._fd is not None:
            return self._fd
        self.path.parent.mkdir(parents=True, exist_ok=True)
        _chmod(self.path.parent, 0o700)
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        if os.name != "nt":
            with contextlib.suppress(OSError):
                os.fchmod(fd, 0o600)
        self._fd = fd
        return fd

    def _rotate_if_needed(self, line_len: int) -> None:
        """Single-generation size rotation. No gzip, no timestamped archive.

        This file grows on every tool call in a long-lived Claude Desktop
        session, so an unbounded append-only file in $HOME is not an acceptable
        follow-up.
        """
        if self.max_bytes <= 0:
            return
        fd = self._ensure_fd()
        size = os.fstat(fd).st_size
        if size == 0 or size + line_len <= self.max_bytes:
            return
        rotated = self.path.with_name(self.path.name + ".1")
        os.close(fd)
        self._fd = None
        os.replace(self.path, rotated)
        _chmod(rotated, 0o600)
        self._ensure_fd()

    def _on_failure(self, exc: BaseException) -> None:
        self._drops += 1
        self._failures += 1
        if self._fd is not None:
            with contextlib.suppress(Exception):
                os.close(self._fd)
            self._fd = None
        logger = logging.getLogger(__name__)
        if self._warnings < MAX_FAILURE_WARNINGS:
            self._warnings += 1
            logger.warning("Audit write failed path=%s reason=%s: %s", self.path, _failure_kind(exc), exc)
        if self._failures >= MAX_CONSECUTIVE_FAILURES:
            self.enabled = False
            logger.warning(
                "Audit log disabled after %d consecutive failures path=%s dropped=%d",
                self._failures,
                self.path,
                self._drops,
            )

    def close(self) -> None:
        with self._lock:
            if self._fd is not None:
                with contextlib.suppress(Exception):
                    os.close(self._fd)
                self._fd = None


def format_console_line(record: AuditRecord, *, arguments: dict[str, Any] | None = None) -> str | None:
    """Derive the Rich console line from a record, or None for a silent decision.

    Single source of truth for the console. The divergence this module fixes was
    caused by two independent formatting paths, so a third would recreate it.

    `arguments` is the raw dict on purpose. The console is ephemeral and local;
    the file is persistent and may be shipped somewhere. That is why the console
    still shows raw arguments while a default record only carries a keyed hash.
    """
    tool = record.tool or "-"
    if record.action is AuditAction.BLOCK_INJECTION:
        return f"[INJECT]  {tool:<10} prompt injection detected (critical)"
    if record.action is AuditAction.REDACT_OUTPUT:
        return f"[REDACT]  {tool:<10} ({record.pii_redactions or 0} PII items redacted)"
    if record.action in (AuditAction.BLOCK_RESULT_INJECTION, AuditAction.NEUTRALIZE_RESULT):
        return f"[RESULT]  {tool:<10} {record.detail}"
    if record.action in (AuditAction.BLOCK_METADATA, AuditAction.REDACT_METADATA):
        return f"[META]    {record.method or '-':<10} {record.detail}"
    args_text = json.dumps(arguments or {}, separators=(", ", ": "), ensure_ascii=True, default=str)
    if record.action is AuditAction.BLOCK_POLICY:
        return f"[BLOCK]   {tool:<10} {args_text}  <- {record.rule or 'policy_block'}"
    if record.action is AuditAction.REQUIRE_APPROVAL:
        return f"[APPROVE] {tool:<10} {args_text}  <- {record.rule or 'requires_approval'}"
    if record.action is AuditAction.ALLOW:
        return f"[ALLOW]   {tool:<10} {args_text}"
    return None


_full_args_warned = False
_writer: AuditWriter | None = None
_writer_lock = threading.Lock()


def _warn_full_args_once(path: Path) -> None:
    global _full_args_warned
    if _full_args_warned:
        return
    _full_args_warned = True
    logging.getLogger(__name__).warning(
        "AGENTPARRY_AUDIT_ARGS=full: raw tool arguments, including any secrets, "
        "are being written to %s. Every record stamps args_mode=full.",
        path,
    )


def get_writer() -> AuditWriter:
    """Process-wide writer, created lazily.

    An accessor rather than a fifth module-level global in `src/proxy.py`, so
    tests have one seam to swap instead of one more shared mutable import.
    """
    global _writer
    with _writer_lock:
        if _writer is None:
            _writer = AuditWriter()
        return _writer


def set_writer(writer: AuditWriter) -> None:
    global _writer
    with _writer_lock:
        previous, _writer = _writer, writer
    if previous is not None and previous is not writer:
        previous.close()


def reset_writer() -> None:
    global _writer
    with _writer_lock:
        previous, _writer = _writer, None
    if previous is not None:
        previous.close()


__all__ = [
    "DEFAULT_MAX_BYTES",
    "DEFAULT_MAX_LINE_BYTES",
    "KEY_BYTES",
    "MAX_CONSECUTIVE_FAILURES",
    "MAX_PREVIEW_CHARS",
    "AuditWriter",
    "ShortWriteError",
    "arg_hash",
    "audit_enabled",
    "build_preview",
    "canonical_json",
    "default_audit_path",
    "default_key_path",
    "format_console_line",
    "get_writer",
    "key_id",
    "load_or_create_key",
    "omit_sensitive",
    "reset_writer",
    "resolve_args_mode",
    "set_writer",
    "utc_now_iso",
]
