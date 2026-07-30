"""Pin an MCP server's advertised metadata and diff it on every discovery.

:class:`~src.inspector.MetadataInspector` catches a server that is poisoned when
you look at it. It cannot catch a server that is clean on day one and rewrites a
tool description a month later, because nothing about the new description has to
match a pattern for it to redirect the agent. This module closes that hole and
only that hole: it records what a server advertised the first time it was seen
and reports every later change against it.

Three deliberate choices:

* Fingerprints are taken over the **raw** canonical JSON of each tool, never a
  normalized view. Normalizing first would let an attacker flip zero-width
  characters freely, and a change that adds only invisible instructions would
  hash identically. Whitespace churn producing a diff is the correct trade.
* The set-level fingerprint sorts tools by name and folds in a count, so
  legitimate reordering is invisible while an addition or a removal is not.
* Server identity comes from how the server is launched, never from
  ``serverInfo.name``, which is attacker-controlled: a malicious server would
  simply rename itself out of its own pin.

The store is advisory. It is read-only in steady state, every write goes through
an ``flock`` plus ``os.replace`` and is merged per server key, and a busy lock or
an unreadable file is skipped rather than allowed to hold up the MCP stream. A
local attacker who can write the pin file defeats the mechanism outright; 0600 in
a 0700 directory is hygiene, not a defense.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import shlex
import tempfile
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError

from src.audit import canonical_json, utc_now_iso
from src.inspector import MetadataInspector, is_prose_leaf, iter_string_leaves
from src.models import (
    AUDIT_SEVERITY_ORDER,
    AuditFinding,
    AuditTransport,
    Finding,
    PinDiff,
    PinFile,
    PinObservation,
    PinSnapshot,
    ServerPin,
    ToolPin,
    max_severity,
)

logger = logging.getLogger(__name__)

if os.name != "nt":
    import fcntl
else:  # pragma: no cover - the test suite and both proxies are POSIX-only today
    fcntl = None  # type: ignore[assignment]

DEFAULT_PINS_DIR = ".agentparry"
DEFAULT_PINS_FILENAME = "pins.json"
LOCK_SUFFIX = ".lock"

DEFAULT_LOCK_TIMEOUT = 2.0
LOCK_POLL_SECONDS = 0.02

LAST_SEEN_INTERVAL_SECONDS = 86_400.0
"""How stale ``last_seen`` must be before an unchanged server earns a write.

Steady state has to be read-only, or two clients wrapping the same server would
contend on every handshake for a field nobody reads in anger.
"""

MAX_KEY_CHARS = 400

PIN_REDACTION = (
    "[AgentParry removed this text: it changed since this server was pinned, and the changed metadata "
    "matches an injection signature. Run `agentparry pins diff` to review it.]"
)

_INSTRUCTIONS_SUBJECT = "initialize.instructions"
"""Subject key for escalated findings on server instructions, never a tool name."""

_ESCALATION: dict[str, str] = {
    "low": "medium",
    "medium": "high",
    "high": "critical",
    "critical": "critical",
}


def escalate_severity(severity: str) -> str:
    """Raise one severity level, saturating at critical.

    Changed metadata is more suspicious than the same text sitting in a catalogue
    that never moved, so a signature that reads as ``high`` on first sight reads
    as ``critical`` on a rug pull.
    """
    return _ESCALATION.get(severity, severity if severity in AUDIT_SEVERITY_ORDER else "medium")


def _digest(domain: str, value: Any) -> str:
    return hashlib.sha256(f"{domain}\x00{canonical_json(value)}".encode(errors="replace")).hexdigest()


def tool_fingerprint(tool: Any) -> str:
    """SHA-256 over the raw canonical JSON of one tool object."""
    return _digest("agentparry-pin-tool", tool)


def tool_name_of(tool: Any) -> str | None:
    """Return a tool's advertised name, or None when it has no usable one."""
    if not isinstance(tool, dict):
        return None
    name = tool.get("name")
    if isinstance(name, str) and name:
        return name
    return None


def tools_set_fingerprint(tools: Sequence[Any]) -> str:
    """SHA-256 over the (name, fingerprint) pairs sorted by name, plus a count.

    Sorted so a server that reorders its catalogue does not read as a change.
    Counted so a duplicate name cannot hide behind another entry.
    """
    entries = sorted((tool_name_of(tool) or "", tool_fingerprint(tool)) for tool in tools)
    return _digest("agentparry-pin-set", {"count": len(tools), "tools": entries})


def instructions_fingerprint(instructions: Any) -> str | None:
    """SHA-256 over ``initialize``'s instructions string, or None when absent."""
    if not isinstance(instructions, str):
        return None
    return _digest("agentparry-pin-instructions", instructions)


def server_info_fingerprint(server_info: Any) -> str | None:
    """SHA-256 over ``initialize``'s serverInfo object, or None when absent."""
    if server_info is None:
        return None
    return _digest("agentparry-pin-serverinfo", server_info)


def fingerprint_tools(tools: Sequence[Any]) -> dict[str, ToolPin]:
    """Fingerprint each named tool, at a timestamp shared across the page."""
    now = utc_now_iso()
    pinned: dict[str, ToolPin] = {}
    for tool in tools:
        name = tool_name_of(tool)
        if name is None:
            logger.info("Skipping tools/list entry with no usable name while pinning")
            continue
        if name in pinned:
            logger.warning("Duplicate tool name in tools/list; the set fingerprint will differ name=%s", name)
        pinned[name] = ToolPin(fingerprint=tool_fingerprint(tool), updated=now)
    return pinned


def normalize_argv(argv: Sequence[str] | str) -> str:
    """Reduce a launch command to one whitespace-normalized line.

    A string is split with :mod:`shlex` first, so ``npx  server`` and
    ``npx server`` are the same server and not two pins.
    """
    tokens = shlex.split(argv, posix=os.name != "nt") if isinstance(argv, str) else list(argv)
    return " ".join(token.strip() for token in tokens if token and token.strip())


def _scoped_key(scheme: str, value: str) -> str:
    if len(value) > MAX_KEY_CHARS:
        return f"{scheme}:sha256:{hashlib.sha256(value.encode(errors='replace')).hexdigest()}"
    return f"{scheme}:{value}"


@dataclass(frozen=True, slots=True)
class ServerIdentity:
    """How one MCP server is addressed, and therefore how its pin is keyed.

    The key is derived from the wrapped argv or the upstream URL, both of which
    are known before any traffic and neither of which the server can influence.
    """

    key: str
    target: str
    transport: AuditTransport

    @classmethod
    def for_command(
        cls, argv: Sequence[str] | str, *, transport: AuditTransport = AuditTransport.STDIO
    ) -> ServerIdentity:
        """Key on the wrapped command line."""
        target = normalize_argv(argv)
        return cls(key=_scoped_key("cmd", target), target=target, transport=transport)

    @classmethod
    def for_url(cls, url: str, *, transport: AuditTransport = AuditTransport.HTTP) -> ServerIdentity:
        """Key on the upstream URL."""
        target = url.strip()
        return cls(key=_scoped_key("url", target), target=target, transport=transport)


def default_pins_path() -> Path:
    """Resolve the pin store path, honoring ``AGENTPARRY_PINS_PATH``."""
    override = os.environ.get("AGENTPARRY_PINS_PATH", "").strip()
    if override:
        return Path(override).expanduser()
    try:
        home = Path.home()
    except (RuntimeError, OSError):
        home = Path(os.environ.get("TMPDIR", "/tmp"))
    return home / DEFAULT_PINS_DIR / DEFAULT_PINS_FILENAME


def _chmod(path: Path, mode: int) -> None:
    if os.name == "nt":
        return
    with contextlib.suppress(OSError):
        os.chmod(path, mode)


class PinStore:
    """Reads and writes the JSON pin store, atomically and under a file lock.

    Every write re-reads the file inside the lock and merges one server key, so a
    second client wrapping a different server cannot lose its entry. The path is
    resolved per call rather than at construction, so an environment override set
    after import (which is how the tests isolate it) still applies.
    """

    def __init__(self, path: Path | str | None = None, *, lock_timeout: float = DEFAULT_LOCK_TIMEOUT) -> None:
        self._path = Path(path).expanduser() if path is not None else None
        self.lock_timeout = lock_timeout

    @property
    def path(self) -> Path:
        """The pin file this store operates on."""
        return self._path if self._path is not None else default_pins_path()

    @property
    def lock_path(self) -> Path:
        """The sidecar lock file, held instead of the replaced pin file itself."""
        return self.path.with_name(self.path.name + LOCK_SUFFIX)

    def load(self) -> PinFile:
        """Return the whole store, quarantining a corrupt file rather than raising."""
        path = self.path
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return PinFile()
        except OSError as exc:
            logger.warning("Pin store unreadable path=%s reason=%s", path, exc)
            return PinFile()
        try:
            return PinFile.model_validate_json(text)
        except (ValidationError, ValueError):
            self._quarantine(path)
            return PinFile()

    def get(self, key: str) -> ServerPin | None:
        """Return one server's pin, or None when it has never been seen."""
        return self.load().servers.get(key)

    def mutate(self, key: str, apply: Callable[[ServerPin | None], ServerPin | None]) -> bool:
        """Read-modify-write one server key under the lock. False means skipped.

        ``apply`` returning the pin it was given unchanged, or None for a pin that
        did not exist, writes nothing at all: that is how steady state stays
        read-only.
        """
        with self._locked() as acquired:
            if not acquired:
                logger.warning("Pin store lock busy after %.1fs; skipping the update key=%s", self.lock_timeout, key)
                return False
            data = self.load()
            before = data.servers.get(key)
            after = apply(before.model_copy(deep=True) if before is not None else None)
            if after is None:
                if before is None:
                    return True
                data.servers.pop(key, None)
            else:
                if before is not None and before == after:
                    return True
                data.servers[key] = after
            try:
                self._write(data)
            except OSError as exc:
                logger.warning("Pin store write failed path=%s reason=%s", self.path, exc)
                return False
            return True

    def _quarantine(self, path: Path) -> None:
        """Move an unparseable pin file aside so the next run starts clean.

        Not fatal, and not silently deleted: a corrupt store means every pin is
        gone, which an operator needs to be able to see.
        """
        target = path.with_name(f"{path.name}.corrupt-{utc_now_iso().replace(':', '')}")
        try:
            os.replace(path, target)
        except OSError as exc:
            logger.warning("Corrupt pin store could not be quarantined path=%s reason=%s", path, exc)
            return
        logger.warning("Corrupt pin store quarantined path=%s moved_to=%s", path, target)

    @contextlib.contextmanager
    def _locked(self) -> Iterator[bool]:
        if fcntl is None:
            yield True
            return
        path = self.lock_path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            _chmod(path.parent, 0o700)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        except OSError as exc:
            logger.warning("Pin store lock unavailable path=%s reason=%s", path, exc)
            yield False
            return
        deadline = time.monotonic() + self.lock_timeout
        acquired = False
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(LOCK_POLL_SECONDS)
            yield acquired
        finally:
            if acquired:
                with contextlib.suppress(OSError):
                    fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _write(self, data: PinFile) -> None:
        path = self.path
        path.parent.mkdir(parents=True, exist_ok=True)
        _chmod(path.parent, 0o700)
        payload = data.model_dump_json(indent=2) + "\n"
        fd, raw_tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
        tmp = Path(raw_tmp)
        try:
            if os.name != "nt":
                with contextlib.suppress(OSError):
                    os.fchmod(fd, 0o600)
            os.write(fd, payload.encode("utf-8", errors="replace"))
        finally:
            os.close(fd)
        try:
            os.replace(tmp, path)
        except OSError:
            with contextlib.suppress(OSError):
                tmp.unlink()
            raise
        _chmod(path, 0o600)


class ToolPinSettings(BaseModel):
    """What to do when a server's advertised metadata no longer matches its pin."""

    enabled: bool = True
    action: Literal["off", "warn", "redact_changed", "block"] = "warn"
    lock_timeout: float = Field(default=DEFAULT_LOCK_TIMEOUT, ge=0)
    last_seen_interval: float = Field(default=LAST_SEEN_INTERVAL_SECONDS, ge=0)


def _findings_for_audit(escalated: Sequence[AuditFinding]) -> list[Finding]:
    """Adapt persisted pin findings back into the shape the audit writer reads."""
    return [
        Finding(
            severity=item.severity,  # type: ignore[arg-type]
            description=item.description,
            field=item.field,
            matched_pattern=item.pattern,
        )
        for item in escalated
        if item.severity in AUDIT_SEVERITY_ORDER
    ]


def redact_tool_prose(tool: dict[str, Any]) -> bool:
    """Replace every prose leaf of one tool with the pin marker, in place.

    Only prose. ``enum`` members, defaults, ``required`` and property key names
    stay intact so the tool is still callable and client-side schema validation
    still passes, exactly as metadata redaction does.
    """
    replaced = False
    for path, container, key, _text in list(iter_string_leaves(tool, "tool", include_keys=True)):
        if container is None or not is_prose_leaf(path):
            continue
        container[key] = PIN_REDACTION
        replaced = True
    return replaced


class ToolPinner:
    """Diff a discovery response against the pin on disk and report the change.

    The default action on a diff is ``warn`` and not ``block``: benign description
    updates are routine, and a proxy that breaks discovery whenever a maintainer
    rewords a description gets turned off. What does act is a diff whose changed
    metadata itself matches an injection signature, because the changed tools are
    re-inspected with every severity raised one level. So "changed **and** now
    looks like a prompt injection" costs the tool its prose, while a routine
    update costs a log line.

    First sight records the pin and reports that it did, without diffing.
    Flagging everything on first contact trains people to ignore the warning. Be
    clear about what that means: a server that is malicious on day one gets its
    poison pinned as the baseline, and catching that is
    :class:`~src.inspector.MetadataInspector`'s job, not this one's. The only
    hedge is that a critical metadata finding at creation time writes the pin
    ``trusted: false``, which re-reports on every discovery until accepted.
    """

    def __init__(
        self,
        identity: ServerIdentity | None = None,
        *,
        settings: ToolPinSettings | None = None,
        store: PinStore | None = None,
        inspector: MetadataInspector | None = None,
    ) -> None:
        self._identity = identity
        self._settings = settings or ToolPinSettings()
        self._store = store or PinStore(lock_timeout=self._settings.lock_timeout)
        self._inspector = inspector or MetadataInspector()

    @classmethod
    def from_policy_settings(cls, settings: Any, **kwargs: Any) -> ToolPinner:
        """Build from the ``settings.tool_pinning`` block of a policy file."""
        raw = settings.get("tool_pinning") if isinstance(settings, dict) else None
        if not isinstance(raw, dict):
            return cls(**kwargs)
        overrides = {key: value for key, value in raw.items() if key in ToolPinSettings.model_fields}
        if overrides.get("action") is False:
            overrides["action"] = "off"
        try:
            parsed = ToolPinSettings(**overrides)
        except ValidationError:
            logger.exception("Invalid settings.tool_pinning block, using defaults")
            parsed = ToolPinSettings()
        return cls(settings=parsed, **kwargs)

    @property
    def settings(self) -> ToolPinSettings:
        """Return the settings this pinner was built with."""
        return self._settings

    @property
    def store(self) -> PinStore:
        """Return the pin store this pinner writes to."""
        return self._store

    @property
    def identity_key(self) -> str:
        """Return the pin key this pinner defaults to, or ``-`` when it has none."""
        return self._identity.key if self._identity is not None else "-"

    def observe(
        self,
        method: str,
        result: dict[str, Any],
        findings: Sequence[Finding] = (),
        *,
        identity: ServerIdentity | None = None,
    ) -> PinObservation:
        """Dispatch on the JSON-RPC method that produced this discovery result.

        Pass the **raw** upstream result, before metadata redaction rewrote it:
        pinning the redacted form would diff on every run and would pin poison
        that inspection had already removed as if it were clean.
        """
        target = identity or self._identity
        if not self._active() or target is None:
            return PinObservation()
        if method == "tools/list":
            return self._observe_tools_list(target, result, findings)
        if method == "initialize":
            return self._observe_initialize(target, result, findings)
        return PinObservation()

    def apply(self, payload: dict[str, Any], observation: PinObservation) -> dict[str, Any]:
        """Apply an observation's action to the response being forwarded.

        Takes the payload metadata inspection produced, not the raw result, so
        redaction composes with whatever that inspector already did.
        """
        if observation.redact_instructions and isinstance(payload.get("instructions"), str):
            payload["instructions"] = PIN_REDACTION
        if not observation.redact_tools:
            return payload
        tools = payload.get("tools")
        if not isinstance(tools, list):
            return payload
        wanted = set(observation.redact_tools)
        for tool in tools:
            if isinstance(tool, dict) and tool_name_of(tool) in wanted:
                redact_tool_prose(tool)
        return payload

    def _active(self) -> bool:
        return self._settings.enabled and self._settings.action != "off"

    def _observe_tools_list(
        self, identity: ServerIdentity, result: dict[str, Any], findings: Sequence[Finding]
    ) -> PinObservation:
        tools = result.get("tools")
        if not isinstance(tools, list):
            return PinObservation()

        paginated = bool(result.get("nextCursor"))
        observed = fingerprint_tools(tools)
        if paginated:
            logger.info(
                "tools/list carries nextCursor; skipping set-level pin diffing for this page key=%s tools=%d",
                identity.key,
                len(tools),
            )

        snapshot = PinSnapshot(
            observed_at=utc_now_iso(),
            tools=observed,
            merge_tools=paginated,
            set_fingerprint=None if paginated else tools_set_fingerprint(tools),
            tool_count=None if paginated else len(tools),
        )
        pin = self._store.get(identity.key)
        if pin is None or not pin.tools_seen:
            return self._create(
                identity,
                pin,
                findings,
                snapshot=snapshot,
                detail=f"{len(observed)} tool(s) pinned" + (" (first page only)" if paginated else ""),
                paginated=paginated,
            )

        diff = self._diff_tools(pin, observed, tools, paginated=paginated)
        escalated = {
            name: self._escalated_tool_findings(tool)
            for tool in tools
            if (name := tool_name_of(tool)) in (*diff.changed, *diff.added)
        }
        return self._settle(identity, pin, diff, snapshot, escalated=escalated, paginated=paginated)

    def _observe_initialize(
        self, identity: ServerIdentity, result: dict[str, Any], findings: Sequence[Finding]
    ) -> PinObservation:
        info = result.get("serverInfo")
        instructions = result.get("instructions")
        if info is None and instructions is None:
            return PinObservation()

        snapshot = PinSnapshot(
            observed_at=utc_now_iso(),
            identity=True,
            server_info=info if isinstance(info, dict) else None,
            server_info_fingerprint=server_info_fingerprint(info),
            instructions_fingerprint=instructions_fingerprint(instructions),
        )
        pin = self._store.get(identity.key)
        if pin is None or not pin.identity_seen:
            return self._create(identity, pin, findings, snapshot=snapshot, detail="server identity pinned")

        diff = PinDiff(
            server_info_changed=snapshot.server_info_fingerprint != pin.server_info_fingerprint,
            instructions_changed=snapshot.instructions_fingerprint != pin.instructions_fingerprint,
        )
        escalated: dict[str, list[AuditFinding]] = {}
        if diff.instructions_changed and isinstance(instructions, str):
            escalated[_INSTRUCTIONS_SUBJECT] = self._escalated_instruction_findings(instructions)
        return self._settle(identity, pin, diff, snapshot, escalated=escalated)

    def _create(
        self,
        identity: ServerIdentity,
        existing: ServerPin | None,
        findings: Sequence[Finding],
        *,
        snapshot: PinSnapshot,
        detail: str,
        paginated: bool = False,
    ) -> PinObservation:
        """Record a facet nobody has pinned yet, without diffing it.

        Reached for a brand new server and for the first ``initialize`` after a
        ``tools/list``-only pin, because neither has anything to diff against.
        """
        critical = [f for f in findings if f.severity == "critical"]
        reason = (
            f"metadata inspection reported {len(critical)} critical finding(s) when the pin was created"
            if critical
            else ""
        )

        def apply(current: ServerPin | None) -> ServerPin | None:
            now = utc_now_iso()
            pin = current or ServerPin(
                key=identity.key,
                target=identity.target,
                transport=identity.transport,
                created=now,
            )
            _apply_snapshot(pin, snapshot)
            pin.updated = now
            pin.last_seen = now
            if critical:
                pin.trusted = False
                pin.untrusted_reason = reason
            return pin

        if not self._store.mutate(identity.key, apply):
            return PinObservation(status="skipped", key=identity.key, detail="pin store unavailable")
        trusted = not critical and (existing is None or existing.trusted)
        suffix = f"; {reason}" if reason else ""
        return PinObservation(
            status="created",
            key=identity.key,
            trusted=trusted,
            paginated=paginated,
            detail=f"pin created: {detail}{suffix}",
        )

    def _settle(
        self,
        identity: ServerIdentity,
        pin: ServerPin,
        diff: PinDiff,
        snapshot: PinSnapshot,
        *,
        escalated: dict[str, list[AuditFinding]],
        paginated: bool = False,
    ) -> PinObservation:
        if diff.is_empty:
            self._touch(identity, pin)
            detail = "metadata matches the pin"
            if not pin.trusted:
                detail = f"metadata matches the pin, which is not accepted yet: {pin.untrusted_reason}"
            return PinObservation(
                status="unchanged",
                key=identity.key,
                trusted=pin.trusted,
                paginated=paginated,
                detail=detail,
            )

        diff.escalated = [finding for items in escalated.values() for finding in items]
        snapshot.diff = diff
        self._record_pending(identity, pin, snapshot)

        acting = {
            subject for subject, items in escalated.items() if any(f.severity == "critical" for f in items)
        }
        action: Literal["none", "warn", "redact_changed", "block"] = "warn"
        redact = sorted(acting - {_INSTRUCTIONS_SUBJECT})
        redact_instructions = _INSTRUCTIONS_SUBJECT in acting
        if self._settings.action == "block":
            action = "block"
            redact = []
            redact_instructions = False
        elif self._settings.action == "redact_changed":
            action = "redact_changed"
            redact = sorted({*diff.changed, *diff.added})
            redact_instructions = diff.instructions_changed
        elif redact or redact_instructions:
            action = "redact_changed"

        return PinObservation(
            status="changed",
            key=identity.key,
            trusted=pin.trusted,
            diff=diff,
            action=action,
            blocked=action == "block",
            block_message="Blocked: this server's tool metadata changed since it was pinned",
            redact_tools=redact,
            redact_instructions=redact_instructions,
            paginated=paginated,
            detail=f"{action}: {diff.summary()}",
        )

    def _diff_tools(
        self, pin: ServerPin, observed: dict[str, ToolPin], tools: Sequence[Any], *, paginated: bool
    ) -> PinDiff:
        changed = sorted(
            name
            for name, entry in observed.items()
            if name in pin.tools and pin.tools[name].fingerprint != entry.fingerprint
        )
        added = sorted(name for name in observed if name not in pin.tools)
        if paginated:
            return PinDiff(changed=changed, added=added)
        removed = sorted(name for name in pin.tools if name not in observed)
        set_fingerprint = tools_set_fingerprint(tools)
        return PinDiff(
            changed=changed,
            added=added,
            removed=removed,
            set_changed=pin.set_fingerprint is not None and set_fingerprint != pin.set_fingerprint,
        )

    def _escalated_tool_findings(self, tool: Any) -> list[AuditFinding]:
        try:
            return _escalate(self._inspector.scan_tool(tool))
        except Exception:
            logger.exception("Re-inspection of changed tool metadata failed; reporting the diff alone")
            return []

    def _escalated_instruction_findings(self, instructions: str) -> list[AuditFinding]:
        try:
            return _escalate(self._inspector.scan_instructions(instructions))
        except Exception:
            logger.exception("Re-inspection of changed server instructions failed; reporting the diff alone")
            return []

    def _record_pending(self, identity: ServerIdentity, pin: ServerPin, snapshot: PinSnapshot) -> None:
        """Store the observed catalogue so the CLI can show and accept it.

        Skipped when the same snapshot is already pending, so a rug pull is
        re-reported on every discovery without writing the file again.
        """
        merged = _merge_snapshots(pin.pending, snapshot)
        if pin.pending is not None and _same_pending(pin.pending, merged):
            return

        def apply(existing: ServerPin | None) -> ServerPin | None:
            if existing is None:
                return None
            existing.pending = _merge_snapshots(existing.pending, snapshot)
            existing.updated = utc_now_iso()
            return existing

        self._store.mutate(identity.key, apply)

    def _touch(self, identity: ServerIdentity, pin: ServerPin) -> None:
        """Refresh ``last_seen``, but only once per interval.

        The whole point of the throttle: an unchanged server causes no write at
        all, which is what makes two clients wrapping the same server a
        non-event.
        """
        if _seconds_since(pin.last_seen) < self._settings.last_seen_interval:
            return

        def apply(existing: ServerPin | None) -> ServerPin | None:
            if existing is None:
                return None
            existing.last_seen = utc_now_iso()
            return existing

        self._store.mutate(identity.key, apply)


def accept_pending(store: PinStore, key: str) -> ServerPin | None:
    """Promote a pending snapshot into the pin and mark it trusted.

    Returns the accepted pin, or None when there was nothing to accept.
    """
    accepted: list[ServerPin] = []

    def apply(existing: ServerPin | None) -> ServerPin | None:
        if existing is None:
            return None
        if existing.pending is None and existing.trusted:
            return existing
        if existing.pending is not None:
            _apply_snapshot(existing, existing.pending)
            existing.pending = None
        existing.trusted = True
        existing.untrusted_reason = ""
        existing.updated = utc_now_iso()
        existing.last_seen = utc_now_iso()
        accepted.append(existing)
        return existing

    store.mutate(key, apply)
    return accepted[0] if accepted else None


def forget(store: PinStore, key: str) -> bool:
    """Delete one server's pin. Returns False when it was not there."""
    found: list[bool] = []

    def apply(existing: ServerPin | None) -> ServerPin | None:
        found.append(existing is not None)
        return None

    store.mutate(key, apply)
    return bool(found and found[0])


def _merge_snapshots(existing: PinSnapshot | None, incoming: PinSnapshot) -> PinSnapshot:
    """Fold a new observation into a pending one, per facet.

    A pending tool-list diff and a later identity diff are one pending snapshot,
    so accepting once accepts everything the operator was shown.
    """
    if existing is None:
        return incoming
    merged = existing.model_copy(deep=True)
    merged.observed_at = incoming.observed_at
    merged.diff = existing.diff.merge(incoming.diff)
    if incoming.identity:
        merged.identity = True
        merged.server_info = incoming.server_info
        merged.server_info_fingerprint = incoming.server_info_fingerprint
        merged.instructions_fingerprint = incoming.instructions_fingerprint
    if incoming.tools is not None:
        if incoming.merge_tools and merged.tools is not None:
            merged.tools = {**merged.tools, **incoming.tools}
        else:
            merged.tools = dict(incoming.tools)
        merged.merge_tools = incoming.merge_tools
        if incoming.set_fingerprint is not None:
            merged.set_fingerprint = incoming.set_fingerprint
        if incoming.tool_count is not None:
            merged.tool_count = incoming.tool_count
    return merged


def _escalate(findings: Sequence[Finding]) -> list[AuditFinding]:
    return [
        AuditFinding(
            severity=escalate_severity(finding.severity),
            description=finding.description,
            field=finding.field,
            pattern=finding.matched_pattern,
        )
        for finding in findings
    ]


def _apply_snapshot(pin: ServerPin, snapshot: PinSnapshot) -> None:
    """Copy one observed facet onto a pin, leaving the other facet alone.

    An ``initialize`` observation must not wipe the tool set, one page of a
    paginated ``tools/list`` must not wipe the pages after it, and an identity
    observation applies its fingerprints verbatim including ``None``, which is how
    instructions being withdrawn is recorded rather than ignored.
    """
    if snapshot.identity:
        pin.server_info = snapshot.server_info
        pin.server_info_fingerprint = snapshot.server_info_fingerprint
        pin.instructions_fingerprint = snapshot.instructions_fingerprint
        pin.identity_seen = True
    if snapshot.tools is not None:
        if snapshot.merge_tools:
            pin.tools.update(snapshot.tools)
        else:
            pin.tools = dict(snapshot.tools)
        pin.tools_seen = True
        if snapshot.set_fingerprint is not None:
            pin.set_fingerprint = snapshot.set_fingerprint
        if snapshot.tool_count is not None:
            pin.tool_count = snapshot.tool_count


def _same_pending(existing: PinSnapshot, candidate: PinSnapshot) -> bool:
    """Compare two pending snapshots by fingerprint, ignoring when they were taken.

    Timestamps are excluded on purpose: the same unaccepted rug pull observed
    again must not earn a write, or "re-report until accepted" would mean
    rewriting the pin file on every handshake.
    """
    return _pending_shape(existing) == _pending_shape(candidate)


def _pending_shape(snapshot: PinSnapshot) -> dict[str, Any]:
    fingerprints = None if snapshot.tools is None else {name: pin.fingerprint for name, pin in snapshot.tools.items()}
    return {
        "tools": fingerprints,
        "merge_tools": snapshot.merge_tools,
        "set_fingerprint": snapshot.set_fingerprint,
        "tool_count": snapshot.tool_count,
        "identity": snapshot.identity,
        "server_info_fingerprint": snapshot.server_info_fingerprint,
        "instructions_fingerprint": snapshot.instructions_fingerprint,
    }


def _seconds_since(timestamp: str) -> float:
    if not timestamp:
        return float("inf")
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return float("inf")
    return (datetime.now(UTC) - parsed).total_seconds()


def audit_findings_for(observation: PinObservation) -> list[Finding]:
    """Return an observation's escalated findings in audit-writer shape."""
    if observation.diff is None:
        return []
    return _findings_for_audit(observation.diff.escalated)


def highest_escalated(observation: PinObservation) -> str | None:
    """Return the highest escalated severity in an observation, or None."""
    if observation.diff is None or not observation.diff.escalated:
        return None
    return max_severity(finding.severity for finding in observation.diff.escalated)


__all__ = [
    "DEFAULT_LOCK_TIMEOUT",
    "LAST_SEEN_INTERVAL_SECONDS",
    "PIN_REDACTION",
    "PinStore",
    "ServerIdentity",
    "ToolPinSettings",
    "ToolPinner",
    "accept_pending",
    "audit_findings_for",
    "default_pins_path",
    "escalate_severity",
    "fingerprint_tools",
    "forget",
    "highest_escalated",
    "instructions_fingerprint",
    "normalize_argv",
    "redact_tool_prose",
    "server_info_fingerprint",
    "tool_fingerprint",
    "tool_name_of",
    "tools_set_fingerprint",
]
