"""Absolute resolution of the policy and payload files AgentParry ships.

Every default resolves the same way, in order: an explicit path from a flag, an
environment variable, a per-user copy under ``~/.agentparry``, then the copy that
ships inside the ``src.data`` package. Nothing resolves relative to the current
directory unless the caller asked for a relative path, so an installed
``agentparry`` works from anywhere.

The packaged files are read-only in an installed tree. `copy_out` materializes a
writable user copy, which every later resolution then prefers.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

DATA_PACKAGE = "src.data"
PACKAGED_POLICY_FILENAME = "default_policy.yaml"
PACKAGED_PAYLOADS_FILENAME = "payloads.yaml"

POLICY_ENV = "AGENTPARRY_POLICY"
PAYLOADS_ENV = "AGENTPARRY_PAYLOADS"
HOME_ENV = "AGENTPARRY_HOME"

USER_DIR_NAME = ".agentparry"
USER_POLICY_FILENAME = "policy.yaml"
USER_PAYLOADS_FILENAME = "payloads.yaml"

POLICY_DEFAULT_HELP = "AGENTPARRY_POLICY, then ~/.agentparry/policy.yaml, then the packaged policy"
PAYLOADS_DEFAULT_HELP = "AGENTPARRY_PAYLOADS, then ~/.agentparry/payloads.yaml, then the packaged corpus"

SOURCE_FLAG = "flag"
SOURCE_ENV = "env"
SOURCE_USER = "user"
SOURCE_PACKAGED = "packaged"


class Unset:
    """Sentinel type meaning "resolve the shipped default"."""


UNSET = Unset()
"""Default for arguments where ``None`` already means something else."""


@dataclass(frozen=True)
class ResolvedFile:
    """A resolved default file, and which precedence step produced it."""

    path: Path
    source: str

    @property
    def packaged(self) -> bool:
        """True when this is the read-only copy inside the installed package."""
        return self.source == SOURCE_PACKAGED

    def __str__(self) -> str:
        return str(self.path)


def user_dir() -> Path:
    """The per-user AgentParry directory, honoring ``AGENTPARRY_HOME``."""
    override = os.environ.get(HOME_ENV, "").strip()
    if override:
        return Path(override).expanduser()
    try:
        home = Path.home()
    except (RuntimeError, OSError):
        home = Path(os.environ.get("TMPDIR", "/tmp"))
    return home / USER_DIR_NAME


def user_policy_path() -> Path:
    """Where a writable policy lives once the user has one."""
    return user_dir() / USER_POLICY_FILENAME


def user_payloads_path() -> Path:
    """Where a user-supplied payload corpus lives once the user has one."""
    return user_dir() / USER_PAYLOADS_FILENAME


def _packaged(filename: str) -> Path:
    """Absolute path of a file shipped in ``src.data``.

    Assumes an unpacked install, which is what pip produces; a zipimported
    package would need `importlib.resources.as_file` and a temp copy, and the
    proxies hand these paths to long-lived readers that outlive any context
    manager.
    """
    return Path(str(resources.files(DATA_PACKAGE).joinpath(filename))).resolve()


def packaged_policy_path() -> Path:
    """Absolute path of the policy file that ships with the package."""
    return _packaged(PACKAGED_POLICY_FILENAME)


def packaged_payloads_path() -> Path:
    """Absolute path of the payload corpus that ships with the package."""
    return _packaged(PACKAGED_PAYLOADS_FILENAME)


def _resolve(
    explicit: str | Path | None,
    *,
    env_name: str,
    user_path: Path,
    packaged_path: Path,
) -> ResolvedFile:
    if explicit is not None and str(explicit).strip():
        return ResolvedFile(Path(str(explicit)).expanduser(), SOURCE_FLAG)
    env_value = os.environ.get(env_name, "").strip()
    if env_value:
        return ResolvedFile(Path(env_value).expanduser(), SOURCE_ENV)
    if user_path.is_file():
        return ResolvedFile(user_path, SOURCE_USER)
    return ResolvedFile(packaged_path, SOURCE_PACKAGED)


def resolve_policy(explicit: str | Path | None = None) -> ResolvedFile:
    """Resolve the policy file to use, flag over env over user copy over packaged."""
    return _resolve(
        explicit,
        env_name=POLICY_ENV,
        user_path=user_policy_path(),
        packaged_path=packaged_policy_path(),
    )


def resolve_payloads(explicit: str | Path | None = None) -> ResolvedFile:
    """Resolve the payload corpus to use, flag over env over user copy over packaged."""
    return _resolve(
        explicit,
        env_name=PAYLOADS_ENV,
        user_path=user_payloads_path(),
        packaged_path=packaged_payloads_path(),
    )


def policy_path(explicit: str | Path | None | Unset = UNSET) -> Path:
    """Policy path for a library caller: the given one, or the resolved default."""
    if isinstance(explicit, Unset) or explicit is None:
        return resolve_policy().path
    return Path(explicit)


def copy_out(source: Path, destination: Path) -> Path:
    """Copy a read-only default to a writable location, creating its directory."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    return destination


def copy_out_policy(source: Path | None = None) -> Path:
    """Materialize the user's own policy from the packaged default."""
    return copy_out(source or packaged_policy_path(), user_policy_path())
