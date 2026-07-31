"""Package data: the policy and payload files AgentParry ships.

Both entries are symlinks to the canonical files at the repo root, so
``config/default_policy.yaml`` and ``attacks/payloads.yaml`` stay the single
source of truth for a developer while setuptools copies their contents into the
wheel and sdist. Resolve them through `src.resources`, never by relative path.
"""
