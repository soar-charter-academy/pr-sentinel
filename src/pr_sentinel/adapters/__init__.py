"""The adapter layer: DESIGN-V2 §3, where we stop reimplementing other
people's rules and start normalising their output.

The six adapters here replace roughly 6,000 lines of v1 checks. Each one runs
a tool that is better at its job than we were and speaks our `Finding` model
on the way out, so severity policy, dedup, rendering and the verdict still
have exactly one type to reason about.

| adapter | tool | required | replaced |
|---|---|---|---|
| `zizmor` | `zizmor` | yes | the whole `github-actions` pack |
| `gitleaks` | `gitleaks` | yes | `core/rules/secrets.yml` |
| `socket` | `socket` | no | `supply-chain.new-dependency`, `.install-scripts` |
| `supabase-advisors` | `supabase` | no | three Supabase lints we had copied |
| `squawk` | `squawk` | no | migration-safety guesswork in the agent tier |
| `actionlint` | `actionlint` | no | nothing; it is new breadth |

Only two are required, and both for the same reason: without them, a class
of problem is not looked for at all. There is no other Actions auditor, and
this repository is private on the free tier so there is no GitHub secret
scanning underneath `gitleaks`. The optional four are keyed services, need
database connectivity, or add breadth over checks we still perform
ourselves — their absence costs coverage, not a guarantee, and a required
adapter that gets switched off because it is red on every fork is worth
less than an optional one that is loudly absent.
"""

from __future__ import annotations

# Importing the adapter modules is what populates the registry, exactly as in
# `tier1/engine.py`. Explicit rather than a directory scan: an adapter that
# silently fails to register is a tool everyone believes is running, and the
# whole design rests on absence being loud.
from . import (  # noqa: F401  (imported for side effects)
    actionlint,
    gitleaks,
    socket,
    squawk,
    supabase_advisors,
    zizmor,
)
from .base import (
    DEFAULT_TIMEOUT,
    AdapterContext,
    AdapterResult,
    AdapterSpec,
    RegisteredAdapter,
    all_adapters,
    findings_from_sarif,
    get,
    missing_tool_result,
    register,
    run_tool,
    tool_version,
    which,
)
from .runner import AdapterRunReport, missing_required_adapters, run_adapters

__all__ = [
    "DEFAULT_TIMEOUT",
    "AdapterContext",
    "AdapterResult",
    "AdapterRunReport",
    "AdapterSpec",
    "RegisteredAdapter",
    "all_adapters",
    "findings_from_sarif",
    "get",
    "missing_required_adapters",
    "missing_tool_result",
    "register",
    "run_adapters",
    "run_tool",
    "tool_version",
    "which",
]


def required_adapters() -> list[str]:
    """Adapter ids whose absence withholds the deterministic check-run."""
    return sorted(a.adapter_id for a in all_adapters().values() if a.required)
