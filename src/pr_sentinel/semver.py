"""A small, dependency-free semver implementation.

Exists because DESIGN s15 resolved pack versioning in favour of *independent
pack pinning*: a consuming repo pins each pack's version separately rather
than inheriting whatever a single engine tag happens to ship.

The practical consequence is that the engine must be able to answer "does the
pack I am shipping satisfy the spec this repo pinned?" and fail loudly when it
does not. Silently running a pack the repo did not ask for is exactly the
failure mode `@main` pinning was rejected to avoid (DESIGN s4).

Supported spec syntax, a deliberate subset of node-semver:

    *  or  any        anything
    1.2.3             exact
    =1.2.3            exact
    ^1.2.3            >=1.2.3 <2.0.0   (and ^0.2.3 => >=0.2.3 <0.3.0)
    ~1.2.3            >=1.2.3 <1.3.0
    >=1.2.3           comparators: > >= < <= =
    >=1.2.3 <2.0.0    space-separated comparators are ANDed
    1.x / 1.2.x       wildcard ranges
    a || b            alternatives are ORed
"""

from __future__ import annotations

import functools
import re
from dataclasses import dataclass

_VERSION_RE = re.compile(
    r"^\s*v?(\d+)\.(\d+)\.(\d+)"
    r"(?:-([0-9A-Za-z.-]+))?"
    r"(?:\+([0-9A-Za-z.-]+))?\s*$"
)

_COMPARATOR_RE = re.compile(r"^(>=|<=|>|<|=|\^|~)?\s*(.+)$")


class InvalidVersion(ValueError):
    pass


class InvalidSpec(ValueError):
    pass


@functools.total_ordering
@dataclass(frozen=True)
class Version:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str | int, ...] = ()
    build: str | None = None

    @classmethod
    def parse(cls, text: str) -> Version:
        m = _VERSION_RE.match(str(text))
        if not m:
            raise InvalidVersion(f"not a semver version: {text!r}")
        major, minor, patch, pre, build = m.groups()
        prerelease: tuple[str | int, ...] = ()
        if pre:
            prerelease = tuple(int(p) if p.isdigit() else p for p in pre.split("."))
        return cls(int(major), int(minor), int(patch), prerelease, build)

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            base += "-" + ".".join(str(p) for p in self.prerelease)
        if self.build:
            base += "+" + self.build
        return base

    @property
    def _core(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        # Build metadata is ignored in precedence, per the spec.
        return self._core == other._core and self.prerelease == other.prerelease

    def __hash__(self) -> int:
        return hash((self._core, self.prerelease))

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        if self._core != other._core:
            return self._core < other._core
        # A version WITH a prerelease is lower than one without.
        if self.prerelease and not other.prerelease:
            return True
        if not self.prerelease and other.prerelease:
            return False
        return _compare_prerelease(self.prerelease, other.prerelease) < 0


def _compare_prerelease(a: tuple, b: tuple) -> int:
    for x, y in zip(a, b):
        if x == y:
            continue
        # Numeric identifiers always have lower precedence than alphanumeric.
        x_num, y_num = isinstance(x, int), isinstance(y, int)
        if x_num and not y_num:
            return -1
        if y_num and not x_num:
            return 1
        return -1 if x < y else 1  # type: ignore[operator]
    return (len(a) > len(b)) - (len(a) < len(b))


@dataclass(frozen=True)
class _Comparator:
    op: str
    version: Version

    def matches(self, v: Version) -> bool:
        if self.op == ">":
            return v > self.version
        if self.op == ">=":
            return v >= self.version
        if self.op == "<":
            return v < self.version
        if self.op == "<=":
            return v <= self.version
        return v == self.version


class Spec:
    """A parsed version specification."""

    def __init__(self, raw: str) -> None:
        self.raw = str(raw).strip()
        self._clauses: list[list[_Comparator]] | None = self._parse(self.raw)

    @property
    def is_any(self) -> bool:
        return self._clauses is None

    def matches(self, version: Version | str) -> bool:
        v = Version.parse(version) if isinstance(version, str) else version
        if self._clauses is None:
            return True
        return any(all(c.matches(v) for c in clause) for clause in self._clauses)

    def __str__(self) -> str:
        return self.raw

    def __repr__(self) -> str:
        return f"Spec({self.raw!r})"

    # -- parsing ---------------------------------------------------------

    @staticmethod
    def _parse(raw: str) -> list[list[_Comparator]] | None:
        if raw in ("", "*", "any", "latest"):
            return None
        clauses = []
        for alternative in raw.split("||"):
            alternative = alternative.strip()
            if not alternative:
                raise InvalidSpec(f"empty alternative in spec {raw!r}")
            comparators: list[_Comparator] = []
            for part in _split_comparators(alternative):
                comparators.extend(_parse_comparator(part, raw))
            if not comparators:
                return None
            clauses.append(comparators)
        return clauses


def _split_comparators(text: str) -> list[str]:
    """Split on whitespace but keep an operator attached to its version."""
    tokens = text.split()
    out: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in (">=", "<=", ">", "<", "=", "^", "~") and i + 1 < len(tokens):
            out.append(tok + tokens[i + 1])
            i += 2
        else:
            out.append(tok)
            i += 1
    return out


def _parse_comparator(part: str, raw: str) -> list[_Comparator]:
    m = _COMPARATOR_RE.match(part.strip())
    if not m:
        raise InvalidSpec(f"cannot parse {part!r} in spec {raw!r}")
    op, rest = m.group(1) or "=", m.group(2).strip()

    if "x" in rest.lower() or "*" in rest:
        return _wildcard(op, rest, raw)

    partial = _parse_partial(rest, raw)

    if op == "^":
        return _caret(partial)
    if op == "~":
        return _tilde(partial)

    major, minor, patch = partial
    if minor is None or patch is None:
        # ">=1" means ">=1.0.0"; "=1.2" means the 1.2.x range.
        if op == "=":
            return _wildcard("=", rest, raw)
        return [_Comparator(op, Version(major, minor or 0, patch or 0))]
    return [_Comparator(op, Version.parse(rest))]


def _parse_partial(rest: str, raw: str) -> tuple[int, int | None, int | None]:
    bits = rest.lstrip("v").split("+")[0].split("-")[0].split(".")
    try:
        nums = [int(b) for b in bits]
    except ValueError as exc:
        raise InvalidSpec(f"cannot parse version {rest!r} in spec {raw!r}") from exc
    while len(nums) < 3:
        nums.append(None)  # type: ignore[arg-type]
    if len(nums) > 3:
        raise InvalidSpec(f"too many version segments in {rest!r} (spec {raw!r})")
    return nums[0], nums[1], nums[2]


def _wildcard(op: str, rest: str, raw: str) -> list[_Comparator]:
    if op not in ("=", "^", "~"):
        raise InvalidSpec(f"wildcard not allowed with operator {op!r} in spec {raw!r}")
    bits = rest.lstrip("v").split(".")
    concrete = []
    for b in bits:
        if b.lower() in ("x", "*", ""):
            break
        concrete.append(int(b))
    if not concrete:
        return []  # "x" / "*" -> any
    if len(concrete) == 1:
        lo = Version(concrete[0], 0, 0)
        hi = Version(concrete[0] + 1, 0, 0)
    else:
        lo = Version(concrete[0], concrete[1], 0)
        hi = Version(concrete[0], concrete[1] + 1, 0)
    return [_Comparator(">=", lo), _Comparator("<", hi)]


def _caret(partial: tuple[int, int | None, int | None]) -> list[_Comparator]:
    major, minor, patch = partial
    lo = Version(major, minor or 0, patch or 0)
    # Caret bounds the range at the leftmost *non-zero* stated segment, and
    # where every stated segment is zero, at the last one the author actually
    # wrote. `^0` and `^0.0` are therefore NOT the same as `^0.0.0`: omitting
    # a segment is a wider pin, not a tighter one. Collapsing them all to
    # `<0.0.1` refuses pins node-semver accepts, and since an unsatisfiable
    # pin is a hard error here, that turns a valid pin into a failed review.
    if major > 0:
        hi = Version(major + 1, 0, 0)
    elif minor is None:
        hi = Version(1, 0, 0)  # ^0
    elif minor > 0:
        hi = Version(0, minor + 1, 0)  # ^0.2.3
    elif patch is None:
        hi = Version(0, 1, 0)  # ^0.0
    else:
        hi = Version(0, 0, patch + 1)  # ^0.0.3
    return [_Comparator(">=", lo), _Comparator("<", hi)]


def _tilde(partial: tuple[int, int | None, int | None]) -> list[_Comparator]:
    major, minor, patch = partial
    lo = Version(major, minor or 0, patch or 0)
    hi = Version(major, (minor or 0) + 1, 0) if minor is not None else Version(major + 1, 0, 0)
    return [_Comparator(">=", lo), _Comparator("<", hi)]


def satisfies(version: str | Version, spec: str | Spec) -> bool:
    s = spec if isinstance(spec, Spec) else Spec(spec)
    return s.matches(version)
