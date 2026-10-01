"""Model access, kept behind a small interface.

Three reasons this is an abstraction rather than a direct API call:

1. **Tests must run without a key or a network.** `ScriptedProvider` replays
   canned responses, so the agent tier's orchestration, parsing and
   verification logic are all testable offline. An agent tier that can only
   be tested by spending money does not get tested.

2. **Triage cheap, escalate expensive** (DESIGN s9). Two models, chosen per
   call. Reviewing a lockfile with a frontier model is how this gets
   abandoned on cost, so the cost control has to live somewhere structural.

3. **Provenance.** Every call records which model answered, and that ends up
   in the PR comment so a verdict is reproducible (DESIGN s10).

Implemented with `urllib` rather than the vendor SDK to keep the runtime
dependency list at PyYAML. A review engine that drags a dependency tree into
CI is poorly placed to lecture anyone about supply chain.

The tool-use loop (DESIGN-V2 s4) lives here too, for the same reason and with
the same constraint: `urllib`, no SDK, and a scripted twin so the loop is
testable with no key and no network. The provider owns the *conversation* —
assistant `tool_use` blocks in, `tool_result` blocks back — and knows nothing
about what a tool does. Confinement and budgets are `tools.py`'s job, and
keeping them there means there is exactly one copy of those rules.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"

DEFAULT_TIMEOUT = 120
DEFAULT_MAX_TOKENS = 4096

#: Sent with the tool results once a budget has run out. The loop makes one
#: more call, without tools, so that a pass that spent its budget still
#: returns the findings it managed to substantiate instead of nothing.
FINAL_TURN_NUDGE = (
    "The tool budget for this pass is spent. No further tool calls will be "
    "answered. Return your final JSON answer now, based only on what you have "
    "already established, and omit any finding you could not substantiate."
)


class ModelError(RuntimeError):
    pass


class NoCredentials(ModelError):
    pass


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    calls: int = 0

    def add(self, other: Usage) -> None:
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.calls += other.calls


@dataclass
class Completion:
    text: str
    model: str
    usage: Usage = field(default_factory=Usage)
    stop_reason: str | None = None


@dataclass
class ToolExecution:
    """The outcome of one tool call, as the model will see it.

    `content` is already fenced as untrusted data by the time it gets here —
    the tool layer does that, not the provider, because the provider has no
    way to know which parts of a result came from the pull request.

    `halt` is how a budget reaches the loop. The runner decides it has
    answered enough; the provider's job is to stop asking.
    """

    content: str
    is_error: bool = False
    halt: bool = False
    summary: str = ""


class ToolRunner(Protocol):
    """What the provider needs from a tool implementation.

    Deliberately two members. The provider must not know what a tool does,
    where it reads from, or what its budget is — otherwise the confinement
    rules in `tools.py` would have a second, weaker copy in here.
    """

    @property
    def specs(self) -> list[dict[str, Any]]: ...

    def run(self, name: str, arguments: dict[str, Any] | None = None) -> ToolExecution: ...


@dataclass
class ToolCompletion(Completion):
    """A completion that may have taken several model turns to produce."""

    rounds: int = 0
    tool_calls: int = 0
    notes: list[str] = field(default_factory=list)


class ModelProvider(Protocol):
    def complete(
        self,
        *,
        system: str,
        prompt: str,
        model: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float = 0.0,
    ) -> Completion: ...

    def complete_with_tools(
        self,
        *,
        system: str,
        prompt: str,
        model: str,
        runner: ToolRunner,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float = 0.0,
        max_rounds: int = 24,
    ) -> ToolCompletion: ...

    @property
    def models_used(self) -> dict[str, str]: ...

    @property
    def usage(self) -> Usage: ...


class AnthropicProvider:
    """Live provider.

    Temperature defaults to 0. This is a reviewer: the same PR should get the
    same review twice, and a verdict that moves between runs is a verdict
    nobody can act on.
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        timeout: int = DEFAULT_TIMEOUT,
        max_retries: int = 3,
        base_url: str = ANTHROPIC_URL,
    ) -> None:
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self._api_key:
            raise NoCredentials(
                "No ANTHROPIC_API_KEY. The agent tier needs one; the deterministic "
                "tiers do not. Run with --no-agent to skip Tier 2."
            )
        self._timeout = timeout
        self._max_retries = max_retries
        self._base_url = base_url
        self._usage = Usage()
        self._models_used: dict[str, str] = {}

    @property
    def usage(self) -> Usage:
        return self._usage

    @property
    def models_used(self) -> dict[str, str]:
        return dict(self._models_used)

    def complete(
        self,
        *,
        system: str,
        prompt: str,
        model: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float = 0.0,
    ) -> Completion:
        data = self._post(
            {
                "model": model,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "system": system,
                "messages": [{"role": "user", "content": prompt}],
            }
        )
        text, _blocks = _split_content(data)
        usage = self._record(data, model)
        return Completion(
            text=text, model=model, usage=usage, stop_reason=data.get("stop_reason")
        )

    def complete_with_tools(
        self,
        *,
        system: str,
        prompt: str,
        model: str,
        runner: ToolRunner,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float = 0.0,
        max_rounds: int = 24,
    ) -> ToolCompletion:
        """The tool-use loop, over the Messages API, in `urllib`.

        The shape is the documented one: the model answers with `tool_use`
        blocks, we echo its assistant message back verbatim and follow it with
        a user message of matching `tool_result` blocks. Echoing the blocks
        unchanged matters — a reconstructed assistant turn is a different
        conversation, and the ids would stop matching.

        Three ways out, and the loop reports which: the model stops asking for
        tools, the runner halts because a budget is spent, or `max_rounds` is
        reached. The last two append a note, and the note reaches the comment,
        because a pass that ran out of budget mid-investigation must not have
        its silence read as a clean result.
        """
        specs = runner.specs
        messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]
        usage = Usage()
        notes: list[str] = []
        tool_calls = 0
        text = ""
        rounds = 0

        while rounds < max(1, max_rounds):
            rounds += 1
            payload: dict[str, Any] = {
                "model": model,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "system": system,
                "messages": messages,
            }
            if specs:
                payload["tools"] = specs
            data = self._post(payload)
            usage.add(self._record(data, model))
            text, blocks = _split_content(data)
            tool_uses = [b for b in blocks if b.get("type") == "tool_use"]

            if not tool_uses:
                if data.get("stop_reason") == "max_tokens":
                    notes.append(
                        "The model's answer was cut off by the token limit; findings "
                        "from this pass may be incomplete."
                    )
                return ToolCompletion(
                    text=text,
                    model=model,
                    usage=usage,
                    stop_reason=data.get("stop_reason"),
                    rounds=rounds,
                    tool_calls=tool_calls,
                    notes=notes,
                )

            messages.append({"role": "assistant", "content": blocks})
            results: list[dict[str, Any]] = []
            halt = False
            for block in tool_uses:
                execution = runner.run(block.get("name", ""), block.get("input") or {})
                tool_calls += 1
                results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.get("id", ""),
                        "content": execution.content,
                        "is_error": execution.is_error,
                    }
                )
                halt = halt or execution.halt

            content: list[dict[str, Any]] = list(results)
            if halt:
                # One last turn, tools withheld, so the model has to answer
                # with what it has rather than asking again. The nudge rides
                # in the same user message as the tool results: two
                # consecutive user turns is not a conversation the API
                # accepts.
                content.append({"type": "text", "text": FINAL_TURN_NUDGE})
                messages.append({"role": "user", "content": content})
                final = self._post(
                    {
                        "model": model,
                        "max_tokens": max_tokens,
                        "temperature": temperature,
                        "system": system,
                        "messages": messages,
                    }
                )
                usage.add(self._record(final, model))
                text, _ = _split_content(final)
                return ToolCompletion(
                    text=text,
                    model=model,
                    usage=usage,
                    stop_reason=final.get("stop_reason"),
                    rounds=rounds + 1,
                    tool_calls=tool_calls,
                    notes=notes,
                )
            messages.append({"role": "user", "content": content})

        notes.append(
            f"The tool loop reached its {max_rounds}-turn limit without the pass "
            "reaching a conclusion; it was stopped."
        )
        return ToolCompletion(
            text=text,
            model=model,
            usage=usage,
            stop_reason="tool_loop_limit",
            rounds=rounds,
            tool_calls=tool_calls,
            notes=notes,
        )

    # -- transport ---------------------------------------------------------

    def _record(self, data: dict[str, Any], model: str) -> Usage:
        usage_raw = data.get("usage") or {}
        usage = Usage(
            input_tokens=int(usage_raw.get("input_tokens", 0) or 0),
            output_tokens=int(usage_raw.get("output_tokens", 0) or 0),
            calls=1,
        )
        self._usage.add(usage)
        self._models_used[model] = data.get("model", model)
        return usage

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310  (fixed https endpoint)
            self._base_url,
            data=body,
            headers={
                "content-type": "application/json",
                "x-api-key": self._api_key or "",
                "anthropic-version": ANTHROPIC_VERSION,
                "user-agent": "pr-sentinel",
            },
            method="POST",
        )

        last_error: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310
                    data = json.loads(response.read().decode("utf-8"))
                break
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="replace")[:400]
                # 4xx other than 429 will not improve by trying again.
                if exc.code not in (408, 429, 500, 502, 503, 504):
                    raise ModelError(f"model API returned {exc.code}: {detail}") from exc
                last_error = ModelError(f"model API returned {exc.code}: {detail}")
            except (urllib.error.URLError, TimeoutError, ValueError) as exc:
                last_error = ModelError(f"model API call failed: {exc}")
            time.sleep(min(2**attempt, 8))
        else:
            raise last_error or ModelError("model API call failed")

        if not isinstance(data, dict):
            raise ModelError("model API returned something that is not an object")
        return data


def _split_content(data: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    """Separate a response's text from its raw content blocks.

    The blocks are returned unchanged because the tool loop has to echo them
    back verbatim; rebuilding them would break the `tool_use` ids.
    """
    blocks = [b for b in (data.get("content") or []) if isinstance(b, dict)]
    text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
    return text, blocks


class ScriptedProvider:
    """Offline provider for tests and dry runs.

    Responses are matched by a substring of the prompt, so a test can say
    "when asked to triage, return this" without reproducing the prompt.

    It also replays whole tool-use conversations, and that is not a nicety.
    The existing suite has no API key and no network, so a tool loop only
    testable against the live API is a tool loop that is never tested — and
    the parts most worth testing (does a budget actually end the loop, does a
    result actually arrive fenced, is a traversal actually refused) are
    exactly the parts a live-API test would be too slow and too flaky to
    assert.

    Script a conversation with `script_tools`:

        provider.script_tools(
            "## Your concern: parity",
            [
                [("grep", {"pattern": "awardPoints"})],
                [("read_file", {"path": "src/points.ts"})],
                final_json_answer,
            ],
        )
    """

    def __init__(self, responses: list[tuple[str, str]] | None = None, default: str = "") -> None:
        self._responses = responses or []
        self._default = default
        self._usage = Usage()
        self._models_used: dict[str, str] = {}
        self.prompts: list[tuple[str, str]] = []
        self._tool_scripts: list[tuple[str, list[Any]]] = []
        #: Everything the runner handed back, in order, so a test can assert
        #: on what the model was actually shown.
        self.tool_results: list[ToolExecution] = []
        self.tool_specs_seen: list[list[str]] = []

    @property
    def usage(self) -> Usage:
        return self._usage

    @property
    def models_used(self) -> dict[str, str]:
        return dict(self._models_used)

    def complete(
        self,
        *,
        system: str,
        prompt: str,
        model: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float = 0.0,
    ) -> Completion:
        self._note_call(model, prompt)
        return Completion(text=self._reply_for(system, prompt), model=model)

    # -- scripted tool use -------------------------------------------------

    def script_tools(self, needle: str, turns: list[Any]) -> None:
        """Register a tool conversation, keyed by a prompt/system substring."""
        self._tool_scripts.append((needle, list(turns)))

    def complete_with_tools(
        self,
        *,
        system: str,
        prompt: str,
        model: str,
        runner: ToolRunner,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float = 0.0,
        max_rounds: int = 24,
    ) -> ToolCompletion:
        """Replay a scripted tool conversation, really running the tools.

        The tools are not stubbed — the runner passed in is the real
        `ToolSession`, against a real temporary repository. Only the model's
        side is scripted, which is the half a test has no business asserting
        about anyway.

        With no script registered this degrades to `complete()`, which is why
        every pre-existing test keeps working unchanged: one prompt recorded,
        one response matched, no tools involved.
        """
        self.tool_specs_seen.append([spec["name"] for spec in runner.specs])
        script = self._match_script(system, prompt)
        if script is None:
            completion = self.complete(
                system=system,
                prompt=prompt,
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
            )
            return ToolCompletion(
                text=completion.text, model=model, usage=completion.usage, rounds=1
            )

        self._note_call(model, prompt)
        text = ""
        tool_calls = 0
        rounds = 0
        notes: list[str] = []

        for turn in script:
            rounds += 1
            if isinstance(turn, str):
                text = turn
                break
            halt = False
            for call in turn:
                name, arguments = (call if isinstance(call, tuple) else (call, {}))
                execution = runner.run(name, dict(arguments or {}))
                self.tool_results.append(execution)
                tool_calls += 1
                halt = halt or execution.halt
            if halt:
                # Same contract as the live loop: one final turn, no tools,
                # so a halted pass still returns what it managed to establish.
                notes.append("the scripted loop was halted by the runner")
                text = self._reply_for(system, prompt)
                rounds += 1
                break
        else:
            text = self._reply_for(system, prompt)

        self._usage.add(Usage(calls=max(0, rounds - 1)))
        return ToolCompletion(
            text=text,
            model=model,
            usage=Usage(calls=rounds),
            rounds=rounds,
            tool_calls=tool_calls,
            notes=notes,
        )

    def _match_script(self, system: str, prompt: str) -> list[Any] | None:
        for needle, turns in self._tool_scripts:
            if needle in prompt or needle in system:
                return turns
        return None

    def _note_call(self, model: str, prompt: str) -> None:
        self.prompts.append((model, prompt))
        self._usage.add(Usage(calls=1))
        self._models_used[model] = model + " (scripted)"

    def _reply_for(self, system: str, prompt: str) -> str:
        for needle, response in self._responses:
            if needle in prompt or needle in system:
                return response
        return self._default


_JSON_BLOCK = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def parse_json_response(text: str, expect: str = "object") -> Any:
    """Pull JSON out of a model response, tolerantly but not credulously.

    Models wrap JSON in prose and fences. This strips both. What it
    deliberately does not do is repair malformed JSON: a response the engine
    cannot parse becomes zero findings, which is the safe direction. Inventing
    structure from a garbled response is how a reviewer reports something the
    model never said.
    """
    if not text or not text.strip():
        return [] if expect == "array" else {}

    candidates: list[str] = []
    for match in _JSON_BLOCK.finditer(text):
        candidates.append(match.group(1).strip())
    candidates.append(text.strip())

    opener, closer = ("[", "]") if expect == "array" else ("{", "}")
    for candidate in candidates:
        try:
            return json.loads(candidate)
        except ValueError:
            pass
        start = candidate.find(opener)
        end = candidate.rfind(closer)
        if start != -1 and end > start:
            try:
                return json.loads(candidate[start : end + 1])
            except ValueError:
                continue
    return [] if expect == "array" else {}
