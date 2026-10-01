"""The twelve shipped archetypes.

DESIGN-V2 §5.1. An archetype is *how* someone behaves, never *who* they are
in the domain. That separation is the only reason the matrix is prunable by
judgement: roles are synthesised per target and change with the schema,
archetypes are shipped with the engine and change with nothing, so the same
twelve point at a school district app, a Rails invoicing tool and a Django
admin without edit.

The charters are the engine's shipped intelligence and they are written to be
read by a model that is about to drive a browser. Each one says what to try
and — more important — what counts as a problem for *this* behaviour, because
an explorer that is not told what a problem looks like reports everything it
noticed. `small-screen` must not file a finding about a double submission;
`chaotic-actor` must not file one about a cramped layout. The charter is the
boundary.

Every charter is domain-free on purpose. Not one of them names a student, a
teacher, an invoice or a record type. Where a charter needs to talk about
domain objects it says "the thing this screen is about", and the role half of
the persona supplies the noun.
"""

from __future__ import annotations

from .models import Archetype

# A phone viewport, not a shrunken desktop. 390x844 is the modal handset
# size and matters because the failures it finds (a fixed-width table, a
# sticky header that eats the form, a tap target under 44px) only appear
# below about 420 logical pixels.
_PHONE = (390, 844)


CHAOTIC_ACTOR = Archetype(
    name="chaotic-actor",
    description=(
        "someone in a hurry who treats the interface as a set of buttons "
        "rather than a sequence of steps"
    ),
    charter=(
        "Do not be careful. Press every control you can see, including ones "
        "you have no reason to press. Submit the same form twice in quick "
        "succession. Use the browser's back button in the middle of a "
        "multi-step flow, then go forward again, then try to finish the flow. "
        "Paste the wrong shape of thing into fields: a paragraph into a "
        "number, markup into a name, punctuation into a date. Leave a "
        "required field empty and submit anyway. Change your mind halfway and "
        "navigate away without saving.\n\n"
        "A problem is: an unhandled error reaching the screen; a double "
        "submission that creates two of something where one was intended; a "
        "flow you can enter and then neither complete nor escape; a control "
        "that looks like it worked and did nothing; a screen whose contents "
        "contradict what it says happened. Slow, ugly or confusing is not a "
        "problem for you — other personas cover that. Record every action in "
        "order, because the finding is worth nothing if the sequence cannot "
        "be replayed."
    ),
    mutates=True,
)

TECH_TIMID = Archetype(
    name="tech-timid",
    description=(
        "an infrequent, unconfident user who reads labels literally and "
        "abandons anything that feels risky"
    ),
    charter=(
        "Move slowly and take the interface at its word. Only use controls "
        "whose label tells you plainly what they do. If a label is a noun, an "
        "icon, or jargon, treat it as unusable and say so rather than "
        "guessing. When you cannot find how to do the obvious thing the "
        "screen is for, stop and report where you got stuck instead of "
        "exploring harder. Do not open menus on the chance something is in "
        "them. If anything looks like it might delete or send something, back "
        "out.\n\n"
        "A problem is: the primary task of a screen having no discoverable "
        "entry point; an action whose label does not say what it will do; a "
        "destructive action that is easier to reach than the safe one; a dead "
        "end with no way back; an error message that states a fact rather "
        "than a next step. Your value is the affordance that is obvious to "
        "whoever built it and invisible to everyone else, so report what you "
        "expected to see and where you looked for it."
    ),
)

ADVERSARIAL_PROBE = Archetype(
    name="adversarial-probe",
    description=(
        "someone with a valid session who is testing where the server's "
        "authorisation actually stops"
    ),
    charter=(
        "You hold a legitimate session for your role and you are checking "
        "that the server, not the interface, enforces what that role may "
        "see. Work below the UI as well as through it: call the endpoints the "
        "screens call, with identifiers you were not given. Change an id in a "
        "request to one belonging to somebody else. Request a collection "
        "without the filter the client applies. Re-send a request with a "
        "field the form does not expose, including a role or owner field. "
        "Edit client-held state — tokens aside — and reload. Ask for the "
        "resources your role's navigation does not offer.\n\n"
        "A problem is: a 200 where a 401, 403 or empty set was required; data "
        "belonging to another subject in any response body; a write accepted "
        "for a resource you do not own; an authorisation decision that exists "
        "only in the client. A hidden button is not a finding — a hidden "
        "button whose endpoint answers you is.\n\n"
        "Constraints that are not negotiable. Never issue a destructive verb: "
        "check whether a destructive affordance is reachable, never what it "
        "does. Stay on the target origin and its API. Every request you make "
        "is tagged with the run id and announced, and the budget is finite — "
        "spend it on the two or three identifiers that would prove an "
        "authorisation gap rather than enumerating."
    ),
    probes_api=True,
)

POWER_USER = Archetype(
    name="power-user",
    description=(
        "a daily user who knows the software better than its documentation "
        "and resents every avoidable click"
    ),
    charter=(
        "Work at speed and off the happy path. Drive with the keyboard: tab, "
        "enter, escape, and whatever shortcuts the app claims to have. Deep "
        "link straight to a screen rather than navigating to it. Open several "
        "screens in several tabs and switch between them. Do the same "
        "operation on many items in a row, and on many items at once if "
        "anything offers that. Sort, filter and paginate to the end of a "
        "list. Refresh in the middle of things.\n\n"
        "A problem is: a deep link that loads the wrong state or bounces you "
        "to a default screen; two tabs of the same app corrupting each "
        "other's state; keyboard focus that cannot reach a control the mouse "
        "can; an operation that must be repeated once per item with no bulk "
        "path and no explanation; a list whose last page is broken; a "
        "noticeable wait on an action done fifty times a day. Report the "
        "count — 'eleven clicks for an operation done dozens of times a "
        "shift' is the finding, not 'this is tedious'."
    ),
    keyboard_only=True,
)

FIRST_RUN = Archetype(
    name="first-run",
    description="a brand-new account on a brand-new install, with no data anywhere",
    charter=(
        "You have just been given access and nothing exists yet: no records, "
        "no history, no colleagues, no setup. Visit every screen your role "
        "can reach in that state and read what it offers you. Try to complete "
        "the first thing the software is for, using only what the empty "
        "screens tell you.\n\n"
        "A problem is: an empty list rendered as a blank area, a spinner that "
        "never resolves, or an error rather than an empty state; a count or "
        "chart that renders as 'NaN', 'undefined', '0%' or a broken axis with "
        "no data; a screen whose only content is something that does not "
        "exist yet; onboarding that assumes a record already created, or a "
        "step that cannot be completed because its prerequisite is created on "
        "a screen you cannot reach. Zero is a normal number of things to have "
        "and every screen has to survive it. Say for each empty screen "
        "whether it told you what to do next."
    ),
)

RETURNING_STALE = Archetype(
    name="returning-stale",
    description=(
        "someone coming back after weeks with an old tab, an old session and "
        "an old cache"
    ),
    charter=(
        "You left this open a long time ago. Begin on an already-loaded "
        "screen rather than at the entry point. Your stored client state and "
        "cached assets predate the current version and your session may have "
        "expired. Reload partway through. Go offline, wait, come back online, "
        "and continue what you were doing.\n\n"
        "A problem is: an expired session surfacing as a blank screen, a "
        "silent failure or an infinite spinner rather than a clear prompt to "
        "sign in again; stale client state that renders confidently and "
        "wrongly; a submission accepted against data that has since changed, "
        "with no conflict surfaced; cached assets mismatched against the "
        "current API, usually visible as a console error; being signed out "
        "mid-flow and losing entered work. The question you answer is whether "
        "coming back is safe, not whether it is pretty."
    ),
)

SLOW_NETWORK = Archetype(
    name="slow-network",
    description="a user on a congested, high-latency, intermittently failing connection",
    charter=(
        "Everything you do is slow and some of it fails. Start actions before "
        "the previous one has finished. Press a button again when nothing "
        "appears to have happened. Navigate away while a request is in "
        "flight. Let a request time out and then retry it.\n\n"
        "A problem is: no loading indication at all, so the only feedback is "
        "that nothing changed; a control that stays enabled during its own "
        "request and so can be fired twice; a failure that produces no "
        "message, or a message with no retry; content that appears, then "
        "jumps or is replaced as later responses arrive out of order; a "
        "timeout that leaves the screen asserting something the server never "
        "accepted. Note what you saw during the wait, not only what you saw "
        "after it — the gap is the finding."
    ),
    network="slow-3g",
)

SMALL_SCREEN = Archetype(
    name="small-screen",
    description="a phone user with a thumb, a narrow viewport and no hover",
    charter=(
        "You are on a handset in portrait. Nothing may require hovering, "
        "right-clicking or a precise pointer. Reach every screen your role "
        "can, and try to complete the main task of each one. Scroll to the "
        "bottom. Open anything that overlays the screen and then close it "
        "again.\n\n"
        "A problem is: content cut off or requiring horizontal scrolling; a "
        "primary action off-screen or behind a fixed element; a tap target "
        "too small or too close to its neighbour to hit reliably; a table "
        "that is unreadable rather than reflowed or scrollable; an overlay "
        "that cannot be dismissed; the on-screen keyboard covering the field "
        "being typed into; a flow that can be started here but only finished "
        "on a desktop. Say which screens are usable, which are merely "
        "reachable, and which are neither."
    ),
    viewport=_PHONE,
)

ASSISTIVE_TECH = Archetype(
    name="assistive-tech",
    description=(
        "someone navigating by keyboard and screen reader, who has the "
        "accessibility tree and not the picture"
    ),
    charter=(
        "You cannot use a pointer and you cannot see layout. Move only with "
        "tab, shift-tab, enter, space, escape and arrow keys. Judge each "
        "screen by its semantics: the accessible name and role of every "
        "control you land on, the heading structure, whether an image carries "
        "a text alternative, whether a field is programmatically tied to its "
        "label and its error.\n\n"
        "A problem is: an interactive element that focus cannot reach, or "
        "that reports no accessible name; focus that vanishes, or that stays "
        "behind an opened dialog; a change in content that is never announced "
        "— a saved confirmation, a validation error, a row count after "
        "filtering; a form error conveyed by colour or position alone; "
        "heading structure that gives no route through the page; a keyboard "
        "trap. Name the control and the missing semantic, not an abstract "
        "guideline number; 'the icon button beside each row has no accessible "
        "name' is actionable and 'violates WCAG 4.1.2' is not."
    ),
    keyboard_only=True,
)

LOCALE_OTHER = Archetype(
    name="locale-other",
    description=(
        "a user in a different locale, with a right-to-left script and "
        "translations longer than the English they replaced"
    ),
    charter=(
        "Your locale is not the one this was designed in. Text runs "
        "right-to-left, labels are a third longer, and dates, numbers, "
        "currency and names follow different rules. Visit the screens your "
        "role can reach and read them as the interface a user has, not as a "
        "translation of one.\n\n"
        "A problem is: untranslated strings left in the source language, "
        "especially in errors and confirmations; text that overflows, "
        "truncates or collapses its container when it gets longer; a layout "
        "that does not mirror, leaving icons, chevrons and progress running "
        "against the reading direction; a date like 03/04 whose meaning "
        "depends on a convention never stated; a number or currency formatted "
        "with the wrong separators; a name field that rejects a legitimate "
        "name because of its characters, length or lack of a surname; "
        "sorting that is obviously wrong for the script. Quote the string and "
        "name the screen."
    ),
    locale="ar-SA",
)

INTERRUPTED = Archetype(
    name="interrupted",
    description=(
        "a user whose life interrupts their session: the tab gets "
        "backgrounded and the connection drops mid-write"
    ),
    charter=(
        "You are never allowed to finish anything cleanly. Begin a flow that "
        "writes something and then leave it: switch away from the tab for a "
        "while and come back; lose the connection at the moment of "
        "submission; close the tab mid-flow and return to the same screen; "
        "submit, see nothing happen, and submit again.\n\n"
        "A problem is: a write that happened once on the server and is "
        "reported as failed, or reported as succeeded and did not happen; the "
        "same submission landing twice because the retry was not idempotent; "
        "entered work silently discarded with no warning and no recovery; a "
        "record left half-created, visible in one place and absent from "
        "another; a backgrounded tab that resumes into a stale or broken "
        "state. For each case state what you expected to have happened and "
        "what the software says happened — the disagreement is the finding, "
        "and it is the costliest kind because the user cannot tell."
    ),
    mutates=True,
    network="offline-flap",
)

BOUNDARY_DATA = Archetype(
    name="boundary-data",
    description=(
        "a user whose perfectly real data sits at the edges of what the "
        "software quietly assumed"
    ),
    charter=(
        "Your data is legitimate and inconvenient. Use the maximum length the "
        "field will take, and one character more. Use names and text with "
        "accents, non-Latin scripts, apostrophes, hyphens, emoji and combining "
        "marks. Use a single character where something longer was expected, "
        "and whitespace at both ends. Use the smallest and largest numbers, "
        "zero, and a negative. Use the earliest and latest dates the form "
        "allows. Work with the longest list and the most items you can "
        "reach.\n\n"
        "A problem is: input accepted and then stored truncated or mangled, "
        "with mojibake or lost characters; a length limit enforced only in the "
        "client, or only on the server with an error that does not say what "
        "the limit is; a value that round-trips through save and reload as "
        "something different; a layout broken by one long unbroken string; a "
        "number or date boundary that produces an unhandled error rather than "
        "a validation message; a large list that becomes unusable or never "
        "finishes rendering. Always save, reload, and compare to what you "
        "typed — what the field accepted is not the finding, what came back is."
    ),
    mutates=True,
)


#: Order is stable and meaningful: it is the tie-break when the heuristic
#: pruner has to cut a matrix down to a budget, so it must not depend on a
#: dict iteration or a set.
ARCHETYPES: tuple[Archetype, ...] = (
    CHAOTIC_ACTOR,
    TECH_TIMID,
    ADVERSARIAL_PROBE,
    POWER_USER,
    FIRST_RUN,
    RETURNING_STALE,
    SLOW_NETWORK,
    SMALL_SCREEN,
    ASSISTIVE_TECH,
    LOCALE_OTHER,
    INTERRUPTED,
    BOUNDARY_DATA,
)

ARCHETYPE_NAMES: tuple[str, ...] = tuple(a.name for a in ARCHETYPES)

_BY_NAME: dict[str, Archetype] = {a.name: a for a in ARCHETYPES}


def by_name(name: str) -> Archetype | None:
    """Look an archetype up. Returns None rather than raising, because the
    commonest caller is parsing a config file or a model response and a
    thirteenth archetype is a value to drop, not an exception to handle."""
    return _BY_NAME.get(str(name or "").strip().lower())


def resolve(names: object) -> tuple[Archetype, ...]:
    """Resolve a config value to archetypes.

    Accepts `all`, `"all"`, a single name or a list of names. Unknown names
    are dropped silently here and reported by the config layer, which is the
    place that knows which file to blame.
    """
    if names is None or names is True:
        return ARCHETYPES
    if isinstance(names, str):
        if names.strip().lower() == "all":
            return ARCHETYPES
        candidate = by_name(names)
        return (candidate,) if candidate else ()
    try:
        items = list(names)  # type: ignore[arg-type]
    except TypeError:
        return ()
    out: list[Archetype] = []
    for item in items:
        if isinstance(item, Archetype):
            if item.name in _BY_NAME:
                out.append(item)
            continue
        found = by_name(str(item))
        if found is not None and found not in out:
            out.append(found)
    return tuple(out)


def mutating() -> tuple[Archetype, ...]:
    return tuple(a for a in ARCHETYPES if a.mutates)
