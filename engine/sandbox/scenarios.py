"""Scripted interaction scenarios - the "emulate a user" half of the method.

Extensions rarely misbehave on an idle blank page: Hulk (USENIX Sec 2014) showed that
malicious behaviour has to be *elicited*, and ExtPrivA (S&P 2023) elicits it by driving
realistic user interaction.  A scenario is our version of that: a fixed, replayable
script of pages and actions that both versions of an extension are subjected to.

The script must be **identical and deterministic** across the two runs.  Together with
mitmproxy replaying byte-identical responses, that leaves the extension version as the
only variable in the experiment - which is what makes the diff mean anything.

Only dummy credentials ever appear here.  They are fake by construction and are the
values an examiner will see in the traces.
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: Dummy credentials. Never real, never reused anywhere, and deliberately obvious.
DUMMY_USERNAME = "test.user@example.test"
DUMMY_PASSWORD = "Fixture-Passw0rd!"


@dataclass(frozen=True)
class Step:
    """One action in a scenario. ``action`` is one of goto/fill/click/wait/scroll."""

    action: str
    selector: str | None = None
    value: str | None = None
    seconds: float = 0.0


@dataclass(frozen=True)
class Scenario:
    """A named, fixed interaction script."""

    name: str
    description: str
    pages: tuple[str, ...]
    steps: tuple[Step, ...] = field(default_factory=tuple)
    #: Seconds to idle at the end, so late/delayed beaconing still lands in the trace.
    settle_seconds: float = 5.0


BANK_LOGIN = Scenario(
    name="bank-login-then-webmail",
    description=(
        "Log into a fake banking page with dummy credentials, then open a fake webmail "
        "inbox. Targets the two behaviours worth stealing: credentials and session "
        "cookies."
    ),
    pages=("http://demo-bank.test/login", "http://webmail.test/inbox"),
    steps=(
        Step("goto", value="http://demo-bank.test/login"),
        Step("wait", seconds=1.0),
        Step("fill", selector="input[name=username]", value=DUMMY_USERNAME),
        Step("fill", selector="input#password", value=DUMMY_PASSWORD),
        Step("click", selector="button[type=submit]"),
        Step("wait", seconds=2.0),
        Step("goto", value="http://webmail.test/inbox"),
        Step("wait", seconds=1.0),
        Step("scroll", seconds=0.5),
        Step("click", selector="li.message:first-child"),
        Step("wait", seconds=2.0),
    ),
)

CONTACTS = Scenario(
    name="webmail-then-crm-contacts",
    description=(
        "Browse pages dense with personal data but no credentials. Separates extensions "
        "that scrape contact data as their advertised function from those that steal "
        "secrets."
    ),
    pages=("http://webmail.test/inbox", "http://crm-demo.test/contacts"),
    steps=(
        Step("goto", value="http://webmail.test/inbox"),
        Step("wait", seconds=1.0),
        Step("goto", value="http://crm-demo.test/contacts"),
        Step("wait", seconds=1.0),
        Step("scroll", seconds=1.0),
        Step("click", selector="tr.contact-row:first-child"),
        Step("wait", seconds=2.0),
    ),
)

IDLE = Scenario(
    name="idle-background",
    description=(
        "Open one blank page and do nothing. Isolates MV3 service-worker activity that "
        "needs no user and no active page (Karami, NDSS 2021)."
    ),
    pages=("http://blank.test/",),
    steps=(Step("goto", value="http://blank.test/"), Step("wait", seconds=10.0)),
    settle_seconds=10.0,
)

SCENARIOS = {s.name: s for s in (BANK_LOGIN, CONTACTS, IDLE)}


def get(name: str) -> Scenario:
    """Look up a scenario by name, with a helpful error listing the valid ones."""
    try:
        return SCENARIOS[name]
    except KeyError:
        raise KeyError(f"unknown scenario {name!r}; available: {', '.join(sorted(SCENARIOS))}")
