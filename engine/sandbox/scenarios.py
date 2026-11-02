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
    """One action in a scenario. ``action`` is goto/fill/click/wait/scroll/fire_events.

    ``fire_events`` is Hulk-style event-handler fuzzing (Kapravelos USENIX'14): it
    dispatches a battery of synthetic DOM events across the page's elements so dormant
    handlers (a payload's ``submit``/``input`` listener, an extension's lazy hooks) fire
    without a real navigation that would race the trace.
    """

    action: str
    selector: str | None = None
    value: str | None = None
    seconds: float = 0.0


#: The event-fuzzing script run by a ``fire_events`` step. Kept here (not in the engines) so
#: both capture engines fire the identical events, preserving determinism across v1 and v2.
EVENT_FUZZING_JS = """
(() => {
  const types = ['focus','input','change','keydown','keyup','keypress','click',
                 'mousedown','mouseup','blur'];
  // Handlers must run, but no default action: a synthetic click submits a form in Firefox (not in
  // Chromium), and that navigation would abort whatever the extension had in flight. Registered
  // on window, so this runs after every handler on the path has already seen the event.
  const noDefault = (e) => e.preventDefault();
  window.addEventListener('click', noDefault);
  window.addEventListener('submit', noDefault);
  const nodes = document.querySelectorAll('input,textarea,select,button,a,form,body,div,span');
  nodes.forEach((el) => types.forEach((t) => {
    try { el.dispatchEvent(new Event(t, { bubbles: true, cancelable: true })); } catch (e) {}
  }));
  // Fire submit on every form explicitly (it does not navigate — it only runs handlers).
  document.querySelectorAll('form').forEach((f) => {
    try { f.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); } catch (e) {}
  });
  window.removeEventListener('click', noDefault);
  window.removeEventListener('submit', noDefault);
})();
"""


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

HONEYPAGE = Scenario(
    name="honeypage-harvest",
    description=(
        "A Hulk-style HoneyPage (Kapravelos USENIX'14): one page dense with credential, "
        "card and contact fields plus a session cookie, where the fields are filled, "
        "event-handler fuzzing fires dormant handlers, and the page is dwelt on long "
        "enough for delayed beacons — so a data-stealing payload is elicited, not waited "
        "for. This closes the trigger-dependent recall gap the bank scenario leaves."
    ),
    pages=("http://honeypage.test/harvest",),
    steps=(
        Step("goto", value="http://honeypage.test/harvest"),
        Step("wait", seconds=1.0),
        Step("fill", selector="input[name=username]", value=DUMMY_USERNAME),
        Step("fill", selector="input#password", value=DUMMY_PASSWORD),
        Step("fill", selector="input[name=cardnumber]", value="4111 1111 1111 1111"),
        Step("fill", selector="input[name=cvv]", value="123"),
        Step("fire_events"),                # trigger dormant submit/input handlers
        Step("wait", seconds=3.5),          # let setTimeout-delayed payloads (e.g. 2.5s) fire
        Step("scroll", seconds=0.5),
        Step("fire_events"),                # second volley after any late DOM setup
        Step("wait", seconds=2.0),
    ),
    settle_seconds=6.0,
)

#: Seconds between keystrokes for a ``fill`` step that types for real. ``Step.seconds`` on a fill
#: selects keystroke-by-keystroke entry, so key-listening code sees genuine key events.
KEYSTROKE_DELAY = 0.01

GENERAL_BROWSING = Scenario(
    name="general-browsing",
    description="Read ordinary pages and follow links, a redirect and a search form. This is "
                "the control for behaviour that has nothing to do with sensitive pages.",
    pages=("http://daily-news.test/", "http://daily-news.test/article/2"),
    steps=(
        Step("goto", value="http://daily-news.test/"),
        Step("wait", seconds=1.0),
        Step("scroll", seconds=0.5),
        Step("fill", selector="input[name=q]", value="park", seconds=KEYSTROKE_DELAY),
        Step("click", selector="a#redirect"),
        Step("wait", seconds=1.0),
        Step("click", selector="a#home"),
        Step("wait", seconds=1.0),
    ),
    settle_seconds=2.0,
)

FINANCIAL_PORTAL = Scenario(
    name="financial-portal-login",
    description="Sign in to a synthetic bank over HTTPS and open the accounts and transfer pages. "
                "Offers a password, a one-time code, session cookies and an account number.",
    pages=("https://secure-bank.test/login", "https://secure-bank.test/session",
           "https://secure-bank.test/transfer"),
    steps=(
        Step("goto", value="https://secure-bank.test/login"),
        Step("wait", seconds=1.0),
        Step("fill", selector="input[name=username]", value="xdrft.customer.7731",
             seconds=KEYSTROKE_DELAY),
        Step("fill", selector="input#password", value="XDRFT-Bank-Pw-7f3a91c2",
             seconds=KEYSTROKE_DELAY),
        Step("fill", selector="input[name=otp]", value="XDRFT-OTP-581204",
             seconds=KEYSTROKE_DELAY),
        Step("fire_events"),
        Step("wait", seconds=2.8),
        Step("click", selector="button#signin"),
        Step("wait", seconds=1.5),
        Step("scroll", seconds=0.3),
        Step("click", selector="a#transfer"),
        Step("wait", seconds=1.0),
        Step("fill", selector="input[name=destination_account]", value="XDRFT00112233445566"),
        Step("fire_events"),
        Step("wait", seconds=1.0),
    ),
    settle_seconds=3.0,
)

WEBMAIL_LOGIN = Scenario(
    name="webmail-login",
    description="Sign in to a synthetic webmail portal and read the inbox.",
    pages=("https://mail-portal.test/login", "https://mail-portal.test/inbox"),
    steps=(
        Step("goto", value="https://mail-portal.test/login"),
        Step("wait", seconds=1.0),
        Step("fill", selector="input[name=email]", value=DUMMY_USERNAME, seconds=KEYSTROKE_DELAY),
        Step("fill", selector="input#password", value="XDRFT-Mail-Pw-1b8e44d0",
             seconds=KEYSTROKE_DELAY),
        Step("wait", seconds=2.8),
        Step("click", selector="button#signin"),
        Step("wait", seconds=1.5),
        Step("click", selector="li.message:first-child"),
        Step("wait", seconds=1.0),
    ),
    settle_seconds=2.0,
)

CHECKOUT_FORM = Scenario(
    name="checkout-form",
    description="Complete a payment form. Card fields use browser autocomplete tokens and a "
                "password-type CVV, and a hidden merchant key is present.",
    pages=("http://shop-checkout.test/checkout",),
    steps=(
        Step("goto", value="http://shop-checkout.test/checkout"),
        Step("wait", seconds=1.0),
        Step("fill", selector="input[name=cardname]", value="Xdrft Testperson"),
        Step("fill", selector="input[name=cardnumber]", value="4111 1111 1111 1111",
             seconds=KEYSTROKE_DELAY),
        Step("fill", selector="input[name=exp]", value="12/34"),
        Step("fill", selector="input[name=cvv]", value="739", seconds=KEYSTROKE_DELAY),
        Step("fire_events"),
        Step("wait", seconds=2.8),
        Step("click", selector="button#pay"),
        Step("wait", seconds=1.0),
    ),
    settle_seconds=2.0,
)

SENSITIVE_PROFILE = Scenario(
    name="sensitive-profile",
    description="Open a page displaying synthetic personal data and hidden tokens, for code that "
                "scrapes page text rather than form inputs.",
    pages=("http://profile-demo.test/account",),
    steps=(
        Step("goto", value="http://profile-demo.test/account"),
        Step("wait", seconds=1.0),
        Step("fill", selector="input[name=phone]", value="+1-555-0100-417"),
        Step("click", selector="button#save"),
        Step("fire_events"),
        Step("wait", seconds=2.8),
    ),
    settle_seconds=2.0,
)

INTERACTIVE_DOM = Scenario(
    name="interactive-dom",
    description="Click controls that create elements after load, including a login form that "
                "only exists once a button is pressed, to reach observers of dynamic content.",
    pages=("http://app-widgets.test/dashboard",),
    steps=(
        Step("goto", value="http://app-widgets.test/dashboard"),
        Step("wait", seconds=0.5),
        Step("click", selector="button#add-row"),
        Step("click", selector="button#add-row"),
        Step("click", selector="button#open-login"),
        Step("wait", seconds=0.5),
        Step("fill", selector="input#late-user", value="xdrft.customer.7731"),
        Step("fill", selector="input#late-password", value=DUMMY_PASSWORD, seconds=KEYSTROKE_DELAY),
        Step("fire_events"),
        Step("wait", seconds=2.8),
    ),
    settle_seconds=2.0,
)

SCENARIOS = {s.name: s for s in (BANK_LOGIN, CONTACTS, IDLE, HONEYPAGE, GENERAL_BROWSING,
                                 FINANCIAL_PORTAL, WEBMAIL_LOGIN, CHECKOUT_FORM,
                                 SENSITIVE_PROFILE, INTERACTIVE_DOM)}

#: Default order for the Docker pipeline: controls first, then the credential-bearing pages.
DEFAULT_SUITE = ("general-browsing", "honeypage-harvest", "financial-portal-login",
                 "webmail-login", "checkout-form", "sensitive-profile", "interactive-dom",
                 "idle-background")


def targeted_scenario(hosts: list[str]) -> Scenario:
    """Visit hostnames an extension names in its manifest, each serving a synthetic login page.

    Payloads are commonly gated on specific domains, which a generic bank page would never
    trigger. The caller passes the union of both versions' hosts so the two runs stay identical.
    """
    steps: list[Step] = []
    pages = []
    for host in hosts:
        url = f"https://{host}/"
        pages.append(url)
        steps += [
            Step("goto", value=url),
            Step("wait", seconds=0.5),
            Step("fill", selector="input[name=username]", value="xdrft.customer.7731"),
            Step("fill", selector="input#password", value=DUMMY_PASSWORD, seconds=KEYSTROKE_DELAY),
            Step("fire_events"),
            Step("wait", seconds=2.8),
        ]
    return Scenario(
        name="manifest-targeted",
        description="Synthetic login pages served for hostnames named in the extension's manifest.",
        pages=tuple(pages),
        steps=tuple(steps),
        settle_seconds=1.0,
    )


def replay_scenario(urls: list[str]) -> Scenario:
    """Browse the pages of a recorded replay bundle."""
    steps: list[Step] = []
    for url in urls:
        steps += [Step("goto", value=url), Step("wait", seconds=1.0), Step("scroll", seconds=0.5),
                  Step("fire_events"), Step("wait", seconds=1.0)]
    return Scenario(name="replay-browse", description="Browse the pages of a recorded bundle.",
                    pages=tuple(urls), steps=tuple(steps), settle_seconds=2.0)


def get(name: str) -> Scenario:
    """Look up a scenario by name, with a helpful error listing the valid ones."""
    try:
        return SCENARIOS[name]
    except KeyError:
        raise KeyError(f"unknown scenario {name!r}; available: {', '.join(sorted(SCENARIOS))}")
