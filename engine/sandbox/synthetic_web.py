"""The controlled synthetic web: login portals, forms, sensitive pages and interactive pages.

Everything here is fake and fixed. Pages contain no timestamps, no randomness and no calls to
``Date`` or ``Math.random``, so the bytes both extension versions receive are identical. Secret
values come from :mod:`engine.sandbox.markers`, so a value leaving the browser can be recognised.

The hosts use the reserved ``.test`` TLD. Some pages use HTTPS on purpose, so the capture is
exercised through TLS interception rather than only over plain HTTP.
"""

from __future__ import annotations

from engine.sandbox.markers import MARKERS_BY_ID as M


def _v(marker_id: str) -> str:
    return M[marker_id].value


_NEWS_ARTICLE = """<!doctype html>
<html><head><title>Daily News</title><script src="/assets/site.js"></script></head>
<body>
  <nav><a id="next" href="/article/2">Next story</a> <a id="redirect" href="/go/partner">Partner</a></nav>
  <article class="main"><h1>City council approves new park</h1>
    <p class="text">The council voted on Tuesday to convert the old rail yard into a public park.</p>
    <p class="text">Residents will be able to comment on the design at a meeting next month.</p>
  </article>
  <div class="ad-slot"><img src="http://pixel.ads-partner.test/p.gif" alt="ad"></div>
  <form id="search" method="get" action="/search"><input name="q" type="search">
    <button type="submit">Search</button></form>
</body></html>"""

_NEWS_ARTICLE_2 = """<!doctype html>
<html><head><title>Daily News - Weather</title></head>
<body><article class="main"><h1>Rain expected this weekend</h1>
<p class="text">Forecasters expect light rain on Saturday.</p></article>
<a id="home" href="/">Home</a></body></html>"""

_NEWS_SITE_JS = """fetch('/api/headlines').then(function (r) { return r.json(); }).then(function (d) {
  var ul = document.createElement('ul'); ul.id = 'headlines';
  d.items.forEach(function (t) { var li = document.createElement('li'); li.textContent = t; ul.appendChild(li); });
  document.body.appendChild(ul);
});"""

_BANK_LOGIN = f"""<!doctype html>
<html><head><title>Secure Bank - Sign in</title></head>
<body>
  <h1>Secure Bank</h1>
  <form id="login" method="post" action="/session">
    <input type="hidden" name="csrf_token" value="{_v('csrf_token')}">
    <label>Customer ID <input name="username" type="text" autocomplete="username"></label>
    <label>Password <input id="password" name="password" type="password"
                           autocomplete="current-password"></label>
    <label>One-time code <input name="otp" type="text" autocomplete="one-time-code"></label>
    <button id="signin" type="submit">Sign in</button>
  </form>
  <script>localStorage.setItem('auth_token', '{_v('auth_token')}');
  sessionStorage.setItem('session_id', '{_v('bank_session')}');</script>
</body></html>"""

_BANK_ACCOUNTS = f"""<!doctype html>
<html><head><title>Secure Bank - Accounts</title></head>
<body>
  <h1>Your accounts</h1>
  <table id="accounts"><tr class="account-row">
    <td class="account-number" data-sensitive="account">{_v('bank_account')}</td>
    <td class="balance" data-sensitive="balance">1,234.56</td></tr></table>
  <a id="transfer" href="/transfer">Make a transfer</a>
</body></html>"""

_BANK_TRANSFER = """<!doctype html>
<html><head><title>Secure Bank - Transfer</title></head>
<body><form id="transfer-form" method="post" action="/transfer">
  <label>To account <input name="destination_account" type="text"></label>
  <label>Amount <input name="amount" type="number"></label>
  <button id="send" type="submit">Send</button></form></body></html>"""

_MAIL_LOGIN = """<!doctype html>
<html><head><title>Mail Portal - Sign in</title></head>
<body><h1>Mail Portal</h1>
  <form id="login" method="post" action="/inbox">
    <label>Email <input name="email" type="email" autocomplete="email"></label>
    <label>Password <input id="password" name="password" type="password"></label>
    <button id="signin" type="submit">Sign in</button>
  </form></body></html>"""

_MAIL_INBOX = """<!doctype html>
<html><head><title>Mail Portal - Inbox</title></head>
<body><h1>Inbox</h1>
  <ul id="messages">
    <li class="message"><span class="contact-email">alex@example.test</span>
      <div class="message-body">Quarterly report attached.</div></li>
    <li class="message"><span class="contact-email">sam@example.test</span>
      <div class="message-body">Lunch on Friday?</div></li>
  </ul>
  <form id="compose"><textarea name="body"></textarea><button type="button" id="send">Send</button></form>
</body></html>"""

_CHECKOUT = f"""<!doctype html>
<html><head><title>Checkout</title></head>
<body><h1>Checkout</h1><div class="cart"><span class="price">$42.00</span></div>
  <form id="payment" method="post" action="/pay">
    <input type="hidden" name="merchant_key" value="{_v('api_key')}">
    <label>Name <input name="cardname" type="text" autocomplete="cc-name"></label>
    <label>Card <input name="cardnumber" type="text" autocomplete="cc-number"></label>
    <label>Expiry <input name="exp" type="text" autocomplete="cc-exp"></label>
    <label>CVV <input name="cvv" type="password" autocomplete="cc-csc"></label>
    <label>Address <input name="address" type="text" autocomplete="street-address"></label>
    <button id="pay" type="submit">Pay</button>
  </form></body></html>"""

_PROFILE = f"""<!doctype html>
<html><head><title>Account profile</title></head>
<body><h1>Your profile</h1>
  <dl id="profile">
    <dt>Name</dt><dd class="full-name" data-sensitive="name">{_v('full_name')}</dd>
    <dt>Phone</dt><dd class="phone" data-sensitive="phone">{_v('phone')}</dd>
    <dt>National ID</dt><dd class="ssn" data-sensitive="ssn">{_v('ssn')}</dd>
  </dl>
  <form id="edit"><input type="hidden" name="api_key" value="{_v('api_key')}">
    <label>Phone <input name="phone" type="tel" autocomplete="tel"></label>
    <button id="save" type="button">Save</button></form>
  <script>sessionStorage.setItem('api_key', '{_v('api_key')}');</script>
</body></html>"""

_DASHBOARD = """<!doctype html>
<html><head><title>Widgets</title></head>
<body><h1>Dashboard</h1>
  <button id="add-row">Add row</button>
  <button id="open-login">Sign in to continue</button>
  <div id="rows" contenteditable="true"></div>
  <div id="modal"></div>
  <script>
  document.getElementById('add-row').addEventListener('click', function () {
    var d = document.createElement('div'); d.className = 'row'; d.textContent = 'row';
    document.getElementById('rows').appendChild(d);
  });
  document.getElementById('open-login').addEventListener('click', function () {
    document.getElementById('modal').innerHTML =
      '<form id="late-login"><input id="late-user" name="username" type="text">' +
      '<input id="late-password" name="password" type="password">' +
      '<button id="late-submit" type="button">Go</button></form>';
  });
  </script>
</body></html>"""

#: A neutral page served for hosts an extension declares in its manifest, so that behaviour gated on
#: a specific hostname can trigger. It deliberately carries no branding: it never reaches a real
#: user because the network it is served on has no route out, and it only has to look like a login.
TARGETED_PAGE = """<!doctype html>
<html><head><title>Sign in</title></head>
<body><h1>Sign in</h1>
  <form id="login" method="post" action="/login">
    <label>Username <input name="username" type="text" autocomplete="username"></label>
    <label>Password <input id="password" name="password" type="password"></label>
    <button id="signin" type="submit">Sign in</button>
  </form>
  <p class="notice">Synthetic page served by the extdrift analysis sandbox.</p>
</body></html>"""


EXTENDED_SITE: dict[str, dict[str, tuple[str, str]]] = {
    "daily-news.test": {
        "/": ("text/html", _NEWS_ARTICLE),
        "/article/2": ("text/html", _NEWS_ARTICLE_2),
        "/search": ("text/html", _NEWS_ARTICLE_2),
        "/assets/site.js": ("text/javascript", _NEWS_SITE_JS),
        "/api/headlines": ("application/json", '{"items":["Local team wins","Road works end"]}'),
    },
    "pixel.ads-partner.test": {
        "/p.gif": ("image/gif", "GIF89a"),
    },
    "secure-bank.test": {
        "/login": ("text/html", _BANK_LOGIN),
        "/session": ("text/html", _BANK_ACCOUNTS),
        "/transfer": ("text/html", _BANK_TRANSFER),
    },
    "mail-portal.test": {
        "/login": ("text/html", _MAIL_LOGIN),
        "/inbox": ("text/html", _MAIL_INBOX),
    },
    "shop-checkout.test": {
        "/checkout": ("text/html", _CHECKOUT),
        "/pay": ("text/html", "<!doctype html><html><body><h1>Thank you</h1></body></html>"),
    },
    "profile-demo.test": {
        "/account": ("text/html", _PROFILE),
    },
    "app-widgets.test": {
        "/dashboard": ("text/html", _DASHBOARD),
    },
    "blank.test": {
        "/": ("text/html", "<!doctype html><html><head><title>Blank</title></head><body></body></html>"),
    },
}

#: Host -> Set-Cookie headers. HttpOnly cookies are reachable only through the cookies API, so
#: they separate ``document.cookie`` scraping from privileged jar access.
SET_COOKIES: dict[str, tuple[str, ...]] = {
    "demo-bank.test": ("session=demo-session-token-abc123; Path=/",),
    "honeypage.test": ("session=demo-session-token-abc123; Path=/",),
    "secure-bank.test": (
        f"bank_session={_v('bank_session')}; Path=/; Secure; HttpOnly",
        f"auth_token={_v('auth_token')}; Path=/; Secure",
    ),
    "mail-portal.test": (f"mail_session={_v('mail_session')}; Path=/; Secure",),
}

#: (host, path) -> redirect target. Exercises redirect capture.
REDIRECTS: dict[tuple[str, str], str] = {
    ("daily-news.test", "/go/partner"): "http://daily-news.test/article/2",
}
