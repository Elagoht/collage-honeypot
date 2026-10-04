# elagoht/honeypot

A collage plugin that stops form spam without a CAPTCHA: a decoy field people
never see and bots fill in, and a signed timestamp that refuses a form that was
never served, was served too long ago, or — when the form asks — came back too
soon. It supplies the mechanism; each form says where with `{{honeypot}}`, and
nothing in the configuration has to name the forms.

```go
app, err := collage.New(&collage.Config{
	Plugins: []collage.Plugin{honeypot.New(honeypot.Options{Key: key})},
})
```

```html
<form method="post" action="/contact">
  {{csrfToken}}
  {{honeypot}}
  <textarea name="message"></textarea>
  <button>Send</button>
</form>
```

Requires collage v0.43.0 or later. Register it in `Config.Plugins`: it adds a
template function, which only a plugin registered there can.

## What is refused

Every `POST`, `PUT`, `PATCH` and `DELETE` with a form body —
`application/x-www-form-urlencoded` or `multipart/form-data` — to an action on a
protected path is checked before the action's handler runs, and refused when:

- the decoy field was filled in;
- it carries no timestamp, or one the site did not sign;
- the page was served more than `MaxAge` seconds ago (default one day);
- it came back sooner than the form's delay after the page was served, when there
  is one: see [The delay](#the-delay).

Any other body — a JSON API, a `fetch` sending JSON — passes unchecked, and so
does every `GET`.

## Which paths are protected

The forms say. Every form the plugin stamps names the path it posts to — its
`action`, resolved against the page's URL, or the page's own path when it has
none — and from then on a form body posted to that path must carry the fields. A
form without `{{honeypot}}` is never checked, so a sign-up form can go without
while the login form beside it is protected, and nothing in the configuration
names either.

What a process has learned it keeps in memory, up to 4096 paths. **Until a page
with the form has gone out, its path is not checked**: after a restart or a new
release, or on an instance that has not served it yet, a bot that posts straight
to the path without fetching the form first gets through, until the first reader
fetches it. `Protect` closes that gap for the paths that matter: its prefixes are
checked from the first request, and every form posted under them must carry
`{{honeypot}}`. `["/"]` checks every form the site accepts.

`Skip` excludes prefixes from both, by default collage's own `/_collage/`.
collage redirects a path with dot segments to its clean spelling before any
middleware runs, so `/_collage/../contact` arrives as `/contact` and is checked.
The plugin does not rely on that alone: a path is skipped only when it has no dot
segments.

A form whose button carries its own `formaction` is learned by the form's
`action`, not the button's; name such a path in `Protect`.

## The delay

By default a form may be sent back at once. A delay catches a script that fetches
the form and posts it back in the same breath, but a person with the browser's
autofill and Enter is fast too, and a script that knows the delay only has to wait
it out. A form that wants one asks for it in seconds:

```html
{{honeypot 0.3}}
```

The delay is signed into the timestamp, so a bot cannot shorten it by editing the
field. `MinDelay` sets one for every form that does not choose its own;
`{{honeypot 0}}` turns it off for one form, a logout button say, whatever
`MinDelay` is.

A refusal is `400 Bad Request` with a one-line text body telling a person to wait
a moment and send the form again. With `Silent` it is instead a `303 See Other`
back to the page the form was on — the `Referer`, when it is on this site, and `/`
otherwise — which is what an accepted form answers, so a bot believes it succeeded
and does not try something cleverer.

The plugin has no say in how large a submission may be. It checks the form in
collage's `BeforeActionHook`, after the page's guards, the action's body limit and
the forgery check, and reads it through that limit: a form that uploads large
files needs only the action's `WithMaxBodyBytes`, and a body past it is the
action's own `413`. The form is parsed once, and the handler finds it parsed.

Only collage actions are checked. A form posted to a handler mounted with
`app.Handle` is not, whatever `Protect` says.

## The decoy

```html
<div class="collage-hp" aria-hidden="true" inert style="position:absolute;left:-10000px;…">
  <label>Website <input type="text" name="website" tabindex="-1" autocomplete="off" …></label>
</div>
```

It is moved off-screen rather than hidden with `display:none`, which a bot reads as
"leave this alone". `aria-hidden` and `inert` keep it from screen readers,
`tabindex="-1"` keeps it out of the keyboard's way, and `autocomplete="off"` with
the password managers' own opt-outs keeps a browser from filling it in for a
person. `Field` renames it; the default, `website`, is one a bot is keen to fill.

**A strict Content-Security-Policy** — `style-src` without `'unsafe-inline'`, as
[elagoht/secure](https://github.com/Elagoht/collage-secure) can send — blocks the
inline style, and the decoy then shows. Give the class the same rules in your
stylesheet:

```css
.collage-hp { position: absolute; left: -10000px; top: auto; width: 1px; height: 1px; overflow: hidden; }
```

## The timestamp and the page cache

A page with a form is usually cached, and a time rendered into it would be the
time the cache was filled, handed to every reader. So `{{honeypot}}` renders a
placeholder where the timestamp goes, and the cached page carries the placeholder.
On the way out the plugin signs the current time with HMAC-SHA256 and
puts it in the placeholder's place — the way collage puts each reader's forgery
token into a cached form. The placeholder is derived from the key, so a page cached
by one process is recognised by the next, and nobody without the key can plant it
in text a visitor wrote.

This is collage's `PersonaliseHook` (collage v0.43.0, which the plugin now
requires): it runs after the page cache and inside every middleware, so before a
compressor sees the body, and where the plugin is listed in `Config.Plugins` does
not matter. A page given a timestamp is marked personal: collage answers it
`private, no-store`, takes its `ETag` from the body sent, and never answers it
`304`, so a browser cannot have an old copy confirmed and a CDN cannot hand one
reader's time to everyone.

A static build has no request to stand in for the placeholder, so there
`{{honeypot}}` renders the decoy without a timestamp.

## The key

Set a key of at least 32 random bytes, the same on every instance and across
restarts — `openssl rand -hex 32` makes one:

```json
{ "elagoht/honeypot": { "key": "9f2c…" } }
```

Without one, a key is generated per process and a warning logged: a form served
before a restart, or by another instance, is refused — and so is every form in a
page a disk cache kept from an earlier process, since its placeholder no longer
matches.

## Configuration

```json
{
  "elagoht/honeypot": {
    "key": "hex-encoded, 32 bytes or more",
    "field": "website",
    "minDelay": 0,
    "maxAge": 86400,
    "silent": false,
    "protect": [],
    "skip": ["/_collage/"]
  }
}
```

`minDelay` is seconds and may be fractional; `0`, the default, turns the check
off, as `-1` did before v0.2.0 and still does. A key that is short or not hex, a
field that is not a plain name, a `minDelay` not shorter than `maxAge`, a prefix
without a leading `/` — each stops the application from starting. A delay
`{{honeypot}}` cannot keep, negative or not shorter than `maxAge`, fails the
render.

## Limitations

- **It stops careless bots, not a determined one.** A script that fetches the
  page, waits out any delay and posts the fields it found passes, and one
  timestamp serves it for `MaxAge`. Pair it with
  [elagoht/ratelimit](https://github.com/Elagoht/collage-ratelimit), and with
  moderation for what matters.
- With a delay, a person who submits within it — a form filled by the browser's
  autofill and sent at once — is refused. The message asks them to wait and send
  it again; with `Silent` they are sent back to the form with no message at all,
  so keep `Silent` for forms where that is acceptable.
- A browser extension or assistive tool that fills every field it finds, hidden or
  not, fills the decoy.
- A form built by JavaScript must include both fields: `new FormData(form)` does,
  a hand-built body does not.
- Only what collage renders is stamped: a page, a fragment, an action's HTML
  answer, an error page. A placeholder a hand-written `app.Handle` handler writes
  itself goes out as it is.

## Changes

### v0.4.0

- **Fix: listed before elagoht/compress, every real submission was refused.** The
  plugin's middleware held the response to replace the placeholder, and with a
  compressor inside it what it held was gzip bytes: the placeholder was never
  replaced and the timestamp was "not one the site signed". The timestamp now goes
  in through collage's `PersonaliseHook`, after the page cache and before any
  middleware compresses the body, so the order of `Config.Plugins` no longer
  matters. The middleware is gone, and with it the buffering: an HTML response is
  no longer held in memory.
- A page with a timestamp is answered `private, no-store`, its `ETag` from the
  body sent and never `304`, as collage answers any personal page.
- A placeholder a hand-written `app.Handle` handler writes is no longer stamped.
- Requires collage v0.43.0.

### v0.3.0

- **The body is the action's to bound.** The plugin checks a submission in
  collage's `BeforeActionHook` (collage v0.31.0), through the action's own body
  limit, instead of reading it before routing through a limit of its own.
  `MaxBody` is gone: a form that uploads large files needs only the action's
  `WithMaxBodyBytes`. The form is parsed once, for the plugin and the handler.
- The forgery check now runs before the plugin's, so a forged submission is
  collage's `403`.
- Only collage actions are checked; a form posted to an `app.Handle` handler is
  not.
- Requires collage v0.31.0.

### v0.2.0

- **The forms say which paths are protected.** A path is checked once a page with
  a `{{honeypot}}` form posting to it has been served; a form without
  `{{honeypot}}` is never checked. `Protect` no longer defaults to `["/"]`: its
  prefixes are checked from the first request, and `["/"]` restores the old
  behaviour.
- **No delay by default.** `MinDelay` defaults to `0`, off; `-1` still turns it
  off. `{{honeypot seconds}}` gives one form its own delay, signed into the
  timestamp.
- A timestamp now carries its form's delay. One served by v0.1, open in a tab
  across the upgrade, is still accepted.

### v0.1.3

- A response that writes HTML without a `Content-Type` — a handler mounted with
  `app.Handle` writing `RenderPath` output, say — has its placeholder stamped.
  The type is sniffed from the first bytes, as net/http does; before, such a
  response went out with the placeholder, and its form was refused.

### v0.1.2

- `collage.json`: the plugin described to editors — its template functions,
  snippets and configuration schema — for the Collage Snippets & Highlighter
  extension and any tool reading it.

### v0.1.1

- README: collage v0.24.0 cleans paths before middleware; the plugin keeps skipping only clean paths as a second line.
- Requires collage v0.24.0.
