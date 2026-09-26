# elagoht/honeypot

A collage plugin that stops form spam without a CAPTCHA: a decoy field people
never see and bots fill in, and a signed timestamp that refuses a form sent back
sooner than a person could have filled it in. It supplies the mechanism; each form
says where with `{{honeypot}}`.

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

Requires collage v0.24.0 or later. Register it in `Config.Plugins`: it adds a
template function, which only a plugin registered there can.

## What is refused

Every `POST`, `PUT`, `PATCH` and `DELETE` with a form body —
`application/x-www-form-urlencoded` or `multipart/form-data` — to a protected path
is checked before it reaches the action, and refused when:

- the decoy field was filled in;
- it carries no timestamp, or one the site did not sign;
- it came back sooner than `MinDelay` seconds after the page was served (default
  2) — a bot posts at once, a person reads first;
- the page was served more than `MaxAge` seconds ago (default one day).

Any other body — a JSON API, a `fetch` sending JSON — passes unchecked, and so
does every `GET`.

**Every form posted to a protected path must carry `{{honeypot}}`**, or it is
refused for want of a timestamp. `Protect` narrows the paths — `["/contact",
"/comments"]` — and `Skip` excludes some, by default collage's own `/_collage/`.
collage redirects a path with dot segments to its clean spelling before any
middleware runs, so `/_collage/../contact` arrives as `/contact` and is checked.
The plugin does not rely on that alone: a path is skipped only when it has no dot
segments.

A refusal is `400 Bad Request` with a one-line text body telling a person to wait
a moment and send the form again. With `Silent` it is instead a `303 See Other`
back to the page the form was on — the `Referer`, when it is on this site, and `/`
otherwise — which is what an accepted form answers, so a bot believes it succeeded
and does not try something cleverer.

The body is read before routing, so it is read into memory and put back: collage's
forgery check and the action read the request exactly as it arrived. `MaxBody`
bounds what is read, by default 4 MiB, collage's own default limit on an action's
body; a larger form body is refused with `413`. Raise it for a form that uploads
large files.

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
On the way out the plugin's middleware signs the current time with HMAC-SHA256 and
puts it in the placeholder's place — the way collage puts each reader's forgery
token into a cached form. The placeholder is derived from the key, so a page cached
by one process is recognised by the next, and nobody without the key can plant it
in text a visitor wrote.

A page given a timestamp is sent with `Cache-Control: private, no-cache` and no
`ETag` (or `no-store`, when collage already said so): a browser cannot have an old
copy confirmed by a `304`, and a CDN cannot hand one reader's time to everyone.
Only HTML is held back to do this; an event stream, an image, a JSON document pass
straight through.

A static build has no middleware to stand in for the placeholder, so there
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
    "minDelay": 2,
    "maxAge": 86400,
    "silent": false,
    "protect": ["/"],
    "skip": ["/_collage/"],
    "maxBody": 4194304
  }
}
```

`minDelay` is seconds and may be fractional; `-1` turns the check off. A key that
is short or not hex, a field that is not a plain name, a `minDelay` not shorter
than `maxAge`, a prefix without a leading `/` — each stops the application from
starting.

## Limitations

- **It stops careless bots, not a determined one.** A script that fetches the
  page, waits two seconds and posts the fields it found passes, and one timestamp
  serves it for `MaxAge`. Pair it with
  [elagoht/ratelimit](https://github.com/Elagoht/collage-ratelimit), and with
  moderation for what matters.
- A person who submits within `MinDelay` — a form filled by the browser's autofill
  and sent at once — is refused. The message asks them to wait and send it again;
  with `Silent` they are sent back to the form with no message at all, so keep
  `Silent` for forms where that is acceptable.
- A browser extension or assistive tool that fills every field it finds, hidden or
  not, fills the decoy.
- A form built by JavaScript must include both fields: `new FormData(form)` does,
  a hand-built body does not.
- Every HTML response is held in memory until it is complete, to find the
  placeholder, so an HTML response cannot be streamed while the plugin is
  registered.

## Changes

### v0.1.2

- `collage.json`: the plugin described to editors — its template functions,
  snippets and configuration schema — for the Collage Snippets & Highlighter
  extension and any tool reading it.

### v0.1.1

- README: collage v0.24.0 cleans paths before middleware; the plugin keeps skipping only clean paths as a second line.
- Requires collage v0.24.0.
