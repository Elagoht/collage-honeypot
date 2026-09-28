// Package honeypot is a collage plugin that stops form spam without a CAPTCHA:
// a decoy field people never see, and a signed timestamp that says how long the
// form was open.
//
//	app, err := collage.New(&collage.Config{
//		Plugins: []collage.Plugin{honeypot.New(honeypot.Options{Key: key})},
//	})
//
// and inside every form the site accepts:
//
//	<form method="post" action="/contact">
//		{{csrfField}}
//		{{honeypot}}
//		...
//	</form>
//
// A submission is refused when the decoy was filled in, when its timestamp is
// missing, forged or older than MaxAge, or, when a delay is asked for, when it came
// back sooner than that after the page was served. Only form bodies are checked; a
// JSON API passes.
//
// # Which submissions are checked
//
// A form that carries {{honeypot}} is what says its target is protected: every
// form the plugin stamps names the path it posts to, and from then on a form
// body posted there must carry the fields. A form without {{honeypot}} is never
// checked. Protect adds path prefixes that are checked whether or not a form
// naming them has been served yet — which is what closes the gap after a
// restart, or on another instance, before the first such page goes out.
//
// # The timestamp and the page cache
//
// A page with a form is usually cached, and a timestamp rendered into it would
// be the time the cache was filled, handed to every reader. So {{honeypot}}
// renders a placeholder where the timestamp goes, and the cached page carries the
// placeholder; the plugin's middleware signs the time the response leaves and
// puts it in the placeholder's place — the way collage itself puts each reader's
// forgery token into a cached form.
package honeypot

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Elagoht/collage/pkg/collage"
)

// Name is the plugin's name, and the key its configuration is found under.
const Name = "elagoht/honeypot"

// TimeField is the hidden field the signed timestamp travels in.
const TimeField = "_hpt"

// Options configures the plugin.
type Options struct {
	// Key signs the timestamp: at least 32 random bytes, the same on every
	// instance and across restarts. Unset, one is generated per process, and a
	// form served before a restart, or by another instance, is refused. In
	// configuration it is "key", hex-encoded.
	Key []byte `json:"-"`
	// KeyHex is Key, hex-encoded, as configuration carries it.
	KeyHex string `json:"key"`
	// Field is the decoy's name: something a bot is keen to fill in. Default
	// "website".
	Field string `json:"field"`
	// MinDelay is how many seconds a form must be open before it is sent, for a
	// form that does not choose its own with {{honeypot seconds}}. It catches a
	// script that fetches a form and posts it back at once. Default 0: off, since
	// a person with autofill and Enter is fast, and a script that knows the delay
	// only has to wait it out.
	MinDelay float64 `json:"minDelay"`
	// MaxAge is how many seconds a served form stays good for. Default 86400,
	// one day.
	MaxAge int `json:"maxAge"`
	// Silent answers a refused submission with 303 See Other to the page it came
	// from, as an accepted form is answered, so a bot believes it succeeded and
	// does not try another way. Default false: 400 Bad Request.
	Silent bool `json:"silent"`
	// Protect are path prefixes whose submissions are checked even before a form
	// naming them has been served. Default none: a path is checked once a page
	// with a {{honeypot}} form posting to it has gone out from this process.
	// ["/"] checks every form the site accepts, each of which must then carry
	// {{honeypot}}.
	Protect []string `json:"protect"`
	// Skip are path prefixes never checked, even under Protect. Default
	// ["/_collage/"].
	Skip []string `json:"skip"`
	// MaxBody is the largest body, in bytes, the plugin reads to check it; a
	// larger form body is refused with 413. Default 4 MiB, collage's own
	// default limit on an action's body. Raise it with an action's
	// WithMaxBodyBytes for a form that uploads large files.
	MaxBody int64 `json:"maxBody"`
}

var (
	_ collage.Plugin           = (*Plugin)(nil)
	_ collage.Configurer       = (*Plugin)(nil)
	_ collage.BeforeRenderHook = (*Plugin)(nil)
)

// Plugin checks submitted forms.
type Plugin struct {
	opts    Options
	log     *slog.Logger
	marker  string
	learned learned
}

// learnedLimit is how many paths are learned from forms before the plugin stops
// learning more: a form whose action carries an id, one path per record, would
// otherwise grow the set without end.
const learnedLimit = 4096

// learned are the paths the forms this process served post to.
type learned struct {
	mu    sync.RWMutex
	paths map[string]struct{}
	full  bool
}

func (l *learned) has(path string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	_, ok := l.paths[path]
	return ok
}

// add learns path, and reports whether the set had just filled up.
func (l *learned) add(path string) (filled bool) {
	l.mu.RLock()
	_, ok := l.paths[path]
	full := l.full
	l.mu.RUnlock()
	if ok || full {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.paths == nil {
		l.paths = map[string]struct{}{}
	}
	if len(l.paths) >= learnedLimit {
		if l.full {
			return false
		}
		l.full = true
		return true
	}
	l.paths[path] = struct{}{}
	return false
}

// New returns a plugin with opts as its starting point, which the application's
// own configuration is then decoded over.
func New(opts Options) *Plugin { return &Plugin{opts: opts} }

func (p *Plugin) Name() string                   { return Name }
func (p *Plugin) Version() string                { return "0.2.0" }
func (p *Plugin) Shutdown(context.Context) error { return nil }

var fieldName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)

// staticKey marks a render for a static build, which no middleware follows.
const staticKey = Name + ":static"

// Configure reads and checks the configuration and adds {{honeypot}}.
func (p *Plugin) Configure(_ context.Context, host collage.ConfigHost) error {
	if err := host.Config(&p.opts); err != nil {
		return err
	}
	p.log = host.Logger()
	o := &p.opts
	if o.KeyHex != "" {
		key, err := hex.DecodeString(o.KeyHex)
		if err != nil {
			return fmt.Errorf("honeypot: key: %w", err)
		}
		o.Key = key
	}
	if len(o.Key) == 0 {
		o.Key = make([]byte, 32)
		if _, err := rand.Read(o.Key); err != nil {
			return fmt.Errorf("honeypot: %w", err)
		}
		p.log.Warn("honeypot: no key set, so one was generated for this process; a form served before a restart, or by another instance, is refused")
	} else if len(o.Key) < 32 {
		return errors.New("honeypot: the key must be at least 32 bytes")
	}
	if o.Field == "" {
		o.Field = "website"
	}
	if !fieldName.MatchString(o.Field) || o.Field == TimeField {
		return fmt.Errorf("honeypot: field %q must be a plain name: letters, digits, - and _", o.Field)
	}
	// -1 was how the check was turned off before 0 was; it still is.
	switch {
	case o.MinDelay == -1:
		o.MinDelay = 0
	case o.MinDelay < 0:
		return errors.New("honeypot: minDelay is seconds, or 0 to turn the check off")
	}
	if o.MaxAge < 0 {
		return errors.New("honeypot: maxAge cannot be negative")
	}
	if o.MaxAge == 0 {
		o.MaxAge = 86400
	}
	if o.MinDelay > 0 && o.MinDelay >= float64(o.MaxAge) {
		return errors.New("honeypot: minDelay must be shorter than maxAge, or no form could be sent")
	}
	if o.MaxBody < 0 {
		return errors.New("honeypot: maxBody cannot be negative")
	}
	if o.MaxBody == 0 {
		o.MaxBody = 4 << 20
	}
	if o.Skip == nil {
		o.Skip = []string{"/_collage/"}
	}
	for _, prefix := range append(append([]string(nil), o.Protect...), o.Skip...) {
		if !strings.HasPrefix(prefix, "/") {
			return fmt.Errorf("honeypot: path prefix %q must begin with /", prefix)
		}
	}
	// Derived from the key rather than random, like collage's own forgery
	// marker: a page cached by one process is served by the next, which must
	// recognise the placeholder; and nobody without the key can plant it in
	// content a visitor wrote.
	p.marker = "collage-honeypot-" + hex.EncodeToString(p.mac("marker"))[:32]
	return host.AddRenderFunc("honeypot", func(rc *collage.RenderContext) any { // any: html/template.FuncMap's own value type
		return func(delay ...float64) (template.HTML, error) {
			ms := -1
			switch {
			case len(delay) > 1:
				return "", errors.New("honeypot: {{honeypot}} takes one delay in seconds, or none")
			case len(delay) == 1 && (delay[0] < 0 || delay[0] >= float64(p.opts.MaxAge)):
				return "", fmt.Errorf("honeypot: a delay of %g seconds: it must be 0 or more, and shorter than maxAge", delay[0])
			case len(delay) == 1:
				ms = int(delay[0] * 1000)
			}
			static, _ := collage.Get[bool](rc, staticKey)
			return p.fields(static, ms), nil
		}
	})
}

// Init wraps every request: submissions are checked, and forms served are
// given their timestamp.
func (p *Plugin) Init(_ context.Context, host collage.Host) error {
	if p.marker == "" {
		return errors.New("honeypot: register the plugin in Config.Plugins, where Configure runs; {{honeypot}} needs it")
	}
	return host.Use(p.middleware)
}

// OnBeforeRender marks a static build's render: no middleware will stand in for
// the placeholder, so {{honeypot}} leaves the timestamp out.
func (p *Plugin) OnBeforeRender(_ context.Context, ev *collage.BeforeRenderEvent) error {
	if ev.Static && ev.Context != nil {
		ev.Context.Set(staticKey, true)
	}
	return nil
}

// fields is what {{honeypot}} renders. delay is the form's own delay in
// milliseconds, or -1 for MinDelay; it rides in the placeholder, after a dash, for
// the middleware to sign into the timestamp.
//
// The decoy is moved off-screen rather than hidden with display:none, which a bot
// reads as "leave this alone". aria-hidden and inert keep it from a screen
// reader, tabindex=-1 keeps it out of the keyboard's way, and autocomplete=off
// and the password managers' own opt-outs keep a browser from filling it in for a
// person. The class is there for a site whose Content-Security-Policy blocks
// inline styles: give .collage-hp the same rules in a stylesheet.
func (p *Plugin) fields(static bool, delay int) template.HTML {
	decoy := `<div class="collage-hp" aria-hidden="true" inert style="position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden">` +
		`<label>Website <input type="text" name="` + p.opts.Field + `" value="" tabindex="-1" autocomplete="off" data-1p-ignore data-lpignore="true"></label></div>`
	if static {
		return template.HTML(decoy)
	}
	placeholder := p.marker
	if delay >= 0 {
		placeholder += "-" + strconv.Itoa(delay)
	}
	return template.HTML(decoy + `<input type="hidden" name="` + TimeField + `" value="` + placeholder + `">`)
}

func (p *Plugin) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.checks(r) {
			reason, status := p.inspect(r)
			if reason != "" {
				p.refuse(w, r, reason, status)
				return
			}
		}
		sw := &stampWriter{ResponseWriter: w, plugin: p, request: r, head: r.Method == http.MethodHead}
		next.ServeHTTP(sw, r)
		sw.finish()
	})
}

// checks reports whether r is a form submission the plugin checks.
func (p *Plugin) checks(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return false
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || (media != "application/x-www-form-urlencoded" && media != "multipart/form-data") {
		return false
	}
	// Skipped only when the path was clean already, so /_collage/../contact never
	// passes as a development endpoint. collage v0.24.0 redirects such a path
	// before any middleware runs; this stays as a second line, for a handler
	// that does not.
	clean := cleanPath(r.URL.Path)
	if clean == r.URL.Path {
		for _, prefix := range p.opts.Skip {
			if strings.HasPrefix(clean, prefix) {
				return false
			}
		}
	}
	for _, prefix := range p.opts.Protect {
		if strings.HasPrefix(clean, prefix) {
			return true
		}
	}
	return p.learned.has(clean)
}

func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	c := path.Clean(p)
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c
}

// inspect reads the submission and returns why it is refused, or "".
//
// The body is read here, before routing, so it is read into memory and put back
// for the action to read again: collage's forgery check and the action's own
// parsing see the request exactly as it arrived.
func (p *Plugin) inspect(r *http.Request) (string, int) {
	body, err := io.ReadAll(io.LimitReader(r.Body, p.opts.MaxBody+1))
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return "the body could not be read", http.StatusBadRequest
	}
	if int64(len(body)) > p.opts.MaxBody {
		return "the body is larger than maxBody", http.StatusRequestEntityTooLarge
	}
	form := r.Clone(r.Context())
	form.Body = io.NopCloser(bytes.NewReader(body))
	form.Form, form.PostForm, form.MultipartForm = nil, nil, nil
	if err := form.ParseMultipartForm(p.opts.MaxBody); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		return "the form could not be parsed", http.StatusBadRequest
	}
	if form.MultipartForm != nil {
		defer func() { _ = form.MultipartForm.RemoveAll() }()
	}
	if form.PostForm.Get(p.opts.Field) != "" {
		return "the decoy field was filled in", http.StatusBadRequest
	}
	stamp := form.PostForm.Get(TimeField)
	if stamp == "" {
		return "the form carried no timestamp", http.StatusBadRequest
	}
	served, delay, ok := p.verify(stamp)
	if !ok {
		return "the timestamp is not one the site signed", http.StatusBadRequest
	}
	age := time.Now().Sub(served)
	switch {
	case age < -time.Minute:
		return "the timestamp is in the future", http.StatusBadRequest
	case age < delay:
		return "the form was sent too soon after it was served", http.StatusBadRequest
	case age > time.Duration(p.opts.MaxAge)*time.Second:
		return "the form was served too long ago", http.StatusBadRequest
	}
	return "", 0
}

func (p *Plugin) refuse(w http.ResponseWriter, r *http.Request, reason string, status int) {
	p.log.Debug("honeypot: refused a submission", "path", r.URL.Path, "reason", reason)
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	if p.opts.Silent && status == http.StatusBadRequest {
		http.Redirect(w, r, back(r), http.StatusSeeOther)
		return
	}
	h.Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, "The form could not be accepted. If you filled it in yourself, go back, wait a moment and send it again.\n")
}

// back is where a silent refusal sends the client: the page the form was on, when
// the Referer names one on this site, and the home page otherwise. Never another
// site, so the redirect cannot be used to bounce anyone elsewhere.
func back(r *http.Request) string {
	ref, err := url.Parse(r.Referer())
	if err != nil || ref.Host != r.Host || !strings.HasPrefix(ref.Path, "/") || strings.HasPrefix(ref.Path, "//") || strings.Contains(ref.Path, "\\") {
		return "/"
	}
	if ref.RawQuery != "" {
		return ref.EscapedPath() + "?" + ref.RawQuery
	}
	return ref.EscapedPath()
}

// stamp signs t and the delay its form asks for: t's Unix time in milliseconds,
// a dot, the delay in milliseconds, a dot, and an HMAC of both. Signed, so a bot
// cannot shorten the delay by editing the field.
func (p *Plugin) stamp(t time.Time, delay int) string {
	ms := strconv.FormatInt(t.UnixMilli(), 10)
	d := strconv.Itoa(delay)
	return ms + "." + d + "." + base64.RawURLEncoding.EncodeToString(p.mac("ts:" + ms + ":" + d)[:18])
}

// verify returns when stamp was served and the delay its form asked for. A
// v0.1 stamp, time and signature alone, is still good, with MinDelay as its
// delay: a form open in a tab across the upgrade is not refused.
func (p *Plugin) verify(stamp string) (time.Time, time.Duration, bool) {
	parts := strings.Split(stamp, ".")
	var ms, d, signed string
	switch len(parts) {
	case 2:
		ms, signed = parts[0], "ts:"+parts[0]
	case 3:
		ms, d, signed = parts[0], parts[1], "ts:"+parts[0]+":"+parts[1]
	default:
		return time.Time{}, 0, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[len(parts)-1])
	if err != nil || !hmac.Equal(sig, p.mac(signed)[:18]) {
		return time.Time{}, 0, false
	}
	n, err := strconv.ParseInt(ms, 10, 64)
	if err != nil {
		return time.Time{}, 0, false
	}
	delay := time.Duration(p.opts.MinDelay * float64(time.Second))
	if d != "" {
		dn, err := strconv.Atoi(d)
		if err != nil || dn < 0 {
			return time.Time{}, 0, false
		}
		delay = time.Duration(dn) * time.Millisecond
	}
	return time.UnixMilli(n), delay, true
}

func (p *Plugin) mac(s string) []byte {
	m := hmac.New(sha256.New, p.opts.Key)
	m.Write([]byte("collage-honeypot:" + s))
	return m.Sum(nil)
}

// stampWriter holds back an HTML body to put the timestamp in place of the
// placeholder. Anything else — an event stream, an image, JSON — passes straight
// through, and so does a hijacked connection.
//
// A response is HTML when its Content-Type says so, or, when it has none, when
// its first bytes look like HTML: net/http sniffs a missing type the same way,
// below every middleware, so a handler that writes a form without declaring it
// still sends one. Until those first bytes arrive, a status written without a
// type is held back rather than decided on.
type stampWriter struct {
	http.ResponseWriter
	plugin    *Plugin
	request   *http.Request
	head      bool
	status    int
	buffering bool
	decided   bool
	body      bytes.Buffer
}

// decide settles whether the response is held back, from its Content-Type or,
// when it has none, from first, the first bytes written. The sniffed type is
// set on the response, so what net/http would have said is said here.
func (w *stampWriter) decide(first []byte) {
	if w.decided {
		return
	}
	w.decided = true
	h := w.Header()
	if _, declared := h["Content-Type"]; !declared && len(first) > 0 && h.Get("Content-Encoding") == "" {
		h.Set("Content-Type", http.DetectContentType(first))
	}
	w.buffering = strings.HasPrefix(h.Get("Content-Type"), "text/html")
	if !w.buffering && w.status != 0 {
		w.ResponseWriter.WriteHeader(w.status)
	}
}

func (w *stampWriter) WriteHeader(status int) {
	// Informational: early hints, a protocol switch. Not the response itself.
	if status < http.StatusOK {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	if w.decided {
		if !w.buffering {
			w.ResponseWriter.WriteHeader(status)
		} else if w.status == 0 {
			w.status = status
		}
		return
	}
	if w.status == 0 {
		w.status = status
	}
	if _, declared := w.Header()["Content-Type"]; declared {
		w.decide(nil)
	}
}

func (w *stampWriter) Write(b []byte) (int, error) {
	w.decide(b)
	if w.buffering {
		return w.body.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

// Flush passes a flush through when nothing is held back. A flush before
// anything was written decides on the Content-Type alone: a handler that flushes
// is streaming, and a stream is never held back.
func (w *stampWriter) Flush() {
	w.decide(nil)
	if !w.buffering {
		if f, ok := w.ResponseWriter.(http.Flusher); ok {
			f.Flush()
		}
	}
}

// Unwrap lets http.ResponseController reach the connection: a stream's write
// deadline, a WebSocket's hijack.
func (w *stampWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *stampWriter) finish() {
	// Only a status was written, and nothing to sniff: it goes out as it was.
	w.decide(nil)
	if !w.buffering {
		return
	}
	body := w.body.Bytes()
	if stamped, ok := w.plugin.stampAll(w.request, body); ok {
		body = stamped
		h := w.Header()
		// The page now carries this response's time. Without an ETag a browser
		// cannot have it confirmed by a 304 and keep an old copy; private keeps
		// a shared cache from handing one reader's time to the next.
		h.Del("ETag")
		if !strings.Contains(h.Get("Cache-Control"), "no-store") {
			h.Set("Cache-Control", "private, no-cache")
		}
	}
	if !w.head {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	}
	status := w.status
	if status == 0 {
		status = http.StatusOK
	}
	w.ResponseWriter.WriteHeader(status)
	_, _ = w.ResponseWriter.Write(body)
}

// stampAll puts a timestamp in place of every placeholder in body, and learns the
// path each placeholder's form posts to. It reports whether there was any.
func (p *Plugin) stampAll(r *http.Request, body []byte) ([]byte, bool) {
	marker := []byte(p.marker)
	if !bytes.Contains(body, marker) {
		return body, false
	}
	now := time.Now()
	defaultDelay := int(p.opts.MinDelay * 1000)
	out := make([]byte, 0, len(body)+64)
	rest := 0
	for {
		i := bytes.Index(body[rest:], marker)
		if i < 0 {
			break
		}
		at := rest + i
		end := at + len(marker)
		delay := defaultDelay
		// A form's own delay: a dash and its milliseconds.
		if end < len(body) && body[end] == '-' {
			digits := end + 1
			for digits < len(body) && digits-end <= 9 && '0' <= body[digits] && body[digits] <= '9' {
				digits++
			}
			if digits > end+1 {
				delay, _ = strconv.Atoi(string(body[end+1 : digits]))
				end = digits
			}
		}
		if path, ok := formTarget(r, body, at); ok && p.learned.add(path) {
			p.log.Warn("honeypot: learned the most paths it keeps from forms; set protect for the paths not yet learned", "limit", learnedLimit)
		}
		out = append(out, body[rest:at]...)
		out = append(out, p.stamp(now, delay)...)
		rest = end
	}
	return append(out, body[rest:]...), true
}

// formTarget is the clean path the form around body[at] posts to: its action,
// resolved against the page's own URL, or the page's own path when it has none.
// It reports false when at is in no form, or the form posts to another host.
func formTarget(r *http.Request, body []byte, at int) (string, bool) {
	open := formStart(body[:at])
	if open < 0 || lastIndexFold(body[open:at], "</form") >= 0 {
		return "", false
	}
	action, ok := attribute(body[open+len("<form"):], "action")
	if !ok || strings.TrimSpace(action) == "" {
		return cleanPath(r.URL.Path), true
	}
	ref, err := url.Parse(strings.TrimSpace(html.UnescapeString(action)))
	if err != nil {
		return "", false
	}
	target := r.URL.ResolveReference(ref)
	if ref.Host != "" && ref.Host != r.Host {
		return "", false
	}
	return cleanPath(target.Path), true
}

// formStart is the index of the last <form start tag in b: not a <form-field or
// any other element whose name only begins with form.
func formStart(b []byte) int {
	for end := len(b); ; {
		i := lastIndexFold(b[:end], "<form")
		if i < 0 {
			return -1
		}
		next := i + len("<form")
		if next >= len(b) || strings.IndexByte(" \t\n\r\f/>", b[next]) >= 0 {
			return i
		}
		end = i
	}
}

// lastIndexFold is the last index of needle, an ASCII lowercase string, in b,
// matching ASCII letters in either case. Only ASCII is folded: an index into a
// lowercased copy would not be an index into b once a Turkish İ, two bytes that
// lowercase to one, came before it.
func lastIndexFold(b []byte, needle string) int {
	for i := len(b) - len(needle); i >= 0; i-- {
		match := true
		for j := 0; j < len(needle); j++ {
			c := b[i+j]
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// attribute reads the named attribute from tag, the bytes after a start tag's
// name, up to the tag's closing >. Values quoted either way and unquoted ones,
// as a minifier leaves them, are all read.
func attribute(tag []byte, name string) (string, bool) {
	i := 0
	space := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' }
	for i < len(tag) {
		for i < len(tag) && (space(tag[i]) || tag[i] == '/') {
			i++
		}
		if i >= len(tag) || tag[i] == '>' {
			return "", false
		}
		start := i
		for i < len(tag) && !space(tag[i]) && tag[i] != '=' && tag[i] != '>' && tag[i] != '/' {
			i++
		}
		attr := string(tag[start:i])
		for i < len(tag) && space(tag[i]) {
			i++
		}
		value := ""
		if i < len(tag) && tag[i] == '=' {
			i++
			for i < len(tag) && space(tag[i]) {
				i++
			}
			if i < len(tag) && (tag[i] == '"' || tag[i] == '\'') {
				quote := tag[i]
				i++
				start := i
				for i < len(tag) && tag[i] != quote {
					i++
				}
				value = string(tag[start:i])
				i++
			} else {
				start := i
				for i < len(tag) && !space(tag[i]) && tag[i] != '>' {
					i++
				}
				value = string(tag[start:i])
			}
		}
		if strings.EqualFold(attr, name) {
			return value, true
		}
	}
	return "", false
}
