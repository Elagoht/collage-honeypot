package honeypot_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	honeypot "github.com/Elagoht/collage-honeypot"
	"github.com/Elagoht/collage/pkg/collage"
)

var key = bytes.Repeat([]byte("k"), 32)

type received struct {
	mu       sync.Mutex
	messages []string
}

func (r *received) add(m string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.messages = append(r.messages, m)
}

func (r *received) last() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.messages) == 0 {
		return ""
	}
	return r.messages[len(r.messages)-1]
}

func app(t *testing.T, opts honeypot.Options, config map[string]json.RawMessage) (*collage.App, *received) {
	t.Helper()
	return appWith(t, opts, config, false)
}

func appWith(t *testing.T, opts honeypot.Options, config map[string]json.RawMessage, csrf bool) (*collage.App, *received) {
	t.Helper()
	token := ""
	if csrf {
		token = "{{csrfToken}}"
	}
	a, err := collage.New(&collage.Config{
		Server: collage.ServerConfig{Host: "localhost", Port: 3000},
		Template: collage.TemplateConfig{FS: fstest.MapFS{
			"t/p.html": {Data: []byte(`<html><body><form method="post" action="/contact">{{honeypot}}` + token + `<textarea name="message"></textarea></form></body></html>`)},
		}, Root: "t"},
		Cache:        collage.CacheConfig{Enabled: true, Type: "memory", DefaultTTL: time.Hour},
		Security:     collage.SecurityConfig{CSRFKey: key},
		Plugins:      []collage.Plugin{honeypot.New(opts)},
		PluginConfig: config,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Static, so the form is served from the cache: the timestamp has to survive
	// that.
	if err := a.RegisterPage(collage.NewPage("home").WithContent(collage.NewFragment("home", "p.html").Build()).WithPath("en", "/").Static().Build()); err != nil {
		t.Fatal(err)
	}
	got := &received{}
	builder := collage.NewAction("contact").WithPath("en", "/contact").WithMethods(http.MethodPost)
	if !csrf {
		builder = builder.WithoutCSRF()
	}
	action := builder.
		WithHandler(func(_ context.Context, rc *collage.RenderContext) (*collage.ActionResult, error) {
			got.add(rc.Request.FormValue("message"))
			return collage.SeeOther("/thanks"), nil
		}).Build()
	if err := a.RegisterAction(action); err != nil {
		t.Fatal(err)
	}
	return a, got
}

// site is the app's handler, with the form served once, so the path it posts to
// is one the plugin checks.
func site(t *testing.T, opts honeypot.Options) (http.Handler, *received) {
	t.Helper()
	a, got := app(t, opts, nil)
	h := a.Handler()
	serve(h, httptest.NewRequest(http.MethodGet, "/", nil))
	return h, got
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

var stampValue = regexp.MustCompile(`name="_hpt" value="([^"]+)"`)

// stampOf fetches the form and returns the timestamp it was served with.
func stampOf(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := serve(h, httptest.NewRequest(http.MethodGet, "/", nil))
	m := stampValue.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("the form carries no timestamp:\n%s", rec.Body.String())
	}
	return m[1]
}

func post(h http.Handler, values url.Values, headers ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/contact", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	return serve(h, r)
}

func form(stamp string) url.Values {
	return url.Values{"message": {"hello"}, "website": {""}, "_hpt": {stamp}}
}

// signed makes a timestamp the way the plugin does, for a time it would never
// sign itself.
func signed(k []byte, at time.Time) string {
	ms := strconv.FormatInt(at.UnixMilli(), 10)
	m := hmac.New(sha256.New, k)
	m.Write([]byte("collage-honeypot:ts:" + ms))
	return ms + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:18])
}

// The decoy is hidden from people and from assistive technology, without
// display:none.
func TestDecoyMarkup(t *testing.T) {
	h, _ := site(t, honeypot.Options{Key: key})
	body := serve(h, httptest.NewRequest(http.MethodGet, "/", nil)).Body.String()
	for _, want := range []string{`name="website"`, `aria-hidden="true"`, `inert`, `tabindex="-1"`, `autocomplete="off"`, `left:-10000px`, `class="collage-hp"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the decoy lacks %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, "display:none") {
		t.Error("the decoy is hidden with display:none")
	}
}

// Every response gets its own timestamp, though the page comes from the cache,
// and the page cannot be confirmed by a 304 or kept by a shared cache.
func TestTimestampSurvivesTheCache(t *testing.T) {
	h, _ := site(t, honeypot.Options{Key: key})
	first := stampOf(t, h)
	time.Sleep(5 * time.Millisecond)
	rec := serve(h, httptest.NewRequest(http.MethodGet, "/", nil))
	second := stampValue.FindStringSubmatch(rec.Body.String())[1]
	if first == second || strings.Contains(first, "collage-honeypot") {
		t.Errorf("stamps %q and %q", first, second)
	}
	if rec.Header().Get("ETag") != "" || rec.Header().Get("Cache-Control") != "private, no-cache" {
		t.Errorf("ETag %q, Cache-Control %q", rec.Header().Get("ETag"), rec.Header().Get("Cache-Control"))
	}
	if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(rec.Body.Len()) {
		t.Errorf("Content-Length %s for %d bytes", got, rec.Body.Len())
	}
}

func TestSubmissions(t *testing.T) {
	h, got := site(t, honeypot.Options{Key: key, MinDelay: 0.05})
	stamp := stampOf(t, h)

	if rec := post(h, form(stamp)); rec.Code != http.StatusBadRequest {
		t.Errorf("sent at once: %d, want 400", rec.Code)
	}
	time.Sleep(80 * time.Millisecond)

	filled := form(stamp)
	filled.Set("website", "https://spam.example")
	for name, values := range map[string]url.Values{
		"decoy filled":  filled,
		"no timestamp":  {"message": {"hello"}},
		"forged":        form(signed(bytes.Repeat([]byte("x"), 32), time.Now().Add(-time.Minute))),
		"tampered":      form(strings.Replace(stamp, stamp[:3], "999", 1)),
		"expired":       form(signed(key, time.Now().Add(-25*time.Hour))),
		"from tomorrow": form(signed(key, time.Now().Add(time.Hour))),
	} {
		rec := post(h, values)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "could not be accepted") {
			t.Errorf("%s: %d %q, want 400", name, rec.Code, rec.Body.String())
		}
	}
	if got.last() != "" {
		t.Fatalf("a refused submission reached the action: %q", got.last())
	}

	// A person's submission reaches the action with its body intact.
	if rec := post(h, form(stamp)); rec.Code != http.StatusSeeOther || got.last() != "hello" {
		t.Errorf("a person's submission: %d, action saw %q", rec.Code, got.last())
	}
}

// The body read to check it is put back, so collage's own forgery check still
// finds its token in it.
func TestForgeryCheckStillReadsTheBody(t *testing.T) {
	a, got := appWith(t, honeypot.Options{Key: key, MinDelay: -1}, nil, true)
	h := a.Handler()
	page := serve(h, httptest.NewRequest(http.MethodGet, "/", nil))
	token := regexp.MustCompile(`name="_csrf" value="([^"]+)"`).FindStringSubmatch(page.Body.String())
	stamp := stampValue.FindStringSubmatch(page.Body.String())
	if token == nil || stamp == nil {
		t.Fatalf("page:\n%s", page.Body.String())
	}
	values := form(stamp[1])
	values.Set("_csrf", token[1])
	r := httptest.NewRequest(http.MethodPost, "/contact", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range page.Result().Cookies() {
		r.AddCookie(c)
	}
	if rec := serve(h, r); rec.Code != http.StatusSeeOther || got.last() != "hello" {
		t.Errorf("status %d, action saw %q", rec.Code, got.last())
	}
}

// Multipart bodies are checked, and put back for the action as well.
func TestMultipart(t *testing.T) {
	h, got := site(t, honeypot.Options{Key: key, MinDelay: -1})
	send := func(stamp string) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		_ = mw.WriteField("message", "from multipart")
		if stamp != "" {
			_ = mw.WriteField("_hpt", stamp)
		}
		fw, _ := mw.CreateFormFile("file", "a.txt")
		_, _ = fw.Write([]byte("attachment"))
		_ = mw.Close()
		r := httptest.NewRequest(http.MethodPost, "/contact", &buf)
		r.Header.Set("Content-Type", mw.FormDataContentType())
		return serve(h, r)
	}
	if rec := send(""); rec.Code != http.StatusBadRequest {
		t.Errorf("no timestamp: %d", rec.Code)
	}
	if rec := send(stampOf(t, h)); rec.Code != http.StatusSeeOther || got.last() != "from multipart" {
		t.Errorf("multipart: %d, action saw %q", rec.Code, got.last())
	}
}

// Silent refusals look like success, and never send the client off the site.
func TestSilent(t *testing.T) {
	h, got := site(t, honeypot.Options{Key: key, Silent: true})
	for referer, want := range map[string]string{
		"http://example.com/contact?sent=1": "/contact?sent=1",
		"https://evil.example/landing":      "/",
		"":                                  "/",
	} {
		rec := post(h, url.Values{"message": {"spam"}}, "Referer", referer)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != want {
			t.Errorf("Referer %q: %d to %q, want 303 to %q", referer, rec.Code, rec.Header().Get("Location"), want)
		}
	}
	if got.last() != "" {
		t.Errorf("a refused submission reached the action: %q", got.last())
	}
}

// What is not a form body is not checked.
func TestOtherRequestsPass(t *testing.T) {
	h, _ := site(t, honeypot.Options{Key: key, Protect: []string{"/contact"}})
	r := httptest.NewRequest(http.MethodPost, "/contact", strings.NewReader(`{"message":"hi"}`))
	r.Header.Set("Content-Type", "application/json")
	if rec := serve(h, r); rec.Code == http.StatusBadRequest {
		t.Errorf("a JSON body was checked: %d", rec.Code)
	}
	r = httptest.NewRequest(http.MethodPost, "/elsewhere", strings.NewReader("a=b"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if rec := serve(h, r); rec.Code == http.StatusBadRequest {
		t.Errorf("an unprotected path was checked: %d", rec.Code)
	}

	h, _ = site(t, honeypot.Options{Key: key})
	for path, want := range map[string]bool{"/_collage/x": false, "/contact": true} {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader("a=b"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if refused := serve(h, r).Code == http.StatusBadRequest; refused != want {
			t.Errorf("%s: refused %v, want %v", path, refused, want)
		}
	}
	// collage redirects a path with dot segments to its clean spelling before
	// any middleware runs — 308, since a POST carries a body — so it never passes
	// as a development endpoint; the plugin's own check stays behind that.
	r = httptest.NewRequest(http.MethodPost, "/_collage/../contact", strings.NewReader("a=b"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if rec := serve(h, r); rec.Code != http.StatusPermanentRedirect || rec.Header().Get("Location") != "/contact" {
		t.Errorf("/_collage/../contact: %d %q, want collage's redirect to /contact", rec.Code, rec.Header().Get("Location"))
	}
}

// The body is the action's to bound, not the plugin's: a form larger than
// collage's default goes through to an action that allows it, and one past an
// action's limit is that action's 413.
func TestTheActionBoundsTheBody(t *testing.T) {
	a, err := collage.New(&collage.Config{
		Server: collage.ServerConfig{Host: "localhost", Port: 3000},
		Template: collage.TemplateConfig{FS: fstest.MapFS{
			"t/p.html": {Data: []byte(`<form method="post" action="/upload">{{honeypot}}</form><form method="post" action="/small">{{honeypot}}</form>`)},
		}, Root: "t"},
		Plugins: []collage.Plugin{honeypot.New(honeypot.Options{Key: key})},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RegisterPage(collage.NewPage("p").WithContent(collage.NewFragment("p", "p.html").Build()).WithPath("en", "/").Build()); err != nil {
		t.Fatal(err)
	}
	got := &received{}
	for path, limit := range map[string]int64{"/upload": 8 << 20, "/small": 64} {
		action := collage.NewAction(strings.TrimPrefix(path, "/")).WithPath("en", path).WithMethods(http.MethodPost).WithoutCSRF().WithMaxBodyBytes(limit).
			WithHandler(func(_ context.Context, rc *collage.RenderContext) (*collage.ActionResult, error) {
				got.add(strconv.Itoa(len(rc.Request.FormValue("message"))))
				return collage.SeeOther("/thanks"), nil
			}).Build()
		if err := a.RegisterAction(action); err != nil {
			t.Fatal(err)
		}
	}
	h := a.Handler()
	stamp := stampOf(t, h)
	send := func(path string, values url.Values) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return serve(h, r)
	}
	big := form(stamp)
	big.Set("message", strings.Repeat("x", 5<<20))
	if rec := send("/upload", big); rec.Code != http.StatusSeeOther || got.last() != strconv.Itoa(5<<20) {
		t.Errorf("5 MiB to an action allowing 8: %d, action saw %s bytes", rec.Code, got.last())
	}
	if rec := send("/small", big); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("past the action's limit: %d, want 413", rec.Code)
	}
	// Refused still, once the form fits.
	if rec := send("/upload", url.Values{"message": {"spam"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("no timestamp: %d, want 400", rec.Code)
	}
}

// Configuration overlays the options, the key included.
func TestConfiguration(t *testing.T) {
	a, _ := app(t, honeypot.Options{}, map[string]json.RawMessage{
		honeypot.Name: json.RawMessage(`{"key": "` + hex.EncodeToString(key) + `", "field": "homepage", "minDelay": -1, "protect": ["/contact"]}`),
	})
	h := a.Handler()
	if body := serve(h, httptest.NewRequest(http.MethodGet, "/", nil)).Body.String(); !strings.Contains(body, `name="homepage"`) {
		t.Errorf("the field was not renamed:\n%s", body)
	}
	// Signed with the configured key, and sent at once: minDelay is off, as -1
	// turned it off before 0 did.
	values := url.Values{"message": {"hi"}, "_hpt": {signed(key, time.Now())}}
	if rec := post(h, values); rec.Code != http.StatusSeeOther {
		t.Errorf("status %d", rec.Code)
	}
}

// A static build has no middleware to stand in for the placeholder, so the page
// carries the decoy and no timestamp.
func TestStaticBuild(t *testing.T) {
	a, _ := app(t, honeypot.Options{Key: key}, nil)
	out := t.TempDir()
	b, err := collage.NewBuilder(a, collage.BuildOptions{OutDir: out})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(context.Background()); err != nil {
		t.Fatal(err)
	}
	var html []byte
	_ = filepath.WalkDir(out, func(p string, d os.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(p, ".html") {
			html, _ = os.ReadFile(p)
		}
		return nil
	})
	if !bytes.Contains(html, []byte(`name="website"`)) || bytes.Contains(html, []byte("_hpt")) || bytes.Contains(html, []byte("collage-honeypot")) {
		t.Errorf("built page:\n%s", html)
	}
}

// A misconfigured plugin stops the application from being built.
func TestMisconfiguration(t *testing.T) {
	for name, opts := range map[string]honeypot.Options{
		"short key":        {Key: []byte("short")},
		"bad hex":          {KeyHex: "zz"},
		"field with quote": {Key: key, Field: `a"b`},
		"field clash":      {Key: key, Field: "_hpt"},
		"negative delay":   {Key: key, MinDelay: -2},
		"delay past age":   {Key: key, MinDelay: 10, MaxAge: 5},
		"relative prefix":  {Key: key, Protect: []string{"contact"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := collage.New(&collage.Config{
				Server:   collage.ServerConfig{Host: "localhost", Port: 3000},
				Template: collage.TemplateConfig{FS: fstest.MapFS{"t/p.html": {Data: []byte(`{{honeypot}}`)}}, Root: "t"},
				Plugins:  []collage.Plugin{honeypot.New(opts)},
			})
			if err == nil {
				t.Error("the application was built")
			}
		})
	}
}

// markerOf is the placeholder {{honeypot}} renders for key k.
func markerOf(k []byte) string {
	m := hmac.New(sha256.New, k)
	m.Write([]byte("collage-honeypot:marker"))
	return "collage-honeypot-" + hex.EncodeToString(m.Sum(nil))[:32]
}

// A handler of the application's own that writes a form without saying it is
// HTML — net/http sniffs the type below the middleware — still has its
// placeholder stamped. So does one that writes the status first, and one that
// flushes before it writes.
func TestUndeclaredHTML(t *testing.T) {
	marker := markerOf(key)
	page := `<!doctype html><html><body><form method="post"><input type="hidden" name="_hpt" value="` + marker + `"></form></body></html>`
	handlers := map[string]http.HandlerFunc{
		"/write": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, page)
		},
		"/status": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = io.WriteString(w, page)
		},
		"/chunks": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, page[:20])
			_, _ = io.WriteString(w, page[20:])
		},
	}
	a, _ := app(t, honeypot.Options{Key: key}, nil)
	for path, handler := range handlers {
		if err := a.Handle(path, handler); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	for path := range handlers {
		res, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if bytes.Contains(body, []byte(marker)) || !stampValue.Match(body) {
			t.Errorf("%s: the placeholder went out unstamped:\n%s", path, body)
		}
		if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("%s: Content-Type %q", path, ct)
		}
		if path == "/status" && res.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("%s: status %d", path, res.StatusCode)
		}
	}
}

// signedWith makes a timestamp in the current format: the time, the delay its
// form asked for in milliseconds, and an HMAC of both.
func signedWith(k []byte, at time.Time, delayMS int) string {
	ms := strconv.FormatInt(at.UnixMilli(), 10)
	d := strconv.Itoa(delayMS)
	m := hmac.New(sha256.New, k)
	m.Write([]byte("collage-honeypot:ts:" + ms + ":" + d))
	return ms + "." + d + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:18])
}

// learning is a site of several forms, served by a real server: one without
// {{honeypot}}, and ones with it whose actions are spelled every way a page
// spells them.
func learning(t *testing.T, opts honeypot.Options) (*httptest.Server, *received) {
	t.Helper()
	pages := map[string]string{
		"plain":    `<form method="post" action="/register"><input name="message"></form>`,
		"quoted":   `<FORM method="post" ACTION="/login"><form-field action="/nowhere">{{honeypot}}</form-field><input name="message"></FORM>`,
		"bare":     `<form method=post action=/profile>{{honeypot}}<input name=message></form>`,
		"relative": `<p>İstanbul</p><form method="post" action="7/comments?x=1&amp;y=2">{{honeypot}}</form>`,
		"self":     `<form method="post">{{honeypot 0}}</form>`,
		"slow":     `<form method="post" action="/slow">{{honeypot 0.05}}</form>`,
		"away":     `<form method="post" action="https://elsewhere.example/steal">{{honeypot}}</form>`,
	}
	files := fstest.MapFS{}
	for name, body := range pages {
		files["t/"+name+".html"] = &fstest.MapFile{Data: []byte(`<html><body>` + body + `</body></html>`)}
	}
	a, err := collage.New(&collage.Config{
		Server:   collage.ServerConfig{Host: "localhost", Port: 3000},
		Template: collage.TemplateConfig{FS: files, Root: "t"},
		Security: collage.SecurityConfig{CSRFKey: key},
		Plugins:  []collage.Plugin{honeypot.New(opts)},
	})
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{"plain": "/join", "quoted": "/in", "bare": "/me", "relative": "/stories/7", "self": "/logout", "slow": "/slow-form", "away": "/away"}
	for name, path := range paths {
		if err := a.RegisterPage(collage.NewPage(name).WithContent(collage.NewFragment(name, name+".html").Build()).WithPath("en", path).Build()); err != nil {
			t.Fatal(err)
		}
	}
	got := &received{}
	for i, path := range []string{"/register", "/login", "/profile", "/stories/7/comments", "/logout", "/slow", "/steal"} {
		action := collage.NewAction("a"+strconv.Itoa(i)).WithPath("en", path).WithMethods(http.MethodPost).WithoutCSRF().
			WithHandler(func(_ context.Context, rc *collage.RenderContext) (*collage.ActionResult, error) {
				got.add(rc.Request.URL.Path)
				return collage.SeeOther("/thanks"), nil
			}).Build()
		if err := a.RegisterAction(action); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	return srv, got
}

func fetch(t *testing.T, srv *httptest.Server, path string) string {
	t.Helper()
	res, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return string(body)
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func submit(t *testing.T, srv *httptest.Server, path string, values url.Values) int {
	t.Helper()
	res, err := noRedirect.Post(srv.URL+path, "application/x-www-form-urlencoded", strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode
}

// A path is checked once a {{honeypot}} form posting to it has been served, and
// never when no such form has: nothing in the configuration names it.
func TestLearnsFromForms(t *testing.T) {
	srv, _ := learning(t, honeypot.Options{Key: key})
	bare := url.Values{"message": {"spam"}}
	targets := map[string]string{"/in": "/login", "/me": "/profile", "/stories/7": "/stories/7/comments", "/logout": "/logout"}
	for _, target := range targets {
		if code := submit(t, srv, target, bare); code != http.StatusSeeOther {
			t.Errorf("%s before its form was served: %d, want it unchecked", target, code)
		}
	}
	for page, target := range targets {
		body := fetch(t, srv, page)
		if code := submit(t, srv, target, bare); code != http.StatusBadRequest {
			t.Errorf("%s after %s was served: %d, want 400", target, page, code)
		}
		m := stampValue.FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("%s carries no timestamp:\n%s", page, body)
		}
		if code := submit(t, srv, target, form(m[1])); code != http.StatusSeeOther {
			t.Errorf("%s with its timestamp: %d", target, code)
		}
	}
	// A form without {{honeypot}} is never checked, and one posting to another
	// host teaches nothing about this one.
	fetch(t, srv, "/join")
	fetch(t, srv, "/away")
	for _, target := range []string{"/register", "/steal"} {
		if code := submit(t, srv, target, bare); code != http.StatusSeeOther {
			t.Errorf("%s: %d, want it unchecked", target, code)
		}
	}
}

// Protect checks a path before any form naming it has been served.
func TestProtectBeforeServing(t *testing.T) {
	srv, _ := learning(t, honeypot.Options{Key: key, Protect: []string{"/login"}})
	if code := submit(t, srv, "/login", url.Values{"message": {"spam"}}); code != http.StatusBadRequest {
		t.Errorf("/login: %d, want 400", code)
	}
}

// No delay is asked for by default, a form may ask for its own, and the delay it
// asked for is signed: a bot cannot shorten it.
func TestDelays(t *testing.T) {
	srv, _ := learning(t, honeypot.Options{Key: key})
	stamp := func(page string) string {
		m := stampValue.FindStringSubmatch(fetch(t, srv, page))
		if m == nil {
			t.Fatalf("%s carries no timestamp", page)
		}
		return m[1]
	}
	for page, target := range map[string]string{"/in": "/login", "/logout": "/logout"} {
		if code := submit(t, srv, target, form(stamp(page))); code != http.StatusSeeOther {
			t.Errorf("%s sent at once: %d, want accepted", target, code)
		}
	}
	slow := stamp("/slow-form")
	if code := submit(t, srv, "/slow", form(slow)); code != http.StatusBadRequest {
		t.Errorf("/slow sent at once: %d, want 400", code)
	}
	parts := strings.Split(slow, ".")
	if len(parts) != 3 || parts[1] != "50" {
		t.Fatalf("stamp %q, want its delay of 50ms in it", slow)
	}
	if code := submit(t, srv, "/slow", form(parts[0]+".0."+parts[2])); code != http.StatusBadRequest {
		t.Errorf("/slow with its delay edited to 0: %d, want 400", code)
	}
	time.Sleep(80 * time.Millisecond)
	if code := submit(t, srv, "/slow", form(slow)); code != http.StatusSeeOther {
		t.Errorf("/slow after its delay: %d", code)
	}
	// A timestamp from v0.1, served before an upgrade, is still good.
	if code := submit(t, srv, "/login", form(signed(key, time.Now()))); code != http.StatusSeeOther {
		t.Errorf("a v0.1 timestamp: %d", code)
	}
	if code := submit(t, srv, "/login", form(signedWith(key, time.Now(), 0))); code != http.StatusSeeOther {
		t.Errorf("a signed timestamp: %d", code)
	}
}

// A delay {{honeypot}} cannot keep is a render error, not a form nobody can send.
func TestBadDelay(t *testing.T) {
	for _, call := range []string{"{{honeypot -1}}", "{{honeypot 1 2}}", "{{honeypot 100000}}"} {
		a, err := collage.New(&collage.Config{
			Server:   collage.ServerConfig{Host: "localhost", Port: 3000},
			Template: collage.TemplateConfig{FS: fstest.MapFS{"t/p.html": {Data: []byte(`<form method="post">` + call + `</form>`)}}, Root: "t"},
			Plugins:  []collage.Plugin{honeypot.New(honeypot.Options{Key: key, MaxAge: 3600})},
		})
		if err != nil {
			continue
		}
		if err := a.RegisterPage(collage.NewPage("p").WithContent(collage.NewFragment("p", "p.html").Build()).WithPath("en", "/").Build()); err != nil {
			t.Fatal(err)
		}
		rec := serve(a.Handler(), httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "_hpt") {
			t.Errorf("%s rendered a form:\n%s", call, rec.Body.String())
		}
	}
}
