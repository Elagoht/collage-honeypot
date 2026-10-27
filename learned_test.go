package honeypot_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	honeypot "github.com/Elagoht/collage-honeypot"
	"github.com/Elagoht/collage/pkg/collage"
	"github.com/Elagoht/collage/pkg/collagetest"
)

// floodSite is a site where any path under /p/ serves an action-less
// {{honeypot}} form, so a client can make the plugin learn as many junk paths as
// it likes; /contact-us serves the real form posting to /contact, /post-1 a
// comment form posting to /comment/1, and /logout
// is an action no {{honeypot}} form posts to. accepted counts what reached the
// handlers.
func floodSite(t *testing.T, accepted *atomic.Int64) (h http.Handler, get func(string) string, post func(string) int) {
	t.Helper()
	ok := func(context.Context, *collage.RenderContext) (*collage.ActionResult, error) {
		accepted.Add(1)
		return collage.SeeOther("/"), nil
	}
	site := collagetest.NewSite(t,
		collagetest.WithoutHome(),
		collagetest.WithTemplates(map[string]string{
			"p.html":       `<html><body><form method="post">{{honeypot}}</form></body></html>`,
			"contact.html": `<html><body><form method="post" action="/contact">{{honeypot}}</form></body></html>`,
			"post.html":    `<html><body><form method="post" action="/comment/1">{{honeypot}}</form></body></html>`,
		}),
		collagetest.WithRegister(
			collage.NewPage("p").WithContent(collage.NewFragment("p", "p.html").Build()).WithPath("en", "/p/{id}").Build(),
			collage.NewPage("c").WithContent(collage.NewFragment("c", "contact.html").Build()).WithPath("en", "/contact-us").Build(),
			collage.NewPage("post").WithContent(collage.NewFragment("post", "post.html").Build()).WithPath("en", "/post-1").Build(),
			collage.NewAction("contact").WithPath("en", "/contact").WithMethods(http.MethodPost).WithoutCSRF().WithHandler(ok).Build(),
			collage.NewAction("comment").WithPath("en", "/comment/{id}").WithMethods(http.MethodPost).WithoutCSRF().WithHandler(ok).Build(),
			collage.NewAction("logout").WithPath("en", "/logout").WithMethods(http.MethodPost).WithoutCSRF().WithHandler(ok).Build(),
		),
		collagetest.WithPlugins(honeypot.New(honeypot.Options{Key: key})),
	)
	h = site.App.Handler()
	get = func(path string) string {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Body.String()
	}
	post = func(path string) int {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(url.Values{"message": {"buy now"}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	return h, get, post
}

// Filling the learned set with junk paths does not stop the plugin learning: a
// form served after the flood is still protected. (PLUGA-B05)
func TestLearnedSetFloodKeepsProtecting(t *testing.T) {
	var accepted atomic.Int64
	_, get, post := floodSite(t, &accepted)
	for i := range 4200 {
		get(fmt.Sprintf("/p/%d", i))
	}
	if body := get("/contact-us"); !strings.Contains(body, `name="`+honeypot.TimeField+`"`) {
		t.Fatalf("precondition: contact form not stamped: %s", body)
	}
	if code := post("/contact"); code != http.StatusBadRequest || accepted.Load() != 0 {
		t.Fatalf("spam after a flood of junk paths: %d, accepted %d; want 400", code, accepted.Load())
	}
	// Nor does the flood make the plugin refuse an action no {{honeypot}} form
	// posts to: it stays unchecked, which is why a full set is not answered by
	// checking every form.
	if code := post("/logout"); code != http.StatusSeeOther {
		t.Fatalf("a form without {{honeypot}} was refused after the flood: %d", code)
	}
}

// Once a submission reaches an action through a path learned from a form, the
// action is protected on every path: a flood that pushes its path out of the
// learned set, or a record whose form was never served, does not unprotect it.
func TestActionStaysProtectedAfterEviction(t *testing.T) {
	var accepted atomic.Int64
	_, get, post := floodSite(t, &accepted)
	// Record 1's comment form is served, then a submission reaches it.
	get("/post-1")
	if code := post("/comment/1"); code != http.StatusBadRequest {
		t.Fatalf("spam to a learned comment path: %d, want 400", code)
	}
	for i := range 4200 {
		get(fmt.Sprintf("/p/%d", i))
	}
	for _, path := range []string{"/comment/1", "/comment/2"} {
		if code := post(path); code != http.StatusBadRequest {
			t.Errorf("spam to %s after the flood: %d, want 400", path, code)
		}
	}
	if accepted.Load() != 0 {
		t.Errorf("accepted %d spam submissions", accepted.Load())
	}
}
