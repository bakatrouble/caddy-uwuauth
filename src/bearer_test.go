package caddyuwuauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func bearerRequest(secret string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "https://site.example.com/", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return req
}

// bearerGate is the handler for the app with this name, with the fake API.
func bearerGate(t *testing.T, app string) *UwUAuth {
	t.Helper()
	calls := 0
	m := apiGate(t, &calls)
	m.LDAPBaseDN = "dc=example,dc=com"
	m.App = app
	return m
}

func TestBearerAppPasswordAdmitsAMemberOfTheAppsGroup(t *testing.T) {
	m := bearerGate(t, "Writers Guild")
	var app reached
	rec := httptest.NewRecorder()
	if err := m.ServeHTTP(rec, bearerRequest("good-secret"), app.next()); err != nil {
		t.Fatal(err)
	}
	if !app.called {
		t.Fatalf("not admitted: %d %q", rec.Code, rec.Body.String())
	}
	if got := app.header.Get("Remote-User"); got != "nyu" {
		t.Errorf("Remote-User = %q, want nyu", got)
	}
	if got := app.header.Get("Remote-Groups"); got != "writers" {
		t.Errorf("Remote-Groups = %q", got)
	}
}

func TestBearerWrongSecretIsUnauthorizedWithBothChallenges(t *testing.T) {
	m := bearerGate(t, "Writers Guild")
	rec := httptest.NewRecorder()
	var app reached
	if err := m.ServeHTTP(rec, bearerRequest("nope"), app.next()); err != nil {
		t.Fatal(err)
	}
	if app.called || rec.Code != http.StatusUnauthorized {
		t.Errorf("got %d (reached=%v)", rec.Code, app.called)
	}
	challenges := strings.Join(rec.Header().Values("WWW-Authenticate"), ",")
	if !strings.Contains(challenges, "Basic") || !strings.Contains(challenges, "Bearer") {
		t.Errorf("WWW-Authenticate = %q", challenges)
	}
}

func TestBearerOutsideTheAppsGroupIsForbidden(t *testing.T) {
	m := bearerGate(t, "Writers Guild")
	rec := httptest.NewRecorder()
	var app reached
	if err := m.ServeHTTP(rec, bearerRequest("stranger-secret"), app.next()); err != nil {
		t.Fatal(err)
	}
	if app.called || rec.Code != http.StatusForbidden {
		t.Errorf("got %d (reached=%v)", rec.Code, app.called)
	}
}

func TestBearerRefusedAccountIsForbidden(t *testing.T) {
	m := bearerGate(t, "Open")
	rec := httptest.NewRecorder()
	var app reached
	if err := m.ServeHTTP(rec, bearerRequest("disabled-secret"), app.next()); err != nil {
		t.Fatal(err)
	}
	if app.called || rec.Code != http.StatusForbidden {
		t.Errorf("got %d (reached=%v)", rec.Code, app.called)
	}
}

// A second-factor app refuses the bearer secret before asking UwUAuth about it.
func TestBearerRefusedForSecondFactorApp(t *testing.T) {
	m := bearerGate(t, "Secure")
	rec := httptest.NewRecorder()
	var app reached
	if err := m.ServeHTTP(rec, bearerRequest("good-secret"), app.next()); err != nil {
		t.Fatal(err)
	}
	if app.called || rec.Code != http.StatusForbidden {
		t.Errorf("got %d (reached=%v)", rec.Code, app.called)
	}
}

func TestBearerAnOpenAppAdmitsAnySignedInPerson(t *testing.T) {
	m := bearerGate(t, "Open")
	var app reached
	if err := m.ServeHTTP(httptest.NewRecorder(), bearerRequest("good-secret"), app.next()); err != nil {
		t.Fatal(err)
	}
	if !app.called {
		t.Error("the open app did not admit a signed-in person")
	}
}

func TestBearerWithoutSecretIsUnauthorized(t *testing.T) {
	m := bearerGate(t, "Writers Guild")
	rec := httptest.NewRecorder()
	if err := m.ServeHTTP(rec, bearerRequest(""), (&reached{}).next()); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got %d", rec.Code)
	}
}

func TestBearerNeedsAPIToken(t *testing.T) {
	m := bearerGate(t, "Writers Guild")
	m.APIToken = ""
	rec := httptest.NewRecorder()
	var app reached
	if err := m.ServeHTTP(rec, bearerRequest("good-secret"), app.next()); err != nil {
		t.Fatal(err)
	}
	if app.called || rec.Code != http.StatusForbidden {
		t.Errorf("got %d (reached=%v)", rec.Code, app.called)
	}
}

// A site that names no app refuses API clients: nothing is guessed from the host.
func TestBearerNeedsTheAppName(t *testing.T) {
	m := bearerGate(t, "")
	rec := httptest.NewRecorder()
	var app reached
	if err := m.ServeHTTP(rec, bearerRequest("good-secret"), app.next()); err != nil {
		t.Fatal(err)
	}
	if app.called || rec.Code != http.StatusForbidden {
		t.Errorf("got %d (reached=%v)", rec.Code, app.called)
	}
}

// An unknown app name is refused, and the API is asked only once for it.
func TestBearerUnknownAppNameIsForbidden(t *testing.T) {
	m := bearerGate(t, "Nobody")
	rec := httptest.NewRecorder()
	var app reached
	if err := m.ServeHTTP(rec, bearerRequest("good-secret"), app.next()); err != nil {
		t.Fatal(err)
	}
	if app.called || rec.Code != http.StatusForbidden {
		t.Errorf("got %d (reached=%v)", rec.Code, app.called)
	}
}
