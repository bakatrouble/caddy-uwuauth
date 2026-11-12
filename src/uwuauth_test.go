package caddyuwuauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// gate builds a handler whose forward auth is the given fake UwUAuth.
func gate(t *testing.T, uwuauth http.HandlerFunc) *UwUAuth {
	t.Helper()
	server := httptest.NewServer(uwuauth)
	t.Cleanup(server.Close)
	m := &UwUAuth{ForwardAuthURL: server.URL, LDAPAddress: "127.0.0.1:1", logger: zap.NewNop()}
	m.client = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	m.apps = newAppCache(appCacheTTL)
	return m
}

// reached records that the app got the request, and with which headers.
type reached struct {
	called bool
	header http.Header
}

func (r *reached) next() caddyhttp.Handler {
	return caddyhttp.HandlerFunc(func(w http.ResponseWriter, req *http.Request) error {
		r.called = true
		r.header = req.Header.Clone()
		return nil
	})
}

func TestForwardAllowsAndSetsRemoteHeaders(t *testing.T) {
	var seen http.Header
	m := gate(t, func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.Header().Set("Remote-User", "nyu")
		w.Header().Set("Remote-Groups", "grafana,everyone")
		w.Header().Set("Remote-Email", "nyu@example.com")
		w.Header().Set("Remote-Name", "Nyu")
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "https://app.example.com/some/path?q=1", nil)
	req.Header.Set("Remote-User", "admin") // a client's own value must not survive
	req.Header.Set("Cookie", "uwuauth_fa=abc")
	req.Header.Set("X-Forwarded-Host", "evil.example.com")
	var app reached
	if err := m.ServeHTTP(httptest.NewRecorder(), req, app.next()); err != nil {
		t.Fatal(err)
	}
	if !app.called {
		t.Fatal("the app was not reached after a 200")
	}
	if got := app.header.Get("Remote-User"); got != "nyu" {
		t.Errorf("Remote-User = %q, want nyu", got)
	}
	if got := app.header.Get("Remote-Groups"); got != "grafana,everyone" {
		t.Errorf("Remote-Groups = %q", got)
	}
	if seen.Get("X-Forwarded-Host") != "app.example.com" {
		t.Errorf("X-Forwarded-Host sent = %q, want the request's host", seen.Get("X-Forwarded-Host"))
	}
	if seen.Get("X-Forwarded-Uri") != "/some/path?q=1" || seen.Get("X-Forwarded-Method") != http.MethodPost {
		t.Errorf("forward auth got uri=%q method=%q", seen.Get("X-Forwarded-Uri"), seen.Get("X-Forwarded-Method"))
	}
	if seen.Get("Cookie") != "uwuauth_fa=abc" {
		t.Errorf("cookie not passed on: %q", seen.Get("Cookie"))
	}
}

func TestForwardRedirectsToSignIn(t *testing.T) {
	m := gate(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://uwuauth.example.com/sign-in")
		w.Header().Add("Set-Cookie", "uwuauth_fa=; Max-Age=0")
		w.WriteHeader(http.StatusFound)
	})
	rec := httptest.NewRecorder()
	var app reached
	if err := m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil), app.next()); err != nil {
		t.Fatal(err)
	}
	if app.called {
		t.Error("the app was reached without a sign-in")
	}
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://uwuauth.example.com/sign-in" {
		t.Errorf("got %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "uwuauth_fa=") {
		t.Errorf("Set-Cookie not passed on: %q", rec.Header().Get("Set-Cookie"))
	}
}

func TestForwardForbiddenPassesBody(t *testing.T) {
	m := gate(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("not for you"))
	})
	rec := httptest.NewRecorder()
	var app reached
	if err := m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil), app.next()); err != nil {
		t.Fatal(err)
	}
	if app.called || rec.Code != http.StatusForbidden || rec.Body.String() != "not for you" {
		t.Errorf("got %d %q (reached=%v)", rec.Code, rec.Body.String(), app.called)
	}
}

func TestUnexpectedAnswerIsBadGateway(t *testing.T) {
	m := gate(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	rec := httptest.NewRecorder()
	var app reached
	if err := m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil), app.next()); err != nil {
		t.Fatal(err)
	}
	if app.called || rec.Code != http.StatusBadGateway {
		t.Errorf("got %d (reached=%v)", rec.Code, app.called)
	}
}

func TestExcludedPathSkipsTheGate(t *testing.T) {
	m := gate(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("forward auth was asked about an excluded path")
	})
	m.ExcludePaths = []string{"/health", "/notify*"}
	for _, path := range []string{"/health", "/notify", "/notify/abc"} {
		var app reached
		if err := m.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://app.example.com"+path, nil), app.next()); err != nil {
			t.Fatal(err)
		}
		if !app.called {
			t.Errorf("%s: app not reached", path)
		}
	}
}

func TestBasicMalformedIsUnauthorizedNotRedirect(t *testing.T) {
	m := gate(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("forward auth used for a Basic request")
	})
	m.APIToken = "token"
	m.LDAPBaseDN = "dc=example,dc=com"
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	req.Header.Set("Authorization", "Basic !!!not-base64")
	rec := httptest.NewRecorder()
	if err := m.ServeHTTP(rec, req, (&reached{}).next()); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") == "" {
		t.Errorf("got %d, WWW-Authenticate=%q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
}

func TestBasicRefusedWithoutAPIToken(t *testing.T) {
	m := gate(t, func(w http.ResponseWriter, r *http.Request) {})
	m.LDAPBaseDN = "dc=example,dc=com"
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	req.SetBasicAuth("nyu", "secret")
	rec := httptest.NewRecorder()
	var app reached
	if err := m.ServeHTTP(rec, req, app.next()); err != nil {
		t.Fatal(err)
	}
	if app.called || rec.Code != http.StatusForbidden {
		t.Errorf("got %d (reached=%v)", rec.Code, app.called)
	}
}

func TestBasicRejectsUnsafeUsernameBeforeLDAP(t *testing.T) {
	calls := 0
	m := apiGate(t, &calls)
	m.LDAPBaseDN = "dc=example,dc=com"
	m.App = "Writers Guild"
	for _, user := range []string{"nyu,ou=admins", "a=b", "", strings.Repeat("a", 65)} {
		req := httptest.NewRequest(http.MethodGet, "https://writersguild.example.com/", nil)
		req.SetBasicAuth(user, "secret")
		rec := httptest.NewRecorder()
		if err := m.ServeHTTP(rec, req, (&reached{}).next()); err != nil {
			t.Fatal(err)
		}
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("user %q: got %d, want 401 without touching LDAP", user, rec.Code)
		}
	}
}

// A second-factor app is refused for Basic auth before any password is checked:
// the LDAP address here is unreachable, so reaching it would give 502, not 403.
func TestBasicRefusedForSecondFactorApp(t *testing.T) {
	calls := 0
	m := apiGate(t, &calls)
	m.LDAPBaseDN = "dc=example,dc=com"
	m.LDAPAddress = "127.0.0.1:1"
	m.App = "Secure"
	req := httptest.NewRequest(http.MethodGet, "https://secure.example.com/", nil)
	req.SetBasicAuth("nyu", "secret")
	rec := httptest.NewRecorder()
	var app reached
	if err := m.ServeHTTP(rec, req, app.next()); err != nil {
		t.Fatal(err)
	}
	if app.called || rec.Code != http.StatusForbidden {
		t.Errorf("got %d (reached=%v), want 403 for a second-factor app", rec.Code, app.called)
	}
}

func TestGroupName(t *testing.T) {
	cases := map[string]string{
		"cn=grafana,ou=groups,dc=example,dc=com": "grafana",
		"CN=Komodo,ou=groups,dc=example,dc=com":  "Komodo",
		"ou=groups,dc=example,dc=com":            "",
		"cn=":                                    "",
	}
	for in, want := range cases {
		if got := groupName(in); got != want {
			t.Errorf("groupName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExcludedPatterns(t *testing.T) {
	patterns := []string{"/health", "/notify*"}
	cases := map[string]bool{"/health": true, "/health/x": false, "/notify": true, "/notify/k": true, "/other": false}
	for path, want := range cases {
		if got := excluded(patterns, path); got != want {
			t.Errorf("excluded(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestExcludedMidLineWildcards(t *testing.T) {
	patterns := []string{"/static/*/thumb.png", "/a*b*c", "/*.json"}
	cases := map[string]bool{
		"/static/a/thumb.png":   true,
		"/static/a/b/thumb.png": true,
		"/static/thumb.png":     false,
		"/static/a/thumb.jpg":   false,
		"/abc":                  true,
		"/a1b2c":                true,
		"/acb":                  false,
		"/a/b/c":                true,
		"/ab":                   false,
		"/feed.json":            true,
		"/dir/feed.json":        true,
		"/feed.json.bak":        false,
	}
	for path, want := range cases {
		if got := excluded(patterns, path); got != want {
			t.Errorf("excluded(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestCaddyfileSiteBlock(t *testing.T) {
	var m UwUAuth
	d := caddyfile.NewTestDispenser("uwuauth {\n\texclude_paths /health* /ping\n}")
	if err := m.UnmarshalCaddyfile(d); err != nil {
		t.Fatal(err)
	}
	if strings.Join(m.ExcludePaths, ",") != "/health*,/ping" {
		t.Errorf("got exclude=%v", m.ExcludePaths)
	}
	var bad UwUAuth
	if err := bad.UnmarshalCaddyfile(caddyfile.NewTestDispenser("uwuauth {\n\tbasic_groups grafana\n}")); err == nil {
		t.Error("the removed basic_groups option is still accepted")
	}
}

func TestCaddyfileAppName(t *testing.T) {
	var m UwUAuth
	if err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser("uwuauth \"Writers Guild\" {\n\texclude_paths /health*\n}")); err != nil {
		t.Fatal(err)
	}
	if m.App != "Writers Guild" || strings.Join(m.ExcludePaths, ",") != "/health*" {
		t.Errorf("got app=%q exclude=%v", m.App, m.ExcludePaths)
	}
	var unquoted UwUAuth
	if err := unquoted.UnmarshalCaddyfile(caddyfile.NewTestDispenser("uwuauth Writers Guild")); err != nil {
		t.Fatal(err)
	}
	if unquoted.App != "Writers Guild" {
		t.Errorf("unquoted words joined to %q", unquoted.App)
	}
}

func TestGlobalBlock(t *testing.T) {
	d := caddyfile.NewTestDispenser("uwuauth {\n\tldap_base_dn dc=home,dc=example,dc=com\n\tldap_ca_file /ldap-tls/tls.crt\n\tapi_url http://uwuauth:8443\n\tapi_token secret\n}")
	if _, err := parseGlobalOption(d, nil); err != nil {
		t.Fatal(err)
	}
	if globalDefaults.LDAPBaseDN != "dc=home,dc=example,dc=com" || globalDefaults.LDAPCAFile != "/ldap-tls/tls.crt" ||
		globalDefaults.APIToken != "secret" {
		t.Errorf("globalDefaults = %+v", globalDefaults)
	}
	globalDefaults = uwuauthDefaults{}
}

func TestModuleIDAndValidate(t *testing.T) {
	if id := (UwUAuth{}).CaddyModule().ID; id != "http.handlers.uwuauth" {
		t.Errorf("module id %q", id)
	}
	m := &UwUAuth{ForwardAuthURL: "http://uwuauth:8443", APIURL: "::bad"}
	if err := m.Validate(); err == nil {
		t.Error("bad api_url validated")
	}
	var _ caddy.Module = m
}

// fakeAPI answers /uwu/v1/apps and /uwu/v1/groups, and counts calls.
//
//	Writers Guild: allowed "writers", no second factor.
//	Open:          no allowed groups (any signed-in person), no second factor.
//	Secure:        allowed "grafana", needs a second factor.
//	second-factor: a group whose members need a second factor.
func fakeAPI(t *testing.T, token string, calls *int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		*calls++
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/uwu/v1/apps":
			_, _ = w.Write([]byte(`[
				{"name":"Writers Guild","forwardAuth":["writersguild.example.com"],"allowedGroups":["g-writers"],"requireMfa":false},
				{"name":"Open","forwardAuth":["open.example.com/admin"],"allowedGroups":[],"requireMfa":false},
				{"name":"Secure","forwardAuth":["secure.example.com"],"allowedGroups":["g-grafana"],"requireMfa":true}
			]`))
		case "/uwu/v1/groups":
			_, _ = w.Write([]byte(`[
				{"id":"g-grafana","name":"grafana","requireMfa":false},
				{"id":"g-writers","name":"writers","requireMfa":false},
				{"id":"g-2fa","name":"second-factor","requireMfa":true}
			]`))
		case "/uwu/v1/app-passwords/check":
			switch r.Header.Get("X-App-Password") {
			case "good-secret":
				_, _ = w.Write([]byte(`{"username":"nyu","displayName":"Nyu","email":"nyu@example.com","groups":["writers"]}`))
			case "stranger-secret":
				_, _ = w.Write([]byte(`{"username":"kid","displayName":"Kid","email":null,"groups":["grafana"]}`))
			case "disabled-secret":
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"forbidden","detail":{"reason":"disabled"}}`))
			default:
				w.WriteHeader(http.StatusUnauthorized)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func apiGate(t *testing.T, calls *int) *UwUAuth {
	t.Helper()
	server := httptest.NewServer(fakeAPI(t, "tok", calls))
	t.Cleanup(server.Close)
	m := &UwUAuth{APIURL: server.URL, APIToken: "tok", logger: zap.NewNop()}
	m.client = &http.Client{}
	m.apps = newAppCache(appCacheTTL)
	return m
}

func TestAppRuleFromAPI(t *testing.T) {
	calls := 0
	m := apiGate(t, &calls)
	rule, err := m.appRule(context.Background(), "Writers Guild")
	if err != nil || strings.Join(rule.groups, ",") != "writers" || rule.requireMfa {
		t.Fatalf("got %+v, %v", rule, err)
	}
	// The second call is answered from the cache.
	rule, err = m.appRule(context.Background(), "Writers Guild")
	if err != nil || strings.Join(rule.groups, ",") != "writers" {
		t.Fatalf("cached: got %+v, %v", rule, err)
	}
	if calls != 2 {
		t.Errorf("api calls = %d, want 2 (apps and groups once)", calls)
	}
}

func TestNoAllowedGroupsMeansAnySignedInPerson(t *testing.T) {
	calls := 0
	m := apiGate(t, &calls)
	rule, err := m.appRule(context.Background(), "Open")
	if err != nil || len(rule.groups) != 0 {
		t.Errorf("got %+v, %v", rule, err)
	}
}

func TestSecondFactorAppRule(t *testing.T) {
	calls := 0
	m := apiGate(t, &calls)
	rule, err := m.appRule(context.Background(), "Secure")
	if err != nil || !rule.requireMfa {
		t.Fatalf("got %+v, %v", rule, err)
	}
	if strings.Join(rule.mfaGroups, ",") != "second-factor" {
		t.Errorf("mfaGroups = %v", rule.mfaGroups)
	}
}

func TestUnknownNameIsNoApp(t *testing.T) {
	calls := 0
	m := apiGate(t, &calls)
	for i := 0; i < 2; i++ {
		if _, err := m.appRule(context.Background(), "Nobody"); !errors.Is(err, errNoApp) {
			t.Fatalf("got %v, want errNoApp", err)
		}
	}
	if calls != 1 {
		t.Errorf("api calls = %d, want 1 (unknown hosts are cached too)", calls)
	}
}

func TestRejectedTokenIsAnError(t *testing.T) {
	calls := 0
	m := apiGate(t, &calls)
	m.APIToken = "wrong"
	if _, err := m.appRule(context.Background(), "Writers Guild"); err == nil || errors.Is(err, errNoApp) {
		t.Errorf("got %v, want an api error", err)
	}
}

func TestBuildRuleRejectsUnknownGroupID(t *testing.T) {
	_, err := buildRule(apiApp{AllowedGroups: []string{"g-missing"}}, nil)
	if err == nil {
		t.Error("an allowed group the groups list does not have was accepted")
	}
}

func TestFindAppByNameRefusesAmbiguity(t *testing.T) {
	apps := []apiApp{{Name: "Wiki"}, {Name: "Wiki"}, {Name: "Other"}}
	if _, err := findAppByName(apps, "Wiki"); err == nil || errors.Is(err, errNoApp) {
		t.Errorf("two apps with one name: got %v, want an error", err)
	}
	if got, err := findAppByName(apps, "Other"); err != nil || got.Name != "Other" {
		t.Errorf("got %+v, %v", got, err)
	}
	if _, err := findAppByName(apps, "wiki"); !errors.Is(err, errNoApp) {
		t.Errorf("names are compared exactly: got %v", err)
	}
}

func TestEnvPlaceholdersAreExpanded(t *testing.T) {
	t.Setenv("UWUAUTH_TEST_TOKEN", "uwu_example")
	if got := expand("{env.UWUAUTH_TEST_TOKEN}\n"); got != "uwu_example" {
		t.Errorf("expand = %q, want the environment's value", got)
	}
	if got := expand("plain"); got != "plain" {
		t.Errorf("expand(plain) = %q", got)
	}
}
