package caddyuwuauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// appCacheTTL is how long an app's rule is kept. A change in the portal takes
// effect for API clients within this time.
const appCacheTTL = time.Minute

// errNoApp means no UwUAuth app has the name this site gives.
var errNoApp = errors.New("no app with this name")

// apiApp is what UwUAuth's GET /uwu/v1/apps says about an app: its name, the
// groups allowed in (by ID; none means any signed-in person), and whether it
// asks for a second factor.
type apiApp struct {
	Name          string   `json:"name"`
	AllowedGroups []string `json:"allowedGroups"`
	RequireMfa    bool     `json:"requireMfa"`
}

// apiGroup is one of GET /uwu/v1/groups: its ID, name, and whether its members
// need a second factor.
type apiGroup struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	RequireMfa bool   `json:"requireMfa"`
}

// appRule is what API-client sign-in needs to know about an app. Basic and
// Bearer each supply one factor, so an app that needs a second factor (or a
// group of the person that does) cannot be used with them.
type appRule struct {
	groups     []string // allowed group names; none means any signed-in person
	requireMfa bool     // the app asks for a second factor
	mfaGroups  []string // groups whose members need a second factor
}

// appRule returns the rule for the app with this name. errNoApp means there is
// no such app; a name held by more than one app is an error, so the plugin
// never guesses which one a site means.
func (m *UwUAuth) appRule(ctx context.Context, name string) (appRule, error) {
	if entry, ok := m.apps.get(name); ok {
		if entry.missing {
			return appRule{}, errNoApp
		}
		return entry.rule, nil
	}
	var apps []apiApp
	if err := m.apiGet(ctx, "/uwu/v1/apps", &apps); err != nil {
		return appRule{}, err
	}
	app, err := findAppByName(apps, name)
	if errors.Is(err, errNoApp) {
		m.apps.putMissing(name)
		return appRule{}, errNoApp
	}
	if err != nil {
		return appRule{}, err
	}
	var groups []apiGroup
	if err := m.apiGet(ctx, "/uwu/v1/groups", &groups); err != nil {
		return appRule{}, err
	}
	rule, err := buildRule(app, groups)
	if err != nil {
		return appRule{}, err
	}
	m.apps.put(name, rule)
	return rule, nil
}

// buildRule maps the app's allowed group IDs to names and collects the groups
// that need a second factor.
func buildRule(app apiApp, groups []apiGroup) (appRule, error) {
	names := make(map[string]string, len(groups))
	rule := appRule{requireMfa: app.RequireMfa}
	for _, g := range groups {
		names[g.ID] = g.Name
		if g.RequireMfa {
			rule.mfaGroups = append(rule.mfaGroups, g.Name)
		}
	}
	for _, id := range app.AllowedGroups {
		name, ok := names[id]
		if !ok {
			return appRule{}, fmt.Errorf("uwuauth: app allows group %s, which the groups list does not have", id)
		}
		rule.groups = append(rule.groups, name)
	}
	return rule, nil
}

// findAppByName returns the one app called name. Names are compared exactly.
func findAppByName(apps []apiApp, name string) (apiApp, error) {
	var found []apiApp
	for _, app := range apps {
		if app.Name == name {
			found = append(found, app)
		}
	}
	switch len(found) {
	case 0:
		return apiApp{}, errNoApp
	case 1:
		return found[0], nil
	default:
		return apiApp{}, fmt.Errorf("uwuauth: %d apps are called %q; rename them", len(found), name)
	}
}

// apiGet reads a JSON answer of UwUAuth's API with the token. The token is
// never logged.
func (m *UwUAuth) apiGet(ctx context.Context, path string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.APIURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+m.APIToken)
	req.Header.Set("Accept", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("uwuauth api: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("uwuauth api %s: status %d", path, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(into)
}

// appCache keeps what was learned about app names for a while.
type appCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]cacheEntry
}

type cacheEntry struct {
	rule    appRule
	missing bool
	expires time.Time
}

func newAppCache(ttl time.Duration) *appCache {
	return &appCache{ttl: ttl, entries: map[string]cacheEntry{}}
}

func (c *appCache) get(name string) (cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[name]
	if !ok || time.Now().After(entry.expires) {
		delete(c.entries, name)
		return cacheEntry{}, false
	}
	return entry, true
}

func (c *appCache) put(name string, rule appRule) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[name] = cacheEntry{rule: rule, expires: time.Now().Add(c.ttl)}
}

func (c *appCache) putMissing(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[name] = cacheEntry{missing: true, expires: time.Now().Add(c.ttl)}
}
