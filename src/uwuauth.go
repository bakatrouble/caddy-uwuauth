// Package caddyuwuauth gates a Caddy site behind UwUAuth.
//
// Browsers go through UwUAuth's forward-auth endpoint (/uwu/v1/forward-auth):
// no client secret, no callback of our own; UwUAuth decides and says who the
// person is, and this handler passes that on as Remote-* headers. A request
// with an Authorization: Basic header is checked against UwUAuth's LDAP
// listener instead (a simple bind as the person), and the app's allowed groups
// come from UwUAuth's API.
//
// Configuration is two-tier: one global block for the shared addresses, and
// per site one directive. Remote-* headers are always set here, from UwUAuth
// only, so a client cannot send its own.
//
//	{
//		uwuauth {
//			forward_auth_url http://uwuauth:8443
//			ldap_address uwuauth:10636
//			ldap_ca_file /ldap-tls/tls.crt
//			ldap_base_dn dc=example,dc=com
//			api_url http://uwuauth:8443
//			api_token {env.UWUAUTH_TOKEN}
//		}
//		order uwuauth before reverse_proxy
//	}
//
//	labels:
//	  caddy: app.example.com
//	  caddy.uwuauth: "App Name"
//	  caddy.reverse_proxy: "{{upstreams 8000}}"
package caddyuwuauth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

const (
	defaultForwardAuthURL = "http://uwuauth:8443"
	defaultLDAPAddress    = "uwuauth:10636"
	defaultAPIURL         = "http://uwuauth:8443"
	upstreamTimeout       = 10 * time.Second
)

// remoteHeaders are the headers UwUAuth sets for the app. Anything the client
// sent under these names is dropped before the request goes on.
var remoteHeaders = []string{"Remote-User", "Remote-Groups", "Remote-Email", "Remote-Name"}

func init() {
	caddy.RegisterModule(UwUAuth{})
	httpcaddyfile.RegisterHandlerDirective("uwuauth", parseCaddyfile)
	// The gate runs before the proxy, so a site block can use the directive
	// without an `order` line in the global block.
	httpcaddyfile.RegisterDirectiveOrder("uwuauth", httpcaddyfile.Before, "reverse_proxy")
	httpcaddyfile.RegisterGlobalOption("uwuauth", parseGlobalOption)
}

// UwUAuth is the handler: forward auth for browsers, LDAP for Basic auth.
type UwUAuth struct {
	// Where UwUAuth listens for forward auth, reachable from Caddy.
	ForwardAuthURL string `json:"forward_auth_url,omitempty"`
	// LDAPS address of UwUAuth (host:port), for Basic auth.
	LDAPAddress string `json:"ldap_address,omitempty"`
	// PEM file with the certificate UwUAuth's LDAPS presents (self-signed is
	// fine). Empty trusts the system roots only.
	LDAPCAFile string `json:"ldap_ca_file,omitempty"`
	// Base DN of the directory, e.g. dc=example,dc=com. Required
	// for Basic auth.
	LDAPBaseDN string `json:"ldap_base_dn,omitempty"`
	// UwUAuth's API, for the app's allowed groups (Basic auth) and a token
	// that may read apps and groups (an admin's API token).
	APIURL   string `json:"api_url,omitempty"`
	APIToken string `json:"api_token,omitempty"`
	// Paths that bypass the gate: exact paths, or patterns with * (see excluded).
	ExcludePaths []string `json:"exclude_paths,omitempty"`
	// The name of the UwUAuth app this site is. API-client sign-in reads the
	// app's groups and second-factor rules by it. Browsers do not need it.
	App string `json:"app,omitempty"`

	logger  *zap.Logger
	client  *http.Client
	ldapTLS *tls.Config
	apps    *appCache
}

var (
	_ caddy.Module                = (*UwUAuth)(nil)
	_ caddy.Provisioner           = (*UwUAuth)(nil)
	_ caddy.Validator             = (*UwUAuth)(nil)
	_ caddyhttp.MiddlewareHandler = (*UwUAuth)(nil)
	_ caddyfile.Unmarshaler       = (*UwUAuth)(nil)
)

// CaddyModule returns the Caddy module information.
func (UwUAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.uwuauth",
		New: func() caddy.Module { return new(UwUAuth) },
	}
}

// Provision fills unset fields from the global block and prepares clients.
func (m *UwUAuth) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	m.applyGlobalDefaults()
	// Caddy hands global options over with {env.X} unexpanded; the token would
	// otherwise be sent as the literal placeholder.
	m.APIToken = expand(m.APIToken)
	m.LDAPCAFile = expand(m.LDAPCAFile)
	m.LDAPBaseDN = expand(m.LDAPBaseDN)
	m.client = &http.Client{
		Timeout: upstreamTimeout,
		// UwUAuth's redirect is the answer; never follow it.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	tlsConfig, err := ldapTLSConfig(m.LDAPAddress, m.LDAPCAFile)
	if err != nil {
		return err
	}
	m.ldapTLS = tlsConfig
	m.apps = newAppCache(appCacheTTL)
	return nil
}

// Validate checks the configuration that Provision cannot fix by itself.
func (m *UwUAuth) Validate() error {
	if _, err := url.Parse(m.ForwardAuthURL); err != nil || m.ForwardAuthURL == "" {
		return fmt.Errorf("uwuauth: forward_auth_url is not a URL")
	}
	if m.APIURL != "" {
		if _, err := url.Parse(m.APIURL); err != nil {
			return fmt.Errorf("uwuauth: api_url is not a URL")
		}
	}
	return nil
}

// ServeHTTP answers the request, or hands it on to next once UwUAuth lets it in.
func (m *UwUAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	for _, name := range remoteHeaders {
		r.Header.Del(name)
	}
	if excluded(m.ExcludePaths, r.URL.Path) {
		return next.ServeHTTP(w, r)
	}
	auth := r.Header.Get("Authorization")
	switch {
	case isBasic(auth):
		return m.serveBasic(w, r, next)
	case isBearer(auth):
		return m.serveBearer(w, r, next)
	}
	return m.serveForward(w, r, next)
}

// applyGlobalDefaults copies the global block's values into unset fields.
func (m *UwUAuth) applyGlobalDefaults() {
	g := globalDefaults
	if m.ForwardAuthURL == "" {
		m.ForwardAuthURL = firstNonEmpty(g.ForwardAuthURL, defaultForwardAuthURL)
	}
	if m.LDAPAddress == "" {
		m.LDAPAddress = firstNonEmpty(g.LDAPAddress, defaultLDAPAddress)
	}
	if m.LDAPCAFile == "" {
		m.LDAPCAFile = g.LDAPCAFile
	}
	if m.LDAPBaseDN == "" {
		m.LDAPBaseDN = g.LDAPBaseDN
	}
	if m.APIURL == "" {
		m.APIURL = firstNonEmpty(g.APIURL, defaultAPIURL)
	}
	if m.APIToken == "" {
		m.APIToken = g.APIToken
	}
}

// expand replaces {env.X} placeholders with the environment's values, as Caddy
// does for its own options.
func expand(value string) string {
	return caddy.NewReplacer().ReplaceAll(strings.TrimSpace(value), "")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// ldapTLSConfig trusts the CA file if one is given, and checks the host name
// of the LDAPS address against the certificate.
func ldapTLSConfig(address, caFile string) (*tls.Config, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("uwuauth: ldap_address %q: %w", address, err)
	}
	config := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if caFile == "" {
		return config, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("uwuauth: ldap_ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("uwuauth: ldap_ca_file holds no certificate")
	}
	config.RootCAs = pool
	return config, nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m UwUAuth
	if err := m.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return &m, nil
}

// UnmarshalCaddyfile reads the per-site directive: the app's name as its
// argument (several words are joined by spaces), and the block's exclude_paths.
func (m *UwUAuth) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // directive name
	if args := d.RemainingArgs(); len(args) > 0 {
		m.App = strings.Join(args, " ")
	}
	for d.NextBlock(0) {
		switch d.Val() {
		case "exclude_paths":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			m.ExcludePaths = append(m.ExcludePaths, args...)
		default:
			return d.Errf("unknown uwuauth option '%s'", d.Val())
		}
	}
	return nil
}

var globalDefaults uwuauthDefaults

type uwuauthDefaults struct {
	ForwardAuthURL string
	LDAPAddress    string
	LDAPCAFile     string
	LDAPBaseDN     string
	APIURL         string
	APIToken       string
}

func parseGlobalOption(d *caddyfile.Dispenser, _ any) (any, error) {
	d.Next() // uwuauth
	if len(d.RemainingArgs()) > 0 {
		return nil, d.ArgErr()
	}
	var g uwuauthDefaults
	for d.NextBlock(0) {
		var dst *string
		switch d.Val() {
		case "forward_auth_url":
			dst = &g.ForwardAuthURL
		case "ldap_address":
			dst = &g.LDAPAddress
		case "ldap_ca_file":
			dst = &g.LDAPCAFile
		case "ldap_base_dn":
			dst = &g.LDAPBaseDN
		case "api_url":
			dst = &g.APIURL
		case "api_token":
			dst = &g.APIToken
		default:
			return nil, d.Errf("unknown global uwuauth option '%s'", d.Val())
		}
		if !d.NextArg() {
			return nil, d.ArgErr()
		}
		*dst = d.Val()
		if d.NextArg() {
			return nil, d.ArgErr()
		}
	}
	globalDefaults = g
	return g, nil
}
