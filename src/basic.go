package caddyuwuauth

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
)

var (
	errBadLogin     = errors.New("bad login")
	errUnavailable  = errors.New("ldap or api unavailable")
	errRefused      = errors.New("refused by uwuauth")
	usernamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// identity is what UwUAuth says about a person who signed in with a password
// or an app password.
type identity struct {
	username string
	email    string
	name     string
	groups   []string
}

func isBasic(authorization string) bool {
	scheme, _, found := strings.Cut(authorization, " ")
	return found && strings.EqualFold(scheme, "basic")
}

// serveBasic checks a Basic header with a simple LDAP bind as the person.
func (m *UwUAuth) serveBasic(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	user, password, ok := r.BasicAuth()
	if !ok {
		unauthorized(w)
		return nil
	}
	if !m.configuredForAPIClients(w) {
		return nil
	}
	// Basic auth is one factor. An app that asks for a second factor is refused
	// before the password is checked at all.
	rule, ok := m.ruleFor(w, r)
	if !ok {
		return nil
	}
	if rule.requireMfa {
		refuseSecondFactor(w, m.logger, r.Host)
		return nil
	}
	who, err := m.ldapLogin(user, password)
	switch {
	case errors.Is(err, errBadLogin):
		m.logger.Info("basic auth refused", zap.String("user", user))
		unauthorized(w)
		return nil
	case err != nil:
		m.logger.Error("basic auth: ldap failed", zap.Error(err))
		http.Error(w, "Sign-in is unavailable.", http.StatusBadGateway)
		return nil
	}
	return m.admit(w, r, next, rule, who)
}

// configuredForAPIClients refuses API-client sign-in when the plugin lacks
// what it needs (the API token and the LDAP base). It writes the answer.
func (m *UwUAuth) configuredForAPIClients(w http.ResponseWriter) bool {
	if m.APIToken != "" && m.LDAPBaseDN != "" {
		return true
	}
	m.logger.Error("api client sign-in needs api_token and ldap_base_dn")
	http.Error(w, "Sign-in for API clients is not enabled for this site.", http.StatusForbidden)
	return false
}

// ruleFor reads the rule of the app this site names (the label's argument). It
// writes the answer when there is none.
func (m *UwUAuth) ruleFor(w http.ResponseWriter, r *http.Request) (appRule, bool) {
	if m.App == "" {
		m.logger.Error("api client sign-in needs the app name on this site")
		http.Error(w, "This site names no UwUAuth app.", http.StatusForbidden)
		return appRule{}, false
	}
	rule, err := m.appRule(r.Context(), m.App)
	switch {
	case errors.Is(err, errNoApp):
		m.logger.Error("api client sign-in: no UwUAuth app has the configured name", zap.String("app", m.App))
		http.Error(w, "The UwUAuth app for this site does not exist.", http.StatusForbidden)
		return appRule{}, false
	case err != nil:
		m.logger.Error("api client sign-in: api failed", zap.Error(err))
		http.Error(w, "Sign-in is unavailable.", http.StatusBadGateway)
		return appRule{}, false
	}
	return rule, true
}

// admit lets a signed-in API client through when the app's group rules allow
// it, and sets the Remote-* headers for the app.
func (m *UwUAuth) admit(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, rule appRule, who *identity) error {
	// A group of the person that needs a second factor counts the same way.
	if anyOf(who.groups, rule.mfaGroups) {
		m.logger.Info("api client refused: a group of the person needs a second factor", zap.String("user", who.username))
		http.Error(w, "A group you are in needs a second factor; API sign-in is one factor only.", http.StatusForbidden)
		return nil
	}
	if len(rule.groups) > 0 && !anyOf(who.groups, rule.groups) {
		http.Error(w, "You may not use this app.", http.StatusForbidden)
		return nil
	}
	r.Header.Set("Remote-User", who.username)
	r.Header.Set("Remote-Groups", strings.Join(who.groups, ","))
	r.Header.Set("Remote-Email", who.email)
	r.Header.Set("Remote-Name", who.name)
	return next.ServeHTTP(w, r)
}

// refuseSecondFactor answers for an app that asks for a second factor.
func refuseSecondFactor(w http.ResponseWriter, logger *zap.Logger, host string) {
	logger.Info("api client refused: app needs a second factor", zap.String("host", host))
	http.Error(w, "This app needs a second factor; API sign-in is one factor only.", http.StatusForbidden)
}

// ldapLogin binds as the person over LDAPS and reads their own entry.
func (m *UwUAuth) ldapLogin(username, password string) (*identity, error) {
	if !usernamePattern.MatchString(username) || password == "" {
		return nil, errBadLogin
	}
	dn := "uid=" + username + ",ou=people," + m.LDAPBaseDN
	dialer := &net.Dialer{Timeout: upstreamTimeout}
	conn, err := ldap.DialURL("ldaps://"+m.LDAPAddress,
		ldap.DialWithDialer(dialer), ldap.DialWithTLSConfig(m.ldapTLS))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUnavailable, err)
	}
	defer conn.Close()
	conn.SetTimeout(upstreamTimeout)
	if err := conn.Bind(dn, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return nil, errBadLogin
		}
		return nil, fmt.Errorf("%w: %w", errUnavailable, err)
	}
	search := ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, int(upstreamTimeout/time.Second),
		false, "(objectClass=*)", []string{"mail", "displayName", "memberOf"}, nil)
	res, err := conn.Search(search)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUnavailable, err)
	}
	if len(res.Entries) != 1 {
		return nil, errBadLogin
	}
	entry := res.Entries[0]
	who := &identity{
		username: username,
		email:    entry.GetAttributeValue("mail"),
		name:     entry.GetAttributeValue("displayName"),
	}
	for _, groupDN := range entry.GetAttributeValues("memberOf") {
		if name := groupName(groupDN); name != "" {
			who.groups = append(who.groups, name)
		}
	}
	return who, nil
}

// groupName is the cn of a group DN (cn=<name>,ou=groups,<base>). Group names
// cannot hold commas, so the cn ends at the first one.
func groupName(groupDN string) string {
	if len(groupDN) < 3 || !strings.EqualFold(groupDN[:3], "cn=") {
		return ""
	}
	name, _, _ := strings.Cut(groupDN[3:], ",")
	return name
}

func anyOf(have, want []string) bool {
	for _, g := range have {
		for _, w := range want {
			if g == w {
				return true
			}
		}
	}
	return false
}

// unauthorized asks for either scheme: an API client may use Basic or Bearer.
func unauthorized(w http.ResponseWriter) {
	w.Header().Add("WWW-Authenticate", `Basic realm="UwUAuth"`)
	w.Header().Add("WWW-Authenticate", `Bearer realm="UwUAuth"`)
	http.Error(w, "Sign in with your UwUAuth name and password, or an app password.", http.StatusUnauthorized)
}
