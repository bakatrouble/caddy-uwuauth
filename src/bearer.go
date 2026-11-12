package caddyuwuauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// isBearer reports whether the Authorization header uses the Bearer scheme.
func isBearer(authorization string) bool {
	scheme, _, found := strings.Cut(authorization, " ")
	return found && strings.EqualFold(scheme, "bearer")
}

// serveBearer takes `Authorization: Bearer <app password>`. The secret is
// checked by UwUAuth (GET /uwu/v1/app-passwords/check), which answers who it
// belongs to. The app's rules are the same as for Basic auth.
func (m *UwUAuth) serveBearer(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	_, secret, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	secret = strings.TrimSpace(secret)
	if secret == "" {
		unauthorized(w)
		return nil
	}
	if !m.configuredForAPIClients(w) {
		return nil
	}
	rule, ok := m.ruleFor(w, r)
	if !ok {
		return nil
	}
	if rule.requireMfa {
		refuseSecondFactor(w, m.logger, r.Host)
		return nil
	}
	who, err := m.checkAppPassword(r.Context(), secret)
	switch {
	case errors.Is(err, errBadLogin):
		unauthorized(w)
		return nil
	case errors.Is(err, errRefused):
		http.Error(w, "This account may not sign in now.", http.StatusForbidden)
		return nil
	case err != nil:
		m.logger.Error("bearer sign-in: api failed", zap.Error(err))
		http.Error(w, "Sign-in is unavailable.", http.StatusBadGateway)
		return nil
	}
	return m.admit(w, r, next, rule, who)
}

// checkAppPassword asks UwUAuth about one app password. The secret travels in
// X-App-Password, never in a log line.
func (m *UwUAuth) checkAppPassword(ctx context.Context, secret string) (*identity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.APIURL+"/uwu/v1/app-passwords/check", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+m.APIToken)
	req.Header.Set("X-App-Password", secret)
	req.Header.Set("Accept", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUnavailable, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var answer struct {
			Username    string   `json:"username"`
			DisplayName string   `json:"displayName"`
			Email       string   `json:"email"`
			Groups      []string `json:"groups"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&answer); err != nil {
			return nil, fmt.Errorf("%w: %w", errUnavailable, err)
		}
		return &identity{username: answer.Username, email: answer.Email, name: answer.DisplayName, groups: answer.Groups}, nil
	case http.StatusUnauthorized:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, errBadLogin
	case http.StatusForbidden:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, errRefused
	default:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("%w: status %d", errUnavailable, resp.StatusCode)
	}
}
