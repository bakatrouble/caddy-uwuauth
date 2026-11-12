package caddyuwuauth

import (
	"io"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// serveForward asks UwUAuth's forward-auth endpoint about the request, with
// the browser's cookies and the address it asked for. UwUAuth answers 200
// (with the person in Remote-* headers), a redirect to sign in, or 403.
func (m *UwUAuth) serveForward(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, m.ForwardAuthURL+"/uwu/v1/forward-auth", nil)
	if err != nil {
		return upstreamDown(w, m.logger, err)
	}
	// Set, not add: a value the client sent cannot sit in front of ours.
	req.Header.Set("X-Forwarded-Proto", scheme(r))
	req.Header.Set("X-Forwarded-Host", r.Host)
	req.Header.Set("X-Forwarded-Uri", r.URL.RequestURI())
	req.Header.Set("X-Forwarded-Method", r.Method)
	if cookies := r.Header.Values("Cookie"); len(cookies) > 0 {
		req.Header.Set("Cookie", strings.Join(cookies, "; "))
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return upstreamDown(w, m.logger, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		for _, name := range remoteHeaders {
			if value := resp.Header.Get(name); value != "" {
				r.Header.Set(name, value)
			}
		}
		return next.ServeHTTP(w, r)
	case http.StatusFound, http.StatusSeeOther:
		for _, cookie := range resp.Header.Values("Set-Cookie") {
			w.Header().Add("Set-Cookie", cookie)
		}
		w.Header().Set("Location", resp.Header.Get("Location"))
		w.WriteHeader(resp.StatusCode)
		return nil
	case http.StatusForbidden:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write(body)
		return nil
	default:
		m.logger.Error("forward auth answered an unexpected status", zap.Int("status", resp.StatusCode))
		http.Error(w, "Sign-in is unavailable.", http.StatusBadGateway)
		return nil
	}
}

// scheme is the scheme the browser used, as Caddy saw it.
func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func upstreamDown(w http.ResponseWriter, logger *zap.Logger, err error) error {
	logger.Error("forward auth is unreachable", zap.Error(err))
	http.Error(w, "Sign-in is unavailable.", http.StatusBadGateway)
	return nil
}
