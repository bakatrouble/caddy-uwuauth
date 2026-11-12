package caddyuwuauth

import "strings"

// excluded reports whether path matches one of the patterns. A pattern without
// `*` must match exactly. In a pattern, each `*` matches any run of characters,
// slashes included, so `/notify*` covers `/notify/abc` and `/static/*/thumb.png`
// covers `/static/a/b/thumb.png`.
func excluded(patterns []string, path string) bool {
	for _, pattern := range patterns {
		if globMatch(pattern, path) {
			return true
		}
	}
	return false
}

// globMatch matches s against a pattern whose only wildcard is `*`. The match
// is anchored at both ends: the text before the first `*` must start s, the text
// after the last `*` must end it, and the pieces in between must occur in order.
func globMatch(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	first, last := parts[0], parts[len(parts)-1]
	if len(s) < len(first)+len(last) || !strings.HasPrefix(s, first) || !strings.HasSuffix(s, last) {
		return false
	}
	s = s[len(first) : len(s)-len(last)]
	for _, piece := range parts[1 : len(parts)-1] {
		at := strings.Index(s, piece)
		if at < 0 {
			return false
		}
		s = s[at+len(piece):]
	}
	return true
}
