// Package caddyuwuauth is the Caddy module for UwUAuth. The handler lives in
// src/; this root package exists so xcaddy can build it with
// `--with github.com/bakatrouble/caddy-uwuauth=.`.
// See README.md for configuration and the UwUAuth server side.
package caddyuwuauth

import (
	_ "github.com/bakatrouble/caddy-uwuauth/src"
)
