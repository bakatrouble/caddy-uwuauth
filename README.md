# caddy-uwuauth

A Caddy handler that gates a site behind UwUAuth. It replaces an Authelia gate with two changes of method:

- **Browsers** use UwUAuth's forward-auth endpoint (`/uwu/v1/forward-auth`). There is no OIDC client, no client secret and no callback on the app side. UwUAuth answers 200 (with the person in `Remote-*` headers), a redirect to sign-in, or 403.
- **API clients** have two ways in, both with an app password (or the account password for Basic, see below):
  - `Authorization: Basic` binds to UwUAuth's LDAPS listener as the person.
  - `Authorization: Bearer <app password>` is checked by UwUAuth's `GET /uwu/v1/app-passwords/check`, which answers the name and groups from the secret alone.

Caddy only passes `Remote-*` headers that UwUAuth set; any value a client sends under those names is dropped first.

## Server side

The plugin needs two things from UwUAuth that are not in the upstream release yet. Both are in our fork:

- Fork branch **`working-copy`** (`bakatrouble/UwUAuth-Server`): PR #21 and PR #22 merged, the build in use. Commit `a851cd7`.
- **MinifyX/UwUAuth-Server#21** (draft): admin API tokens may read and change groups. Without it the plugin cannot read an app's groups with its token.
- **MinifyX/UwUAuth-Server#22** (draft): `GET /uwu/v1/app-passwords/check`, which Bearer sign-in uses.

The PRs are drafts for review. Until they are merged upstream, run the server from `working-copy`.

## Configuration

There are two parts: one global block for the shared settings, and one directive per site. The directive can go in the Caddyfile or in container labels.

Global, once in the base Caddyfile:

```caddyfile
{
	uwuauth {
		forward_auth_url http://uwuauth:8443
		ldap_address uwuauth:10636
		ldap_ca_file /ldap-tls/tls.crt
		ldap_base_dn dc=example,dc=com
		api_url http://uwuauth:8443
		api_token {env.UWUAUTH_TOKEN}
	}
}
```

Per site, in the Caddyfile:

```caddyfile
app.example.com {
	uwuauth "App Name" {
		exclude_paths /health* /static/*/thumb.png
	}
	reverse_proxy app:8000
}
```

Per site, with caddy-docker-proxy labels:

```yaml
labels:
  caddy: app.example.com
  caddy.reverse_proxy: "{{upstreams 8000}}"
  caddy.uwuauth: "App Name"
  caddy.uwuauth.exclude_paths: /health*
```

The directive runs before `reverse_proxy` wherever it is written, so no `order` line is needed. The argument is the name of the UwUAuth app the site is. Several words are joined by spaces, so the quotes are optional. The name must match the app's name in UwUAuth exactly. API-client sign-in reads the app's groups and second-factor rules by it. A name that no app has, or that two apps share, refuses API clients: the plugin never guesses which app a site means. Browsers do not need the name, and a site without one still gets the forward-auth gate.

- `exclude_paths`: paths that bypass the gate. A pattern without `*` must match exactly. Each `*` matches any run of characters, slashes included, anywhere in the pattern: `/health*`, `/static/*/thumb.png`.

Global defaults: `forward_auth_url` and `api_url` are `http://uwuauth:8443`, and `ldap_address` is `uwuauth:10636`. `ldap_ca_file` must hold the certificate UwUAuth's LDAPS presents when it is self-signed. `{env.X}` placeholders in the global block are expanded at startup.

`api_token` is an API token of an admin in UwUAuth (the portal's _API tokens_). A read-only token is enough: the plugin only reads apps, groups and app-password checks. Pass it to Caddy through the environment, and keep it out of the Caddyfile. API-client sign-in refuses requests while it is unset.

## Who may sign in

For API clients, the app is the one named by the site's directive argument. Its rules are read from UwUAuth's API:

- **Allowed groups.** An app with none lets any signed-in person in, as for browsers. Otherwise the person must be in one of them.
- **Second factor.** Both Basic and Bearer are one factor. They are refused for an app that requires a second factor, and for a person who is in a group that requires one. The check runs before any password is checked.

## Network

Caddy and UwUAuth must share a Docker network for forward auth and the API (port 8443), and a second network for LDAPS (port 10636). The CA file for LDAPS is mounted read-only into Caddy.

## Limits

- API-client sign-in checks identity, the app's allowed groups and the second-factor rules. Time windows, which UwUAuth applies to browsers, are not evaluated for API clients.
- Basic makes an LDAP bind per request. Bearer makes one check request per request. Neither caches a successful sign-in.
- The app's rule is cached for a minute. A portal change applies to API clients within that time.
- The app's rule is looked up by name. Renaming an app in UwUAuth breaks API-client sign-in for every site that names it until the directive is changed.
- The API is reached over plain HTTP on the internal network, as forward auth is.

## Development

```
go vet ./... && go test ./...
```

The tests cover the forward-auth outcomes (200, redirect, 403, unexpected answer), header spoofing, exclusions, both API-client schemes (wrong and missing secrets, groups, refusals, second factor, a missing token, no app name, an unknown name), the API lookup (group IDs to names, caching, unknown names, rejected token, ambiguous names), env expansion and the directive's options in both forms. The LDAPS bind is not covered by a unit test; check it against a live UwUAuth. Both Caddyfile forms were also checked by adapting them with the built image.
