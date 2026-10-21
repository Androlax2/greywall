# Proxy client secret per sandbox (design)

Todo: f2737f68, "Security: proxy clients are identified by username only (password "proxy")".
Spans three repos: greywall (Androlax2/greywall), greyproxy (Androlax2/greyproxy), dotfiles
(agent-docker@.service). Each repo is built on Theo's machine from its fork's `dotfiles` branch;
each change also goes upstream as its own PR.

## Why

greyproxy decides which rules, approvals, session-scoped rules and allow-all apply to a proxy
connection from the login name alone:

- greywall sets the proxy URL to `<name>:proxy@...`, where `<name>` is `--proxy-user` or the
  wrapped command (`opencode`, `claude`), and the password is always the literal `proxy`
  (`cmd/greywall/main.go`, `proxyIdentity` and the loop after it).
- Docker clients use `<project>-docker:proxy` (dotfiles, `agent-docker@.service`).
- greyproxy's auther accepts every login (`internal/greyproxy/plugins/auther.go`,
  `Authenticate` always returns `ok=true`), and `ResolveIdentity` turns the username into the
  container name that rules and sessions match on.

The name is visible inside every sandbox (`GREYWALL_CONFIG_JSON`, `HTTP_PROXY`). An agent that is
told to (prompt injection) can log in as another client (`jobpilot-docker`, `claude`) and get that
client's allowlist, approvals and session rules, including allow-all from a `--learning` session.

## Goal

A proxy connection only gets a client's rules if it proves it is that client: it presents the
secret that was registered for that name, and nobody else knows that secret.

## Non-goals

- Telling apart two sandboxes that use the same name (two `opencode` sessions in two projects).
  They share rules today and keep sharing them. Separate names per project are dotfiles todo
  13063bf8.
- Protecting a sandbox's secret from processes inside the same sandbox.
- Encrypting proxy traffic between the sandbox and greyproxy (it stays on loopback).

## Anti-goals (a failure even if it technically works)

- A sandbox that can still talk to greyproxy's API. It could register its own secret for any
  name. See "Prerequisite".
- A fail-open path: a known name with a missing or wrong secret must be refused, never fall back
  to the name's rules.
- Breaking sessions that run today when the fork's greyproxy is not updated yet: greywall must
  keep working against an older greyproxy (it just gets no protection).

## Prerequisite (blocking)

greyproxy seeds built-in allow rules for every client to `127.0.0.1`, `::1` and `localhost` on all
ports (`internal/greyproxy/migrations.go`, migration 12), and its API on `127.0.0.1:43080` has no
authentication (`internal/greyproxy/api/router.go`). A sandbox can likely reach the API through the
proxy and register a secret, enable allow-all, or create rules. This design is worthless until that
is fixed. Tracked in greyproxy's list: "Security: built-in localhost rule lets every sandbox reach
the unauthenticated API". It must merge first.

Theo chose both layers for that fix:

1. greyproxy refuses proxied connections to its own listeners (API 43080, proxies 43051 and 43052,
   DNS 43053, and whatever ports the running config uses) on loopback, whatever the rules say,
   built-in or user rules alike.
2. The API requires a token. greyproxy creates it on first start in its data dir (`api-token`,
   mode 0600, random 32 bytes), and every `/api/*` call must send `Authorization: Bearer <token>`.
   The dashboard keeps working for the host user (how it authenticates is left to the greyproxy
   builder; it must not weaken the API check). Sandboxes cannot read the file: greywall masks the
   whole data dir (#103), so the token file needs no special handling there.

Consequences for this design:

- greywall reads the token from greyproxy's data dir (same lookup as `SensitiveGreyproxyDirs`,
  including `XDG_DATA_HOME`) on the host side, before the sandbox starts, and sends it on
  `RegisterSession`, the heartbeat and session delete. No token file: send no header (older
  greyproxy). Token present but refused (401): log it and treat it as a failed registration.
- The Docker service sends the token the same way.
- Order: the token check must not be enabled before greywall sends it, or every sandbox loses its
  session registration (credential substitution included). In greyproxy, add the token check
  behind a setting that the fork turns on in step 4, or ship greywall's token support first.

The session table in `greyproxy.db` will hold secret hashes. greywall already hides greyproxy's
data dir from sandboxes (#103, on the fork's `dotfiles` branch).

## Design

### Contract between greywall and greyproxy

1. `POST /api/sessions` gets one new optional field, `client_secret` (string). When present,
   greyproxy stores `sha256(client_secret)` on the session row, never the secret itself, and never
   returns it from any endpoint (`GET /api/sessions` included).
2. A login `name:password` is checked in the auther:
   - If at least one live session (not expired) has `container_name = name` and a secret hash,
     the password must hash to one of those live hashes (constant-time compare). Otherwise the
     auther returns `ok=false` and gost refuses the SOCKS5 handshake or answers HTTP 407.
   - If no live session for `name` has a secret: behavior depends on `requireClientSecret`
     (below).
3. A new greyproxy setting `requireClientSecret` (bool, `greyproxy.yml` under `greyproxy:`, and a
   matching CLI flag). Default `false` upstream so existing users keep working. The fork's
   dotfiles config sets it to `true`.
   - `false`: a name with no secret-bearing session is accepted as today.
   - `true`: such a login is refused, except names listed in `clientSecretExempt` (list of exact
     names, default empty), and the anonymous login (empty user or `proxy`) while
     `allowAnonymousClients` is true.
   - `allowAnonymousClients` (bool, default `true`): when `false` and `requireClientSecret` is on,
     the anonymous login is refused too. Otherwise it keeps mapping to `unknown-<ip>` and its own
     rules, as today.

   Theo believes nothing besides greywall sandboxes and the Docker service uses greyproxy, but is
   not sure. Rollout: the fork turns on `requireClientSecret` with `allowAnonymousClients: true`
   first. Before turning anonymous logins off, check greyproxy's request log for client names that
   are neither a greywall command name nor `<project>-docker`, and for `unknown-*` entries, over
   about a week (a SQL query on `request_logs.container_name` in `greyproxy.db`, run by the host
   user). If none show up, set `allowAnonymousClients: false`. This check and the switch belong to
   the dotfiles session.
4. Secrets expire with their session (TTL and heartbeat already exist). A sandbox whose session
   expired is refused until greywall re-registers it; that is intended (fail closed).
5. A login whose name starts with `unknown-` is always refused: `ResolveIdentity` uses that prefix
   for anonymous clients, so accepting it as a name would let a client claim an anonymous
   identity's rules. (Designer's call.)
6. `POST /api/sessions` currently rejects a session with no credentials, rules or allow-all
   (`api/sessions.go`). A request with `client_secret` is valid on its own. (Designer's call.)

### greywall

1. Generate a secret per run: 32 bytes from `crypto/rand`, base64url without padding. One secret
   per greywall process, shared by the SOCKS5 and HTTP proxy URLs.
2. Put it in the proxy URLs instead of `"proxy"`: `url.UserPassword(proxyUser, secret)`.
3. Always register a session with greyproxy when a proxy is used, not only when credentials or
   session rules exist (today: `credSubstitutionActive` or `len(sessionNetworkRules) > 0`), and
   send `client_secret`. Keep the existing heartbeat loop for it.
4. If registration fails: with debug, log it; keep running with the secret anyway. Against an
   older greyproxy the field is ignored and logins keep working; against a fork greyproxy with
   `requireClientSecret`, the unregistered secret is refused, which is the safe outcome.
5. The debug line "Auto-set proxy credentials to %q:proxy" must not print the secret.
6. `--proxy-user` keeps choosing the name; there is no flag to choose the secret.

### Docker clients (dotfiles)

`agent-docker@.service` generates a secret when the service starts, registers a long-lived session
(`container_name = <project>-docker`, with heartbeat from the service), and writes the secret into
the Docker client proxy URL instead of `proxy`. Details belong to the dotfiles session; it gets
its own proposal once this design is approved.

## Tests

- greyproxy: a client that logs in with another client's name and a wrong or empty password is
  refused when that name has a live secret (SOCKS5 and HTTP). The right secret is accepted. An
  expired session's secret is refused. With `requireClientSecret: true`, an unregistered name is
  refused and the anonymous login still works; with `allowAnonymousClients: false` it is refused.
  A login named `unknown-...` is refused. Secrets never appear in `GET /api/sessions`. A proxied
  connection to greyproxy's own ports is refused even with an allow rule for it. An API call
  without the token, or with a wrong one, gets 401 when the token check is on.
- greywall: the generated proxy URLs carry a non-`proxy` password that differs between two runs;
  the registration request contains `client_secret` and the API token header when the token file
  exists, and no header when it does not; registration happens even with no credentials and no
  rules; the debug output contains neither the secret nor the token.

## Order

1. greyproxy: refuse proxied traffic to its own ports; API token file and check behind a setting
   (prerequisite).
2. greyproxy: `client_secret`, the auther check, `requireClientSecret` (default false), tests.
3. greywall: send the API token, secret per run, always register, tests.
4. dotfiles: Docker service sends the token and its secret; then enable the API token check and
   `requireClientSecret` in the fork's config. Turning either on before steps 3 and the Docker
   change are deployed would cut off every sandbox.

## Left to the builder

- Column name and migration number for the hash in greyproxy's `sessions` table.
- Exact error text and log lines on refusal (must name the client, never the password).
- How the auther reaches the database (it currently has no DB handle).
