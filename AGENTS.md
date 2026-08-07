# Silo LDAP Authentication Plugin

Go plugin for Silo Media Server that provides LDAP/Active Directory password authentication via
the `auth_provider.v1` capability. `main.go` is the gRPC entrypoint that bridges the plugin SDK to
the `internal/ldapauth` authenticator; `internal/config` decodes and validates the plugin's
configuration block.

## Priorities

Security first. Every code path must produce the same observable result for missing users, wrong
passwords, and denied groups — including avoiding practical timing distinctions that leak directory
membership. Credentials are never logged. Plaintext LDAP is rejected by default and requires an
explicit dangerous opt-in.

## Building and verifying

```bash
make test        # go test ./...
make vet         # go vet ./...
make build VERSION=0.4.0
```

Go 1.26 or newer is required (the current Silo plugin SDK requires it).

CI runs on every push to `main` and `agent/**` branches, and on pull requests. It verifies
`go mod tidy` is clean, runs tests, vet, and a build check.

## Architecture

```
main.go                  → gRPC server, manifest, Configure/Authenticate handlers
internal/
  config/config.go       → Config struct, strict Decode from pluginpb.ConfigEntry, Validate
  ldapauth/
    authenticator.go     → Authenticator: dial, bind, search, authenticate, CheckConnection
    errors.go            → typed failure stages and safe stage classification
```

The `authServer` in `main.go` wraps the authenticator behind a `sync.RWMutex` — `Configure` swaps
it atomically, and `Authenticate` reads it under the read lock so reconfigures never race with
in-flight logins. The interface boundary is intentionally injectable for RPC behavior tests.

## Error classification

LDAP infrastructure failures are wrapped in `ldapauth.StageError`. `StageOf` returns a stable,
non-sensitive stage for client responses while the full underlying error is retained for server
logs. Do not return raw directory, TLS, hostname, DN, or search errors to unauthenticated clients.
Invalid credentials and group denials return an empty authentication response so Silo treats them
as ordinary failed logins.

## Managed roles

When role synchronization is enabled, the plugin returns both `silo_role_managed=true` and a
`silo_role` value of `user` or `admin`. The capability manifest advertises the claim names and
allowed values. Do not emit managed-role claims when synchronization is disabled.

## Stable subjects

The `stableSubject` function in `authenticator.go` produces a durable external identity from the
configured attribute. For `objectGUID` and `objectSid` it hex-encodes the raw binary value; for
other attributes it uses the string value if it's valid UTF-8, falling back to hex-encoded raw
bytes. The result is always prefixed `attributename:value` so the attribute name is part of the
identity and a later attribute change is detectable.

## Pull requests

Conventional Commit subjects (`feat(ldap): add group DN validation`). One concern per PR.

AI-use disclosure is required. Follow the same disclosure block used in the main
[silo-server](https://github.com/techrelay/silo-server) repo — tool, exact model ID, involvement
level, and adversarial review summary. Undisclosed AI use gets the PR closed.
