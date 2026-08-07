# Silo LDAP Authentication Plugin

Go plugin for Silo Media Server that provides LDAP/Active Directory password authentication via
the `auth_provider.v1` capability. `main.go` is the gRPC entrypoint that bridges the plugin SDK to
the `internal/ldapauth` authenticator; `internal/config` decodes and validates the plugin's
configuration block.

## Priorities

Security first. Failed authentication paths for a nonexistent/ambiguous account, a wrong password,
and a denied group must expose the same external result and avoid obvious directory-operation-count
differences. Credentials are never logged. Plaintext LDAP is rejected by default and requires an
explicit dangerous opt-in.

A successful password bind happens **before** group authorization. Never move group denial ahead of
the password bind: doing so creates a timing oracle for allowed-group membership. A user search that
does not produce exactly one entry uses the deliberate dummy-bind path before returning invalid
credentials.

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
    authenticator.go     → Authenticator: bounded LDAP operations, auth, CheckConnection
    errors.go            → typed failure stages and safe stage classification
```

The `authServer` in `main.go` wraps the authenticator behind a `sync.RWMutex` — `Configure` swaps
it atomically, and `Authenticate` reads it under the read lock so reconfigures never race with
in-flight logins. The interface boundary is intentionally injectable for RPC behavior tests.

`Authenticator` owns one overall operation deadline. Before each directory request it applies the
remaining deadline as the LDAP request timeout, and a context watcher closes the underlying LDAP
connection when the context expires so cancellation also interrupts TLS and blocked directory I/O.
Do not replace this with independent full-duration timeouts per LDAP request.

## Error classification

LDAP infrastructure failures are wrapped in `ldapauth.StageError`. `StageOf` returns a stable,
non-sensitive stage for client responses while the full underlying error is retained for server
logs. Do not return raw directory, TLS, hostname, DN, or search errors to unauthenticated clients.
Invalid credentials and group denials return an empty authentication response so Silo treats them
as ordinary failed logins.

## Group matching

When both configured and returned group values parse as LDAP DNs, compare them with
`ldap.DN.Equal`; do not reduce DNs to lowercase strings. The fallback case-insensitive string
comparison exists only for directories using a non-DN custom group attribute.

Connection checks must not require read access to configured group objects. Runtime authentication
reads group values from the user entry, so a connection probe should validate only behavior needed
by that runtime path: transport/TLS, optional search-account bind, base DN, and the user search.

## Versioned host extensions

The current Silo plugin SDK does not provide typed connection-test or managed-role fields. Until it
does, these integrations use explicit versioned extensions over `auth_provider.v1`. Treat the
contract tokens as protocol versions. Do not add or consume unversioned magic claims.

### Connection test v1

Contract: `silo.auth.connection-test.v1`

The manifest advertises the contract, owning config key, acknowledgement claim, and response
contract claim. The provider only interprets a connection probe when both `connection_test=true`
and the exact v1 contract are present. A successful probe returns both:

- `silo_connection_test_ok=true`
- `silo_connection_test_contract=silo.auth.connection-test.v1`

### Managed role v1

Contract: `silo.auth.managed-role.v1`

When role synchronization is enabled, a successful login returns all of:

- `silo_role_contract=silo.auth.managed-role.v1`
- `silo_role_managed=true`
- `silo_role=user|admin`

Do not emit managed-role claims when synchronization is disabled. A bare `silo_role` claim has no
host authorization meaning.

If the Silo SDK gains typed equivalents for either extension, migrate to those SDK types instead of
inventing a second convention.

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
