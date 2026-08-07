# Silo Media Server LDAP Authentication

An LDAP authentication provider plugin for [Silo Media Server](https://github.com/Silo-Server/silo-server).

The plugin implements Silo's `auth_provider.v1` password flow and supports:

- OpenLDAP-compatible directories, Synology LDAP Server, and Active Directory
- LDAPS and StartTLS
- Read-only service-account searches or anonymous searches
- Stable Silo identities through `entryUUID`, `objectGUID`, or another configured attribute
- Optional direct LDAP group allowlisting
- Optional LDAP administrator-group to Silo-role synchronization
- Configuration connection testing
- Linux AMD64 and ARM64 builds

## Authentication flow

1. Silo sends the submitted username and password to the plugin.
2. The plugin connects to LDAP and optionally binds with a read-only search account.
3. It searches for exactly one user with the configured filter.
4. If no unique user is found, the plugin performs a deliberately failing dummy bind before returning the generic failed-login result. This keeps the directory operation shape closer to an existing-user wrong-password attempt.
5. For a unique user, the plugin binds as the discovered user DN with the submitted password **before** evaluating authorization groups. A wrong password therefore does not reveal whether that user belongs to an allowed Silo group.
6. After the password succeeds, the plugin evaluates optional direct group membership and the optional administrator-group mapping.
7. It returns a stable external subject, display name, email address, DN, groups, and optional versioned managed-role claims.
8. Silo creates the session, optionally provisions the account, and—when host support and role synchronization are both enabled—applies the advertised role.

The plugin never stores user passwords and does not log credentials.

## Recommended directory settings

### OpenLDAP-compatible directories

| Setting | Example |
| --- | --- |
| LDAP URL | `ldaps://ldap.example.com:636` |
| Base DN | `dc=example,dc=com` |
| User filter | `(&(objectClass=person)(uid={username}))` |
| Subject attribute | `entryUUID` |
| Display-name attribute | `displayName` or `cn` |
| Email attribute | `mail` |
| Group attribute | `memberOf` |

### Active Directory

| Setting | Example |
| --- | --- |
| LDAP URL | `ldaps://dc01.example.com:636` |
| Base DN | `dc=example,dc=com` |
| User filter | `(&(objectClass=user)(sAMAccountName={username}))` |
| Subject attribute | `objectGUID` |
| Display-name attribute | `displayName` |
| Email attribute | `mail` |
| Group attribute | `memberOf` |

`{username}` is escaped with LDAP filter escaping before the search is performed.

## Group access and role mapping

A typical deployment uses separate directory groups for sign-in access and Silo administrators:

| Purpose | Example group DN |
| --- | --- |
| Allowed users | `CN=SiloUsers,OU=Groups,DC=example,DC=com` |
| Silo administrators | `CN=SiloAdmins,OU=Groups,DC=example,DC=com` |

Configure the allowed-user group under **Sign-in group DNs**, enable **Synchronize Silo roles from LDAP**, and configure the administrator group under **Administrator group DNs**.

When role synchronization is enabled:

- a member of the configured administrator group requests the Silo `admin` role;
- any other LDAP user who passes the sign-in allowlist requests the Silo `user` role;
- promotions and demotions are evaluated on each successful login;
- administrators must also satisfy the sign-in allowlist.

When group values and configured values are valid LDAP distinguished names, they are parsed and compared structurally. RDN ordering remains significant; attributes within a multi-valued RDN are matched by type and value rather than position; and attribute types and values are compared case-insensitively for practical directory group matching. Non-DN custom group attributes fall back to case-insensitive string comparison. This is not a complete implementation of every schema-specific LDAP matching rule.

Nested Active Directory groups are not resolved. The plugin evaluates the direct values exposed by the configured user group attribute, normally `memberOf`.

## Versioned Silo host extensions

The current plugin SDK does not yet expose typed connection-test or managed-role fields, so this plugin and the companion Silo server fork use explicit **versioned host extensions** carried through existing capability metadata and claims. These are deliberate protocol contracts, not unversioned magic values.

### Connection testing

The capability advertises:

```json
{
  "connection_test": true,
  "connection_test_contract": "silo.auth.connection-test.v1",
  "connection_test_config_keys": ["ldap"]
}
```

The host sends `connection_test=true` together with `connection_test_contract=silo.auth.connection-test.v1`. The v1 response names are fixed. A successful probe explicitly returns:

```json
{
  "silo_connection_test_ok": true,
  "silo_connection_test_contract": "silo.auth.connection-test.v1"
}
```

The connection test validates the transport/TLS negotiation, optional search-account bind, base DN, and user-search operation. It intentionally does **not** require read permission on the configured group objects because normal authentication only consumes group values from the user entry.

### Managed roles

The capability advertises:

```json
{
  "managed_role_contract": "silo.auth.managed-role.v1",
  "role_values": ["user", "admin"]
}
```

The v1 response names are fixed. A role-managed successful login returns all three required values:

```json
{
  "silo_role_contract": "silo.auth.managed-role.v1",
  "silo_role_managed": true,
  "silo_role": "admin"
}
```

The companion host ignores a bare `silo_role` claim. If role management is requested, the managed marker, exact v1 contract, and a supported `user`/`admin` role must all be present.

Keep a working local Silo administrator account for recovery before enabling synchronization.

## Security behavior

- Plain `ldap://` connections are rejected unless StartTLS is enabled.
- Plaintext LDAP requires an explicit dangerous override.
- TLS 1.2 or later is required.
- Certificate verification is enabled by default.
- A private CA certificate can be supplied in PEM format.
- One configured timeout bounds the overall LDAP authentication or connection-test operation, not just each individual LDAP request.
- Context cancellation closes the LDAP socket, including while a StartTLS handshake or directory operation is blocked.
- User searches are limited to two results and authentication fails unless exactly one entry matches.
- A unique user's password is verified before sign-in-group authorization.
- Missing/ambiguous users take a dummy-bind path so they still consume a bind-sized directory operation.
- Missing users, incorrect passwords, and denied groups produce the same external login result.
- Full LDAP failures are written to plugin logs, while unauthenticated RPC responses expose only a stable operation stage.
- Configuration values with incorrect or unknown types are rejected instead of silently falling back to defaults.

The dummy-bind path is intended to remove obvious LDAP-operation-count differences; it is not a claim of cryptographic constant-time behavior across arbitrary directory servers or network conditions.

## Verification

Go 1.26 or newer is required because the current Silo plugin SDK requires it.

```bash
go mod tidy
git diff --exit-code -- go.mod go.sum
go mod verify
go test ./...
go vet ./...
CGO_ENABLED=0 go build -trimpath -o /tmp/silo-plugin-auth-ldap .
```

The repository CI is configured to run those checks for every pull request.

## Build

```bash
make build VERSION=0.4.0
```

The resulting binary is written to `dist/silo-plugin-auth-ldap`.

## Release artifacts

Tags matching `v*` trigger Linux AMD64 and ARM64 builds. Each release contains:

- `plugin-linux-amd64`
- `plugin-linux-arm64`
- `checksums.txt`

The workflow also generates platform-specific manifests with the binary checksum during the build.

## Current limitations

- Group checks use direct values on the configured user attribute, normally `memberOf`.
- Nested Active Directory group resolution is not implemented.
- LDAP groups do not map to individual Silo libraries or granular permissions.
- Password changes, account linking, and full directory synchronization are outside the password-provider contract.
- The connection-test and managed-role features are versioned host extensions over `auth_provider.v1`; they should move to typed SDK fields/RPCs if the Silo plugin SDK gains first-class equivalents.
- Automated tests cover configuration, claim construction, failure handling, filter escaping, timing-path operation shape, DN comparison, role mapping, and stable identities. Live-directory interoperability still requires deployment testing against the target LDAP implementation.

## License

MIT
