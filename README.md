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
4. It checks optional direct group membership from the configured group attribute.
5. It binds as the discovered user DN with the submitted password.
6. It returns a stable external subject, display name, email address, DN, groups, and optional managed-role claims.
7. Silo creates the session, optionally provisions the account, and—when host support and role synchronization are both enabled—applies the advertised role.

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

- a member of the configured administrator group receives the `admin` role claim;
- any other LDAP user who passes the sign-in allowlist receives the `user` role claim;
- promotions and demotions are evaluated on each successful login;
- administrators must also satisfy the sign-in allowlist.

The capability manifest advertises the role contract explicitly:

```json
{
  "role_managed_claim": "silo_role_managed",
  "role_claim": "silo_role",
  "role_values": ["user", "admin"]
}
```

A successful login with role synchronization enabled returns both `silo_role_managed=true` and the selected `silo_role`. Host support for both claims is required. Keep a working local Silo administrator account for recovery before enabling synchronization.

## Security behavior

- Plain `ldap://` connections are rejected unless StartTLS is enabled.
- Plaintext LDAP requires an explicit dangerous override.
- TLS 1.2 or later is required.
- Certificate verification is enabled by default.
- A private CA certificate can be supplied in PEM format.
- User searches are limited to two results and authentication fails unless exactly one entry matches.
- Missing users, incorrect passwords, and denied groups produce the same login result.
- Full LDAP failures are written to plugin logs, while unauthenticated RPC responses expose only a stable operation stage.
- Configuration values with incorrect or unknown types are rejected instead of silently falling back to defaults.

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
- Automated tests cover configuration, claim construction, failure handling, filter escaping, role mapping, and stable identities. Live-directory interoperability still requires deployment testing against the target LDAP implementation.

## License

MIT
