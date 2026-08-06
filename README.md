# Silo Media Server LDAP Authentication

An LDAP authentication provider plugin for [Silo Media Server](https://github.com/Silo-Server/silo-server).

The plugin implements Silo's `auth_provider.v1` password flow and supports:

- Synology LDAP Server and other OpenLDAP-compatible directories
- Synology Directory Server and Microsoft Active Directory
- LDAPS and StartTLS
- Read-only service-account searches or anonymous searches
- Stable Silo identities through `entryUUID`, `objectGUID`, or another configured attribute
- Optional direct LDAP group allowlisting
- Linux AMD64 and ARM64 builds for common Docker and Synology deployments

## Authentication flow

1. Silo sends the submitted username and password to the plugin.
2. The plugin connects to LDAP and optionally binds with a read-only search account.
3. It searches for exactly one user with the configured filter.
4. It checks optional direct group membership from the configured group attribute.
5. It binds as the discovered user DN with the submitted password.
6. It returns a stable external subject, display name, email address, DN, and group claims to Silo.
7. Silo creates the session and optionally auto-provisions a normal local Silo user.

The plugin never stores user passwords and does not log credentials.

## Recommended directory settings

### Synology LDAP Server / OpenLDAP

| Setting | Example |
| --- | --- |
| LDAP URL | `ldaps://nas.example.com:636` |
| Base DN | `dc=example,dc=com` |
| User filter | `(&(objectClass=person)(uid={username}))` |
| Subject attribute | `entryUUID` |
| Display-name attribute | `displayName` or `cn` |
| Email attribute | `mail` |
| Group attribute | `memberOf` |

### Active Directory / Synology Directory Server

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

## Security defaults

- Plain `ldap://` connections are rejected unless StartTLS is enabled.
- Plaintext LDAP can only be enabled through an explicit dangerous setting.
- TLS 1.2 or later is required.
- Certificate verification is enabled by default.
- A private CA certificate can be supplied in PEM format.
- User searches are limited to two results and authentication fails unless exactly one entry matches.
- Missing users, wrong passwords, and denied groups produce the same login result.

Keep a working local Silo administrator account for recovery. Silo currently auto-provisions plugin users with the normal `user` role; LDAP claims cannot assign Silo administrator roles without a Silo host-side enhancement.

## Build

Go 1.26 or newer is required because the current Silo plugin SDK requires it.

```bash
go test ./...
make build VERSION=0.1.0
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
- Nested Active Directory group resolution is not yet implemented.
- LDAP group claims do not currently control Silo roles or library permissions.
- Password changes, account linking, and LDAP synchronization are outside the password-provider contract.

## License

MIT
