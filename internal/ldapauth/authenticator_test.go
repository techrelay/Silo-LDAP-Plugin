package ldapauth

import (
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/techrelay/Silo-LDAP-Plugin/internal/config"
)

func TestGroupsAllowed(t *testing.T) {
	actual := []string{
		"CN=Silo Users,OU=Groups,DC=example,DC=com",
		"cn=Media,ou=Groups,dc=example,dc=com",
	}
	if !groupsAllowed(actual, []string{"cn=silo users,ou=groups,dc=example,dc=com"}, "any") {
		t.Fatal("expected case-insensitive any-group match")
	}
	if !groupsAllowed(actual, []string{
		"cn=silo users,ou=groups,dc=example,dc=com",
		"cn=media,ou=groups,dc=example,dc=com",
	}, "all") {
		t.Fatal("expected all-group match")
	}
	if groupsAllowed(actual, []string{"cn=admins,dc=example,dc=com"}, "any") {
		t.Fatal("unexpected group match")
	}
}

func TestRoleForGroups(t *testing.T) {
	cfg := config.Default()
	cfg.RoleSyncEnabled = true
	cfg.AdminGroups = []string{"CN=SiloAdmins,OU=groups,DC=example,DC=com"}

	if role := roleForGroups([]string{"cn=siloadmins,ou=groups,dc=example,dc=com"}, cfg); role != "admin" {
		t.Fatalf("administrator role = %q, want admin", role)
	}
	if role := roleForGroups([]string{"cn=silousers,ou=groups,dc=example,dc=com"}, cfg); role != "user" {
		t.Fatalf("normal role = %q, want user", role)
	}

	cfg.RoleSyncEnabled = false
	if role := roleForGroups([]string{"cn=siloadmins,ou=groups,dc=example,dc=com"}, cfg); role != "" {
		t.Fatalf("disabled role sync returned %q, want empty", role)
	}
}

func TestStableSubjectUsesBinaryObjectGUID(t *testing.T) {
	entry := &ldap.Entry{Attributes: []*ldap.EntryAttribute{{Name: "objectGUID", ByteValues: [][]byte{{0x01, 0x02, 0xab}}}}}
	subject, err := stableSubject(entry, "objectGUID")
	if err != nil {
		t.Fatalf("stableSubject returned an error: %v", err)
	}
	if subject != "objectguid:0102ab" {
		t.Fatalf("subject = %q, want objectguid:0102ab", subject)
	}
}

func TestBuildUserFilterEscapesUsername(t *testing.T) {
	filter, err := buildUserFilter(
		"(&(objectClass=user)(sAMAccountName={username}))",
		"nick*)(|(objectClass=*))",
	)
	if err != nil {
		t.Fatalf("buildUserFilter returned an error: %v", err)
	}
	if strings.Contains(filter, "nick*)(|") {
		t.Fatalf("username was not escaped: %q", filter)
	}
	for _, escaped := range []string{`\2a`, `\28`, `\29`} {
		if !strings.Contains(filter, escaped) {
			t.Fatalf("filter %q does not contain escaped sequence %q", filter, escaped)
		}
	}
}

func TestBuildUserFilterRejectsInvalidTemplate(t *testing.T) {
	if _, err := buildUserFilter("(&(objectClass=user)", "nick"); err == nil {
		t.Fatal("expected malformed LDAP filter to be rejected")
	}
}
