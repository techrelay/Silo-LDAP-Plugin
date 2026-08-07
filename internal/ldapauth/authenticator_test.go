package ldapauth

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/techrelay/Silo-LDAP-Plugin/internal/config"
)

type fakeLDAPConnection struct {
	entries    []*ldap.Entry
	searchErr  error
	bindErrors map[string]error
	operations []string
	timeout    time.Duration
	deadline   time.Time
	closed     atomic.Bool
}

func (f *fakeLDAPConnection) Bind(username, _ string) error {
	f.operations = append(f.operations, "bind:"+username)
	if f.bindErrors != nil {
		return f.bindErrors[username]
	}
	return nil
}

func (f *fakeLDAPConnection) Search(*ldap.SearchRequest) (*ldap.SearchResult, error) {
	f.operations = append(f.operations, "search")
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	return &ldap.SearchResult{Entries: f.entries}, nil
}

func (f *fakeLDAPConnection) SetTimeout(timeout time.Duration) { f.timeout = timeout }
func (f *fakeLDAPConnection) SetDeadline(deadline time.Time) error {
	f.deadline = deadline
	return nil
}
func (f *fakeLDAPConnection) Close() error {
	f.closed.Store(true)
	return nil
}

func testAuthenticator(cfg config.Config, conn *fakeLDAPConnection) *Authenticator {
	return &Authenticator{
		config: cfg,
		dialOverride: func(context.Context) (ldapConnection, func(), error) {
			return conn, func() {}, nil
		},
	}
}

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

func TestGroupsAllowedUsesLDAPDNEquality(t *testing.T) {
	actual := []string{"CN=Admins+UID=42,OU=Groups,DC=example,DC=com"}
	required := []string{"uid=42+cn=admins,ou=groups,dc=example,dc=com"}
	if !groupsAllowed(actual, required, "any") {
		t.Fatal("expected equivalent multi-valued LDAP DNs to match")
	}
}

func TestRoleForGroups(t *testing.T) {
	cfg := config.Default()
	cfg.RoleSyncEnabled = true
	cfg.AdminGroups = []string{"CN=SiloAdmins,OU=Groups,DC=example,DC=com"}

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

func TestAuthenticateBindsBeforeGroupDenial(t *testing.T) {
	cfg := config.Default()
	cfg.BaseDN = "dc=example,dc=com"
	cfg.RequiredGroups = []string{"cn=allowed,ou=groups,dc=example,dc=com"}
	entry := &ldap.Entry{
		DN: "cn=alice,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "entryUUID", Values: []string{"alice-id"}},
			{Name: "memberOf", Values: []string{"cn=other,ou=groups,dc=example,dc=com"}},
		},
	}
	conn := &fakeLDAPConnection{entries: []*ldap.Entry{entry}}
	auth := testAuthenticator(cfg, conn)

	_, err := auth.Authenticate(context.Background(), "alice", "correct-password")
	if !errors.Is(err, ErrGroupDenied) {
		t.Fatalf("Authenticate error = %v, want ErrGroupDenied", err)
	}
	want := []string{"search", "bind:" + entry.DN}
	if len(conn.operations) != len(want) {
		t.Fatalf("operations = %v, want %v", conn.operations, want)
	}
	for i := range want {
		if conn.operations[i] != want[i] {
			t.Fatalf("operations = %v, want %v", conn.operations, want)
		}
	}
}

func TestAuthenticateUnknownUserConsumesDummyBind(t *testing.T) {
	cfg := config.Default()
	cfg.BaseDN = "dc=example,dc=com"
	dummyDN := dummyBindDN(cfg.BaseDN, "missing")
	conn := &fakeLDAPConnection{
		bindErrors: map[string]error{
			dummyDN: ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("not found")),
		},
	}
	auth := testAuthenticator(cfg, conn)

	_, err := auth.Authenticate(context.Background(), "missing", "wrong-password")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Authenticate error = %v, want ErrInvalidCredentials", err)
	}
	want := []string{"search", "bind:" + dummyDN}
	if len(conn.operations) != len(want) {
		t.Fatalf("operations = %v, want %v", conn.operations, want)
	}
	for i := range want {
		if conn.operations[i] != want[i] {
			t.Fatalf("operations = %v, want %v", conn.operations, want)
		}
	}
}

func TestAuthenticateAmbiguousSearchConsumesDummyBind(t *testing.T) {
	cfg := config.Default()
	cfg.BaseDN = "dc=example,dc=com"
	dummyDN := dummyBindDN(cfg.BaseDN, "duplicate")
	conn := &fakeLDAPConnection{
		searchErr: ldap.NewError(ldap.LDAPResultSizeLimitExceeded, errors.New("more than two matches")),
		bindErrors: map[string]error{
			dummyDN: ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("not found")),
		},
	}
	auth := testAuthenticator(cfg, conn)

	_, err := auth.Authenticate(context.Background(), "duplicate", "wrong-password")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Authenticate error = %v, want ErrInvalidCredentials", err)
	}
	want := []string{"search", "bind:" + dummyDN}
	if len(conn.operations) != len(want) {
		t.Fatalf("operations = %v, want %v", conn.operations, want)
	}
}

func TestAuthenticateWrongPasswordUsesRealBind(t *testing.T) {
	cfg := config.Default()
	cfg.BaseDN = "dc=example,dc=com"
	entry := &ldap.Entry{
		DN: "cn=alice,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{{Name: "entryUUID", Values: []string{"alice-id"}}},
	}
	conn := &fakeLDAPConnection{
		entries: []*ldap.Entry{entry},
		bindErrors: map[string]error{
			entry.DN: ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials")),
		},
	}
	auth := testAuthenticator(cfg, conn)

	_, err := auth.Authenticate(context.Background(), "alice", "wrong-password")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Authenticate error = %v, want ErrInvalidCredentials", err)
	}
	want := []string{"search", "bind:" + entry.DN}
	if len(conn.operations) != len(want) {
		t.Fatalf("operations = %v, want %v", conn.operations, want)
	}
}

func TestPrepareOperationAppliesContextDeadline(t *testing.T) {
	cfg := config.Default()
	conn := &fakeLDAPConnection{}
	auth := testAuthenticator(cfg, conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := auth.prepareOperation(ctx, conn); err != nil {
		t.Fatalf("prepareOperation returned error: %v", err)
	}
	if conn.deadline.IsZero() {
		t.Fatal("prepareOperation did not apply a socket deadline")
	}
}

func TestCloseLDAPOnContextForcesSocketDeadlineAndClose(t *testing.T) {
	conn := &fakeLDAPConnection{}
	ctx, cancel := context.WithCancel(context.Background())
	stop := closeLDAPOnContext(ctx, conn)
	cancel()
	deadline := time.Now().Add(time.Second)
	for !conn.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	stop()
	if !conn.closed.Load() {
		t.Fatal("context cancellation did not close LDAP connection")
	}
	if conn.deadline.IsZero() {
		t.Fatal("context cancellation did not force a socket deadline")
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

func TestStableSubjectTextAttribute(t *testing.T) {
	entry := &ldap.Entry{Attributes: []*ldap.EntryAttribute{
		{Name: "entryUUID", Values: []string{"abc123-def456"}},
	}}
	subject, err := stableSubject(entry, "entryUUID")
	if err != nil {
		t.Fatalf("stableSubject returned an error: %v", err)
	}
	if subject != "entryuuid:abc123-def456" {
		t.Fatalf("subject = %q, want entryuuid:abc123-def456", subject)
	}
}

func TestStableSubjectRawFallback(t *testing.T) {
	entry := &ldap.Entry{Attributes: []*ldap.EntryAttribute{
		{Name: "customAttr", ByteValues: [][]byte{{0xde, 0xad}}},
	}}
	subject, err := stableSubject(entry, "customAttr")
	if err != nil {
		t.Fatalf("stableSubject returned an error: %v", err)
	}
	if subject != "customattr:dead" {
		t.Fatalf("subject = %q, want customattr:dead", subject)
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

func TestUniqueNonEmpty(t *testing.T) {
	result := uniqueNonEmpty("cn=admins", "", "cn=users", "CN=Admins", "  cn=media  ")
	if len(result) != 3 {
		t.Fatalf("uniqueNonEmpty = %d items, want 3: %v", len(result), result)
	}
	expected := []string{"cn=admins", "cn=users", "cn=media"}
	for i, want := range expected {
		if result[i] != want {
			t.Fatalf("uniqueNonEmpty[%d] = %q, want %q", i, result[i], want)
		}
	}
}

func TestEffectiveTimeout(t *testing.T) {
	ctx := context.Background()
	if got := effectiveTimeout(ctx, 5*time.Second); got != 5*time.Second {
		t.Fatalf("effectiveTimeout without deadline = %v, want 5s", got)
	}
}
