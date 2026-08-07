package ldapauth

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
	"github.com/techrelay/Silo-LDAP-Plugin/internal/config"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrGroupDenied        = errors.New("user is not a member of an allowed LDAP group")
)

type User struct {
	Subject     string
	Username    string
	DisplayName string
	Email       string
	DN          string
	Groups      []string
	Role        string
}

type ldapConnection interface {
	Bind(username, password string) error
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	SetTimeout(timeout time.Duration)
	Close() error
}

type ldapDialer func(context.Context) (ldapConnection, func(), error)

type Authenticator struct {
	config       config.Config
	dialOverride ldapDialer
}

func New(cfg config.Config) *Authenticator {
	return &Authenticator{config: cfg}
}

// CheckConnection validates the configured transport, TLS negotiation,
// search-account bind, base DN, and user-search filter without requiring a
// real user's password. Group objects are deliberately not queried: normal
// authentication only consumes group values from the user entry, so requiring
// group-object read ACLs here would reject otherwise valid deployments.
func (a *Authenticator) CheckConnection(ctx context.Context) error {
	ctx, cancel := a.operationContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}

	filter, err := buildUserFilter(a.config.UserFilter, "__silo_connection_test__")
	if err != nil {
		return withStage(StageUserFilter, err)
	}

	conn, stop, err := a.connectAndBind(ctx)
	if err != nil {
		return err
	}
	defer stop()
	defer conn.Close()

	if err := a.prepareOperation(ctx, conn); err != nil {
		return err
	}
	request := ldap.NewSearchRequest(
		a.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,
		a.config.TimeoutSeconds,
		false,
		filter,
		[]string{"1.1"},
		nil,
	)
	if _, err := conn.Search(request); err != nil {
		return operationError(ctx, StageUserSearch, err)
	}
	return nil
}

func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (*User, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, ErrInvalidCredentials
	}

	ctx, cancel := a.operationContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	conn, stop, err := a.connectAndBind(ctx)
	if err != nil {
		return nil, err
	}
	defer stop()
	defer conn.Close()

	entry, err := a.findUser(ctx, conn, username)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			// Preserve a bind-sized directory operation for an unknown or
			// ambiguous user so failed-login timing does not reveal whether a
			// directory entry exists.
			return nil, a.maskUnknownUser(ctx, conn, username, password)
		}
		return nil, err
	}

	// Verify the password before applying group authorization. This keeps a
	// wrong password from becoming an oracle for sign-in-group membership.
	if err := a.prepareOperation(ctx, conn); err != nil {
		return nil, err
	}
	if err := conn.Bind(entry.DN, password); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return nil, ErrInvalidCredentials
		}
		return nil, withStage(StageUserBind, err)
	}

	groups := entry.GetEqualFoldAttributeValues(a.config.GroupAttribute)
	if !groupsAllowed(groups, a.config.RequiredGroups, a.config.GroupMatchMode) {
		return nil, ErrGroupDenied
	}

	subject, err := stableSubject(entry, a.config.SubjectAttribute)
	if err != nil {
		return nil, withStage(StageSubjectMapping, err)
	}
	displayName := strings.TrimSpace(entry.GetEqualFoldAttributeValue(a.config.DisplayNameAttribute))
	if displayName == "" {
		displayName = username
	}

	return &User{
		Subject:     subject,
		Username:    username,
		DisplayName: displayName,
		Email:       strings.TrimSpace(entry.GetEqualFoldAttributeValue(a.config.EmailAttribute)),
		DN:          entry.DN,
		Groups:      append([]string(nil), groups...),
		Role:        roleForGroups(groups, a.config),
	}, nil
}

func (a *Authenticator) maskUnknownUser(
	ctx context.Context,
	conn ldapConnection,
	username, password string,
) error {
	if err := a.prepareOperation(ctx, conn); err != nil {
		return err
	}
	err := conn.Bind(dummyBindDN(a.config.BaseDN, username), password)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err == nil || isExpectedDummyBindRejection(err) {
		return ErrInvalidCredentials
	}
	return withStage(StageUserBind, err)
}

func dummyBindDN(baseDN, username string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(username))))
	rdn := "cn=__silo_nonexistent_" + hex.EncodeToString(sum[:16])
	baseDN = strings.TrimSpace(baseDN)
	if baseDN == "" {
		return rdn
	}
	return rdn + "," + baseDN
}

func isExpectedDummyBindRejection(err error) bool {
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) {
		return false
	}
	switch ldapErr.ResultCode {
	case ldap.ErrorNetwork,
		ldap.LDAPResultBusy,
		ldap.LDAPResultUnavailable,
		ldap.LDAPResultServerDown,
		ldap.LDAPResultLocalError,
		ldap.LDAPResultTimeout,
		ldap.LDAPResultConnectError:
		return false
	default:
		// Invalid credentials, no-such-object, insufficient-access, and
		// other directory-level rejections all represent the same external
		// authentication outcome on the deliberate dummy bind path.
		return true
	}
}

// connectAndBind dials the LDAP directory, upgrades to TLS when configured,
// and optionally authenticates with the search account.
func (a *Authenticator) connectAndBind(ctx context.Context) (ldapConnection, func(), error) {
	conn, stop, err := a.openConnection(ctx)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, ctxErr
		}
		var staged *StageError
		if errors.As(err, &staged) {
			return nil, nil, err
		}
		return nil, nil, withStage(StageConnection, err)
	}
	if stop == nil {
		stop = func() {}
	}

	if a.config.BindDN != "" {
		if err := a.prepareOperation(ctx, conn); err != nil {
			stop()
			_ = conn.Close()
			return nil, nil, err
		}
		if err := conn.Bind(a.config.BindDN, a.config.BindPassword); err != nil {
			stop()
			_ = conn.Close()
			return nil, nil, operationError(ctx, StageSearchAccountBind, err)
		}
	}
	if err := ctx.Err(); err != nil {
		stop()
		_ = conn.Close()
		return nil, nil, err
	}
	return conn, stop, nil
}

func (a *Authenticator) openConnection(ctx context.Context) (ldapConnection, func(), error) {
	if a.dialOverride != nil {
		return a.dialOverride(ctx)
	}
	return a.dial(ctx)
}

func roleForGroups(groups []string, cfg config.Config) string {
	if !cfg.RoleSyncEnabled {
		return ""
	}
	if groupsAllowed(groups, cfg.AdminGroups, cfg.AdminGroupMatchMode) {
		return "admin"
	}
	return "user"
}

func (a *Authenticator) dial(ctx context.Context) (ldapConnection, func(), error) {
	timeout := effectiveTimeout(ctx, a.config.Timeout())
	tlsConfig, err := a.tlsConfig()
	if err != nil {
		return nil, nil, err
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := ldap.DialURL(
		a.config.URL,
		ldap.DialWithDialer(dialer),
		ldap.DialWithTLSConfig(tlsConfig),
	)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, ctxErr
		}
		return nil, nil, err
	}
	conn.SetTimeout(timeout)
	stop := closeLDAPOnContext(ctx, conn)

	parsed, _ := url.Parse(a.config.URL)
	if parsed != nil && parsed.Scheme == "ldap" && a.config.StartTLS {
		if err := conn.StartTLS(tlsConfig); err != nil {
			stop()
			_ = conn.Close()
			return nil, nil, operationError(ctx, StageStartTLS, err)
		}
	}
	return conn, stop, nil
}

func closeLDAPOnContext(ctx context.Context, conn ldapConnection) func() {
	done := make(chan struct{})
	var once sync.Once
	stop := func() {
		once.Do(func() { close(done) })
	}
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	return stop
}

func (a *Authenticator) operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, a.config.Timeout())
}

func (a *Authenticator) prepareOperation(ctx context.Context, conn ldapConnection) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	conn.SetTimeout(effectiveTimeout(ctx, a.config.Timeout()))
	return nil
}

func operationError(ctx context.Context, stage FailureStage, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return withStage(stage, err)
}

func (a *Authenticator) tlsConfig() (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if strings.TrimSpace(a.config.CAPEM) != "" {
		if ok := roots.AppendCertsFromPEM([]byte(a.config.CAPEM)); !ok {
			return nil, fmt.Errorf("custom CA PEM did not contain a valid certificate")
		}
	}

	serverName := strings.TrimSpace(a.config.ServerName)
	if serverName == "" {
		parsed, err := url.Parse(a.config.URL)
		if err == nil {
			serverName = parsed.Hostname()
		}
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		RootCAs:            roots,
		ServerName:         serverName,
		InsecureSkipVerify: a.config.InsecureSkipVerify, //nolint:gosec // explicit operator setting
	}, nil
}

func (a *Authenticator) findUser(ctx context.Context, conn ldapConnection, username string) (*ldap.Entry, error) {
	filter, err := buildUserFilter(a.config.UserFilter, username)
	if err != nil {
		return nil, withStage(StageUserFilter, err)
	}
	attributes := uniqueNonEmpty(
		a.config.SubjectAttribute,
		a.config.DisplayNameAttribute,
		a.config.EmailAttribute,
		a.config.GroupAttribute,
	)
	if err := a.prepareOperation(ctx, conn); err != nil {
		return nil, err
	}
	request := ldap.NewSearchRequest(
		a.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		2,
		a.config.TimeoutSeconds,
		false,
		filter,
		attributes,
		nil,
	)
	result, err := conn.Search(request)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		// The client-side size limit is two entries. SizeLimitExceeded
		// therefore proves the configured filter is ambiguous rather than
		// indicating an infrastructure outage, so keep the external result
		// indistinguishable from any other non-unique user lookup.
		if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
			return nil, ErrInvalidCredentials
		}
		return nil, withStage(StageUserSearch, err)
	}
	if result == nil || len(result.Entries) != 1 {
		return nil, ErrInvalidCredentials
	}
	return result.Entries[0], nil
}

func buildUserFilter(template, username string) (string, error) {
	filter := strings.ReplaceAll(template, "{username}", ldap.EscapeFilter(username))
	if _, err := ldap.CompileFilter(filter); err != nil {
		return "", err
	}
	return filter, nil
}

func stableSubject(entry *ldap.Entry, attribute string) (string, error) {
	attribute = strings.TrimSpace(attribute)
	text := strings.TrimSpace(entry.GetEqualFoldAttributeValue(attribute))
	raw := entry.GetEqualFoldRawAttributeValue(attribute)

	if strings.EqualFold(attribute, "objectGUID") || strings.EqualFold(attribute, "objectSid") {
		if len(raw) == 0 {
			return "", fmt.Errorf("LDAP subject attribute %q is missing", attribute)
		}
		return strings.ToLower(attribute) + ":" + hex.EncodeToString(raw), nil
	}
	if text != "" && utf8.ValidString(text) {
		return strings.ToLower(attribute) + ":" + text, nil
	}
	if len(raw) > 0 {
		return strings.ToLower(attribute) + ":" + hex.EncodeToString(raw), nil
	}
	return "", fmt.Errorf("LDAP subject attribute %q is missing", attribute)
}

func groupsAllowed(actual, required []string, mode string) bool {
	if len(required) == 0 {
		return true
	}

	matched := 0
	for _, requiredGroup := range required {
		found := false
		for _, actualGroup := range actual {
			if groupValuesEqual(actualGroup, requiredGroup) {
				found = true
				break
			}
		}
		if found {
			matched++
			if mode == "any" {
				return true
			}
		} else if mode == "all" {
			return false
		}
	}
	if mode == "all" {
		return matched == len(required)
	}
	return false
}

func groupValuesEqual(left, right string) bool {
	left = strings.TrimSpace(left)
	right = strings.TrimSpace(right)
	leftDN, leftErr := ldap.ParseDN(left)
	rightDN, rightErr := ldap.ParseDN(right)
	if leftErr == nil && rightErr == nil {
		return leftDN.Equal(rightDN)
	}
	// Preserve support for directories configured with a non-DN group
	// attribute while using RFC distinguishedNameMatch whenever both values
	// are valid DNs.
	return strings.EqualFold(left, right)
}

func uniqueNonEmpty(values ...string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}

func effectiveTimeout(ctx context.Context, configured time.Duration) time.Duration {
	if configured <= 0 {
		configured = 10 * time.Second
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return configured
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return time.Millisecond
	}
	if remaining < configured {
		return remaining
	}
	return configured
}
