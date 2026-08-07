package ldapauth

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
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
	SetDeadline(deadline time.Time) error
	Close() error
}

type networkLDAPConnection struct {
	ldap   *ldap.Conn
	socket net.Conn
}

func (c *networkLDAPConnection) Bind(username, password string) error {
	return c.ldap.Bind(username, password)
}
func (c *networkLDAPConnection) Search(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return c.ldap.Search(request)
}
func (c *networkLDAPConnection) SetTimeout(timeout time.Duration) { c.ldap.SetTimeout(timeout) }
func (c *networkLDAPConnection) SetDeadline(deadline time.Time) error {
	return c.socket.SetDeadline(deadline)
}
func (c *networkLDAPConnection) Close() error { return c.ldap.Close() }

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
// real user's password. Configured group DNs are validated on a best-effort
// basis: warnings are logged for unreachable groups, but the connection test
// succeeds so deployments where group objects are not directly readable
// (common with some LDAP servers) are not rejected.
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
	a.warnUnreachableGroupDNs(ctx, conn)
	return nil
}

// warnUnreachableGroupDNs logs a warning for each configured group DN that
// cannot be queried or resolved. Failures here are not fatal because many
// LDAP deployments do not grant group-object read access to the search
// account — the user entry's memberOf attribute is the canonical source.
func (a *Authenticator) warnUnreachableGroupDNs(ctx context.Context, conn ldapConnection) {
	groupDNs := append([]string(nil), a.config.RequiredGroups...)
	groupDNs = append(groupDNs, a.config.AdminGroups...)
	for _, groupDN := range uniqueNonEmpty(groupDNs...) {
		request := ldap.NewSearchRequest(
			groupDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			1,
			a.config.TimeoutSeconds,
			false,
			"(objectClass=*)",
			[]string{"1.1"},
			nil,
		)
		result, err := conn.Search(request)
		if err != nil {
			slog.WarnContext(ctx, "configured LDAP group query failed during connection test",
				"group_dn", groupDN,
				"error", err,
			)
			continue
		}
		if len(result.Entries) != 1 {
			slog.WarnContext(ctx, "configured LDAP group was not found during connection test",
				"group_dn", groupDN,
			)
		}
	}
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
			return nil, a.maskUnknownUser(ctx, conn, username, password)
		}
		return nil, err
	}

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

func (a *Authenticator) maskUnknownUser(ctx context.Context, conn ldapConnection, username, password string) error {
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
		return true
	}
}

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
	parsed, err := url.Parse(a.config.URL)
	if err != nil {
		return nil, nil, err
	}
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "ldaps" {
			port = "636"
		} else {
			port = "389"
		}
	}
	address := net.JoinHostPort(parsed.Hostname(), port)

	rawConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, err
	}
	if err := setSocketDeadline(ctx, rawConn); err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}

	tlsConfig, err := a.tlsConfig()
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}

	var socket net.Conn = rawConn
	isTLS := false
	if parsed.Scheme == "ldaps" {
		tlsConn := tls.Client(rawConn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = rawConn.Close()
			return nil, nil, operationError(ctx, StageConnection, err)
		}
		socket = tlsConn
		isTLS = true
	}

	ldapConn := ldap.NewConn(socket, isTLS)
	ldapConn.Start()
	conn := &networkLDAPConnection{ldap: ldapConn, socket: socket}
	conn.SetTimeout(effectiveTimeout(ctx, a.config.Timeout()))
	stop := closeLDAPOnContext(ctx, conn)

	if parsed.Scheme == "ldap" && a.config.StartTLS {
		if err := ldapConn.StartTLS(tlsConfig); err != nil {
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
			_ = conn.SetDeadline(time.Now())
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
	return setConnectionDeadline(ctx, conn)
}

func setConnectionDeadline(ctx context.Context, conn ldapConnection) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil
	}
	return conn.SetDeadline(deadline)
}

func setSocketDeadline(ctx context.Context, conn net.Conn) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil
	}
	return conn.SetDeadline(deadline)
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
		return ldapDNEqualFold(leftDN, rightDN)
	}
	return strings.EqualFold(left, right)
}

func ldapDNEqualFold(left, right *ldap.DN) bool {
	if left == nil || right == nil || len(left.RDNs) != len(right.RDNs) {
		return false
	}
	for i := range left.RDNs {
		if !ldapRelativeDNEqualFold(left.RDNs[i], right.RDNs[i]) {
			return false
		}
	}
	return true
}

func ldapRelativeDNEqualFold(left, right *ldap.RelativeDN) bool {
	if left == nil || right == nil || len(left.Attributes) != len(right.Attributes) {
		return false
	}
	matched := make([]bool, len(right.Attributes))
	for _, leftAttr := range left.Attributes {
		found := false
		for i, rightAttr := range right.Attributes {
			if matched[i] {
				continue
			}
			if strings.EqualFold(leftAttr.Type, rightAttr.Type) && strings.EqualFold(leftAttr.Value, rightAttr.Value) {
				matched[i] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
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
