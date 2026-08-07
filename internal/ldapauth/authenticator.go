package ldapauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
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

type Authenticator struct {
	config config.Config
}

func New(cfg config.Config) *Authenticator {
	return &Authenticator{config: cfg}
}

// CheckConnection validates the configured transport, TLS negotiation,
// search-account bind, base DN, user-search filter, and configured group DNs
// without requiring a real user's password. A deliberately unlikely username
// is used and zero results are considered successful; the search itself must
// complete without an LDAP error.
func (a *Authenticator) CheckConnection(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	filter, err := buildUserFilter(a.config.UserFilter, "__silo_connection_test__")
	if err != nil {
		return fmt.Errorf("validate LDAP user filter: %w", err)
	}

	conn, err := a.dial(ctx)
	if err != nil {
		return fmt.Errorf("connect to LDAP: %w", err)
	}
	defer conn.Close()

	if a.config.BindDN != "" {
		if err := conn.Bind(a.config.BindDN, a.config.BindPassword); err != nil {
			return fmt.Errorf("bind LDAP search account: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
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
		return fmt.Errorf("query LDAP user search base: %w", err)
	}
	if err := a.checkConfiguredGroupDNs(conn); err != nil {
		return err
	}
	return nil
}

func (a *Authenticator) checkConfiguredGroupDNs(conn *ldap.Conn) error {
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
			return fmt.Errorf("query configured LDAP group %q: %w", groupDN, err)
		}
		if len(result.Entries) != 1 {
			return fmt.Errorf("configured LDAP group %q was not found", groupDN)
		}
	}
	return nil
}

func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (*User, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, ErrInvalidCredentials
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	conn, err := a.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("connect to LDAP: %w", err)
	}
	defer conn.Close()

	if a.config.BindDN != "" {
		if err := conn.Bind(a.config.BindDN, a.config.BindPassword); err != nil {
			return nil, fmt.Errorf("bind LDAP search account: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	entry, err := a.findUser(conn, username)
	if err != nil {
		return nil, err
	}
	groups := entry.GetEqualFoldAttributeValues(a.config.GroupAttribute)
	if !groupsAllowed(groups, a.config.RequiredGroups, a.config.GroupMatchMode) {
		return nil, ErrGroupDenied
	}

	if err := conn.Bind(entry.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("bind LDAP user: %w", err)
	}

	subject, err := stableSubject(entry, a.config.SubjectAttribute)
	if err != nil {
		return nil, err
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

func roleForGroups(groups []string, cfg config.Config) string {
	if !cfg.RoleSyncEnabled {
		return ""
	}
	if groupsAllowed(groups, cfg.AdminGroups, cfg.AdminGroupMatchMode) {
		return "admin"
	}
	return "user"
}

func (a *Authenticator) dial(ctx context.Context) (*ldap.Conn, error) {
	timeout := effectiveTimeout(ctx, a.config.Timeout())
	tlsConfig, err := a.tlsConfig()
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := ldap.DialURL(
		a.config.URL,
		ldap.DialWithDialer(dialer),
		ldap.DialWithTLSConfig(tlsConfig),
	)
	if err != nil {
		return nil, err
	}
	conn.SetTimeout(timeout)

	parsed, _ := url.Parse(a.config.URL)
	if parsed != nil && parsed.Scheme == "ldap" && a.config.StartTLS {
		if err := conn.StartTLS(tlsConfig); err != nil {
			conn.Close()
			return nil, fmt.Errorf("start TLS: %w", err)
		}
	}
	return conn, nil
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

func (a *Authenticator) findUser(conn *ldap.Conn, username string) (*ldap.Entry, error) {
	filter, err := buildUserFilter(a.config.UserFilter, username)
	if err != nil {
		return nil, fmt.Errorf("compile LDAP user filter: %w", err)
	}
	attributes := uniqueNonEmpty(
		a.config.SubjectAttribute,
		a.config.DisplayNameAttribute,
		a.config.EmailAttribute,
		a.config.GroupAttribute,
	)
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
		return nil, fmt.Errorf("search LDAP user: %w", err)
	}
	if len(result.Entries) != 1 {
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
	set := make(map[string]struct{}, len(actual))
	for _, group := range actual {
		set[strings.ToLower(strings.TrimSpace(group))] = struct{}{}
	}

	matched := 0
	for _, group := range required {
		if _, ok := set[strings.ToLower(strings.TrimSpace(group))]; ok {
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
