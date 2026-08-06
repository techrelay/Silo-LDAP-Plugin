package config

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

const EntryKey = "ldap"

type Config struct {
	URL                    string
	StartTLS               bool
	AllowInsecurePlaintext bool
	InsecureSkipVerify     bool
	ServerName             string
	CAPEM                  string
	BindDN                 string
	BindPassword           string
	BaseDN                 string
	UserFilter             string
	SubjectAttribute       string
	DisplayNameAttribute   string
	EmailAttribute         string
	GroupAttribute         string
	RequiredGroups         []string
	GroupMatchMode         string
	TimeoutSeconds         int
}

func Default() Config {
	return Config{
		UserFilter:           "(&(objectClass=person)(|(uid={username})(sAMAccountName={username})))",
		SubjectAttribute:     "entryUUID",
		DisplayNameAttribute: "displayName",
		EmailAttribute:       "mail",
		GroupAttribute:       "memberOf",
		GroupMatchMode:       "any",
		TimeoutSeconds:       10,
	}
}

func Decode(entries []*pluginv1.ConfigEntry) (Config, bool, error) {
	cfg := Default()
	var values map[string]any
	for _, entry := range entries {
		if entry == nil || strings.TrimSpace(entry.GetKey()) != EntryKey || entry.GetValue() == nil {
			continue
		}
		values = entry.GetValue().AsMap()
		break
	}
	if values == nil {
		return cfg, false, nil
	}

	cfg.URL = stringValue(values, "url", cfg.URL)
	cfg.StartTLS = boolValue(values, "start_tls", cfg.StartTLS)
	cfg.AllowInsecurePlaintext = boolValue(values, "allow_insecure_plaintext", cfg.AllowInsecurePlaintext)
	cfg.InsecureSkipVerify = boolValue(values, "insecure_skip_verify", cfg.InsecureSkipVerify)
	cfg.ServerName = stringValue(values, "server_name", cfg.ServerName)
	cfg.CAPEM = stringValue(values, "ca_pem", cfg.CAPEM)
	cfg.BindDN = stringValue(values, "bind_dn", cfg.BindDN)
	cfg.BindPassword = rawStringValue(values, "bind_password", cfg.BindPassword)
	cfg.BaseDN = stringValue(values, "base_dn", cfg.BaseDN)
	cfg.UserFilter = stringValue(values, "user_filter", cfg.UserFilter)
	cfg.SubjectAttribute = stringValue(values, "subject_attribute", cfg.SubjectAttribute)
	cfg.DisplayNameAttribute = stringValue(values, "display_name_attribute", cfg.DisplayNameAttribute)
	cfg.EmailAttribute = stringValue(values, "email_attribute", cfg.EmailAttribute)
	cfg.GroupAttribute = stringValue(values, "group_attribute", cfg.GroupAttribute)
	cfg.RequiredGroups = splitList(stringValue(values, "required_groups", ""))
	cfg.GroupMatchMode = strings.ToLower(stringValue(values, "group_match_mode", cfg.GroupMatchMode))
	cfg.TimeoutSeconds = intValue(values, "timeout_seconds", cfg.TimeoutSeconds)

	if err := cfg.Validate(); err != nil {
		return Config{}, true, err
	}
	return cfg, true, nil
}

func (c Config) Validate() error {
	parsed, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil {
		return fmt.Errorf("invalid LDAP URL: %w", err)
	}
	if parsed.Scheme != "ldap" && parsed.Scheme != "ldaps" {
		return fmt.Errorf("LDAP URL must use ldap:// or ldaps://")
	}
	if parsed.Hostname() == "" {
		return fmt.Errorf("LDAP URL must include a hostname")
	}
	if parsed.Scheme == "ldaps" && c.StartTLS {
		return fmt.Errorf("StartTLS cannot be enabled with an ldaps:// URL")
	}
	if parsed.Scheme == "ldap" && !c.StartTLS && !c.AllowInsecurePlaintext {
		return fmt.Errorf("plaintext LDAP is disabled; enable StartTLS or explicitly allow insecure plaintext LDAP")
	}
	if (strings.TrimSpace(c.BindDN) == "") != (c.BindPassword == "") {
		return fmt.Errorf("bind DN and bind password must either both be set or both be empty")
	}
	if strings.TrimSpace(c.BaseDN) == "" {
		return fmt.Errorf("base DN is required")
	}
	if strings.TrimSpace(c.UserFilter) == "" || !strings.Contains(c.UserFilter, "{username}") {
		return fmt.Errorf("user filter must contain {username}")
	}
	if strings.TrimSpace(c.SubjectAttribute) == "" {
		return fmt.Errorf("subject attribute is required")
	}
	if len(c.RequiredGroups) > 0 && strings.TrimSpace(c.GroupAttribute) == "" {
		return fmt.Errorf("group attribute is required when required groups are configured")
	}
	if c.GroupMatchMode != "any" && c.GroupMatchMode != "all" {
		return fmt.Errorf("group match mode must be any or all")
	}
	if c.TimeoutSeconds < 1 || c.TimeoutSeconds > 60 {
		return fmt.Errorf("timeout must be between 1 and 60 seconds")
	}
	return nil
}

func (c Config) Timeout() time.Duration {
	return time.Duration(c.TimeoutSeconds) * time.Second
}

func stringValue(values map[string]any, key, fallback string) string {
	value, ok := values[key]
	if !ok || value == nil {
		return fallback
	}
	text, ok := value.(string)
	if !ok {
		return fallback
	}
	return strings.TrimSpace(text)
}

func rawStringValue(values map[string]any, key, fallback string) string {
	value, ok := values[key]
	if !ok || value == nil {
		return fallback
	}
	text, ok := value.(string)
	if !ok {
		return fallback
	}
	return text
}

func boolValue(values map[string]any, key string, fallback bool) bool {
	value, ok := values[key]
	if !ok || value == nil {
		return fallback
	}
	result, ok := value.(bool)
	if !ok {
		return fallback
	}
	return result
}

func intValue(values map[string]any, key string, fallback int) int {
	value, ok := values[key]
	if !ok || value == nil {
		return fallback
	}
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case float32:
		return int(typed)
	case int:
		return typed
	case int32:
		return int(typed)
	case int64:
		return int(typed)
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		if err == nil {
			return parsed
		}
	}
	return fallback
}

func splitList(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ';'
	})
	result := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key := strings.ToLower(part)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, part)
	}
	return result
}
