package config

import (
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestDecodeAllowsMissingConfig(t *testing.T) {
	cfg, configured, err := Decode(nil)
	if err != nil {
		t.Fatalf("Decode returned an error: %v", err)
	}
	if configured {
		t.Fatal("expected missing configuration to remain unconfigured")
	}
	if cfg.TimeoutSeconds != 10 {
		t.Fatalf("default timeout = %d, want 10", cfg.TimeoutSeconds)
	}
}

func TestDecodeValidLDAPSConfig(t *testing.T) {
	value, err := structpb.NewStruct(map[string]any{
		"url":                    "ldaps://ldap.example.com:636",
		"base_dn":                "dc=example,dc=com",
		"bind_dn":                "cn=silo,dc=example,dc=com",
		"bind_password":          "secret",
		"required_groups":        "cn=silo-users,ou=groups,dc=example,dc=com\ncn=media,ou=groups,dc=example,dc=com",
		"group_match_mode":       "all",
		"role_sync_enabled":      true,
		"admin_groups":           "cn=silo-admins,ou=groups,dc=example,dc=com",
		"admin_group_match_mode": "any",
		"timeout_seconds":        15,
		"subject_attribute":      "entryUUID",
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg, configured, err := Decode([]*pluginv1.ConfigEntry{{Key: EntryKey, Value: value}})
	if err != nil {
		t.Fatalf("Decode returned an error: %v", err)
	}
	if !configured {
		t.Fatal("expected configuration to be detected")
	}
	if len(cfg.RequiredGroups) != 2 {
		t.Fatalf("required groups = %d, want 2", len(cfg.RequiredGroups))
	}
	if cfg.GroupMatchMode != "all" {
		t.Fatalf("group match mode = %q, want all", cfg.GroupMatchMode)
	}
	if !cfg.RoleSyncEnabled {
		t.Fatal("expected role synchronization to be enabled")
	}
	if len(cfg.AdminGroups) != 1 {
		t.Fatalf("administrator groups = %d, want 1", len(cfg.AdminGroups))
	}
}

func TestValidateRejectsPlaintextByDefault(t *testing.T) {
	cfg := Default()
	cfg.URL = "ldap://ldap.example.com:389"
	cfg.BaseDN = "dc=example,dc=com"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected plaintext LDAP configuration to be rejected")
	}
}

func TestValidateRequiresAdminGroupForRoleSync(t *testing.T) {
	cfg := Default()
	cfg.URL = "ldaps://ldap.example.com:636"
	cfg.BaseDN = "dc=example,dc=com"
	cfg.RoleSyncEnabled = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected role synchronization without an administrator group to be rejected")
	}
}
