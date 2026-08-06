package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	publicmanifest "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/manifest"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestManifestIsValid(t *testing.T) {
	if _, err := publicmanifest.Load(manifestJSON); err != nil {
		t.Fatalf("manifest is invalid: %v", err)
	}
}

func TestConnectionTestRequested(t *testing.T) {
	metadata, err := structpb.NewStruct(map[string]any{"connection_test": true})
	if err != nil {
		t.Fatal(err)
	}
	if !connectionTestRequested(metadata) {
		t.Fatal("expected connection-test metadata to be detected")
	}

	metadata, err = structpb.NewStruct(map[string]any{"connection_test": false})
	if err != nil {
		t.Fatal(err)
	}
	if connectionTestRequested(metadata) {
		t.Fatal("unexpected connection-test detection")
	}
}

func TestLDAPAuthenticationFailureStage(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "nil", err: nil, want: "unknown"},
		{name: "deadline", err: context.DeadlineExceeded, want: "timeout"},
		{name: "canceled", err: context.Canceled, want: "request"},
		{name: "connection", err: errors.New("connect to LDAP: connection refused"), want: "connection"},
		{name: "search account", err: errors.New("bind LDAP search account: invalid credentials"), want: "search-account bind"},
		{name: "filter", err: errors.New("compile LDAP user filter: bad filter"), want: "user-filter compilation"},
		{name: "search", err: errors.New("search LDAP user: operations error"), want: "user search"},
		{name: "user bind", err: errors.New("bind LDAP user: unwilling to perform"), want: "user bind"},
		{name: "subject", err: errors.New("LDAP subject attribute \"objectGUID\" is missing"), want: "stable-subject mapping"},
		{name: "wrapped deadline", err: fmt.Errorf("connect to LDAP: %w", context.DeadlineExceeded), want: "timeout"},
		{name: "other", err: errors.New("unexpected directory error"), want: "directory processing"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ldapAuthenticationFailureStage(test.err); got != test.want {
				t.Fatalf("ldapAuthenticationFailureStage(%v) = %q, want %q", test.err, got, test.want)
			}
		})
	}
}
