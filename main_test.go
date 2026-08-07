package main

import (
	"context"
	"errors"
	"testing"

	publicmanifest "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/manifest"
	"github.com/techrelay/Silo-LDAP-Plugin/internal/ldapauth"
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

func TestAuthenticationFailureStageUsesSentinels(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "nil", err: nil, want: "unknown"},
		{name: "deadline", err: context.DeadlineExceeded, want: "timeout"},
		{name: "canceled", err: context.Canceled, want: "request"},
		{name: "connection", err: ldapauth.ErrStageConnection, want: "connection"},
		{name: "search bind", err: ldapauth.ErrStageSearchBind, want: "search-account bind"},
		{name: "user filter", err: ldapauth.ErrStageUserFilter, want: "user-filter compilation"},
		{name: "filter validate", err: ldapauth.ErrStageFilterValidate, want: "user-filter compilation"},
		{name: "user search", err: ldapauth.ErrStageUserSearch, want: "user search"},
		{name: "search base", err: ldapauth.ErrStageSearchBaseQuery, want: "user search"},
		{name: "user bind", err: ldapauth.ErrStageUserBind, want: "user bind"},
		{name: "subject", err: ldapauth.ErrStageSubjectMapping, want: "stable-subject mapping"},
		{name: "group query", err: ldapauth.ErrStageGroupQuery, want: "group validation"},
		{name: "group not found", err: ldapauth.ErrStageGroupNotFound, want: "group validation"},
		{name: "other", err: errors.New("unexpected directory error"), want: "directory processing"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ldapauth.AuthenticationFailureStage(test.err); got != test.want {
				t.Fatalf("AuthenticationFailureStage(%v) = %q, want %q", test.err, got, test.want)
			}
		})
	}
}