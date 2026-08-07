package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	publicmanifest "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/manifest"
	"github.com/techrelay/Silo-LDAP-Plugin/internal/ldapauth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

type stubLDAPAuthenticator struct {
	checkErr error
	user     *ldapauth.User
	authErr  error
}

func (s stubLDAPAuthenticator) CheckConnection(context.Context) error {
	return s.checkErr
}

func (s stubLDAPAuthenticator) Authenticate(context.Context, string, string) (*ldapauth.User, error) {
	return s.user, s.authErr
}

func TestManifestIsValid(t *testing.T) {
	if _, err := publicmanifest.Load(manifestJSON); err != nil {
		t.Fatalf("manifest is invalid: %v", err)
	}
}

func TestConnectionTestRequestedRequiresContract(t *testing.T) {
	metadata, err := structpb.NewStruct(map[string]any{
		connectionTestMetadataKey:         true,
		connectionTestContractMetadataKey: connectionTestContractV1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !connectionTestRequested(metadata) {
		t.Fatal("expected versioned connection-test metadata to be detected")
	}

	metadata, err = structpb.NewStruct(map[string]any{connectionTestMetadataKey: true})
	if err != nil {
		t.Fatal(err)
	}
	if connectionTestRequested(metadata) {
		t.Fatal("connection test without contract must not be accepted")
	}
}

func TestConnectionCheckReturnsExplicitAck(t *testing.T) {
	metadata, err := structpb.NewStruct(map[string]any{
		connectionTestMetadataKey:         true,
		connectionTestContractMetadataKey: connectionTestContractV1,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := &authServer{}
	server.SetAuthenticator(stubLDAPAuthenticator{})

	response, err := server.Authenticate(context.Background(), &pluginv1.AuthenticateRequest{Metadata: metadata})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	claims := response.GetClaims().AsMap()
	if claims[connectionTestAckClaimKey] != true {
		t.Fatalf("connection-test response = %#v, want %s=true", claims, connectionTestAckClaimKey)
	}
	if claims[connectionTestResponseContractClaimKey] != connectionTestContractV1 {
		t.Fatalf("connection-test response contract = %#v", claims[connectionTestResponseContractClaimKey])
	}
}

func TestAuthenticationFailureDoesNotExposeLDAPDetails(t *testing.T) {
	server := &authServer{}
	server.SetAuthenticator(stubLDAPAuthenticator{
		authErr: &ldapauth.StageError{
			Stage: ldapauth.StageConnection,
			Err:   errors.New("dial tcp dc01.internal.example:636: connection refused"),
		},
	})

	_, err := server.Authenticate(context.Background(), &pluginv1.AuthenticateRequest{
		Username: "alice",
		Password: "not-logged",
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("status code = %v, want %v", status.Code(err), codes.Unavailable)
	}
	message := status.Convert(err).Message()
	if message != "LDAP authentication failed during connection" {
		t.Fatalf("message = %q", message)
	}
	if strings.Contains(message, "dc01") || strings.Contains(message, "connection refused") {
		t.Fatalf("response leaked directory details: %q", message)
	}
}

func TestConnectionFailureDoesNotExposeLDAPDetails(t *testing.T) {
	metadata, err := structpb.NewStruct(map[string]any{
		connectionTestMetadataKey:         true,
		connectionTestContractMetadataKey: connectionTestContractV1,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := &authServer{}
	server.SetAuthenticator(stubLDAPAuthenticator{
		checkErr: &ldapauth.StageError{
			Stage: ldapauth.StageSearchAccountBind,
			Err:   errors.New("LDAP Result Code 49: invalid service account password"),
		},
	})

	_, err = server.Authenticate(context.Background(), &pluginv1.AuthenticateRequest{Metadata: metadata})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("status code = %v, want %v", status.Code(err), codes.Unavailable)
	}
	message := status.Convert(err).Message()
	if message != "LDAP connection check failed during search-account bind" {
		t.Fatalf("message = %q", message)
	}
	if strings.Contains(message, "password") || strings.Contains(message, "Result Code") {
		t.Fatalf("response leaked directory details: %q", message)
	}
}

func TestInvalidCredentialsRemainIndistinguishable(t *testing.T) {
	server := &authServer{}
	server.SetAuthenticator(stubLDAPAuthenticator{authErr: ldapauth.ErrInvalidCredentials})

	response, err := server.Authenticate(context.Background(), &pluginv1.AuthenticateRequest{
		Username: "missing-or-wrong",
		Password: "wrong",
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if response == nil || response.GetExternalSubject() != "" {
		t.Fatalf("unexpected invalid-credential response: %#v", response)
	}
}

func TestRoleClaimIsMarkedAndVersioned(t *testing.T) {
	server := &authServer{}
	server.SetAuthenticator(stubLDAPAuthenticator{user: &ldapauth.User{
		Subject:     "objectguid:0102",
		Username:    "alice",
		DisplayName: "Alice",
		Role:        "admin",
	}})

	response, err := server.Authenticate(context.Background(), &pluginv1.AuthenticateRequest{
		Username: "alice",
		Password: "correct",
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	claims := response.GetClaims().AsMap()
	if got := claims[siloRoleClaimKey]; got != "admin" {
		t.Fatalf("role claim = %#v, want admin", got)
	}
	if got := claims[siloRoleManagedClaimKey]; got != true {
		t.Fatalf("managed role marker = %#v, want true", got)
	}
	if got := claims[siloRoleContractClaimKey]; got != siloRoleContractV1 {
		t.Fatalf("managed role contract = %#v, want %q", got, siloRoleContractV1)
	}
}
