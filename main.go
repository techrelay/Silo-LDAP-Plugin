package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	publicmanifest "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/manifest"
	sdkruntime "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtime"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtimedefault"
	"github.com/techrelay/Silo-LDAP-Plugin/internal/config"
	"github.com/techrelay/Silo-LDAP-Plugin/internal/ldapauth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	connectionTestMetadataKey = "connection_test"
	connectionTestAckClaimKey = "silo_connection_test_ok"
	siloRoleClaimKey          = "silo_role"
	siloRoleManagedClaimKey   = "silo_role_managed"
)

var version string

//go:embed manifest.json
var manifestJSON []byte

type runtimeServer struct {
	runtimedefault.Server

	manifest *pluginv1.PluginManifest
	auth     *authServer
}

func (s *runtimeServer) GetManifest(context.Context, *pluginv1.GetManifestRequest) (*pluginv1.GetManifestResponse, error) {
	return &pluginv1.GetManifestResponse{
		Manifest: proto.Clone(s.manifest).(*pluginv1.PluginManifest),
	}, nil
}

func (s *runtimeServer) Configure(_ context.Context, req *pluginv1.ConfigureRequest) (*pluginv1.ConfigureResponse, error) {
	cfg, configured, err := config.Decode(req.GetConfig())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid LDAP configuration: %v", err)
	}
	if !configured {
		s.auth.SetAuthenticator(nil)
		return &pluginv1.ConfigureResponse{}, nil
	}
	s.auth.SetAuthenticator(ldapauth.New(cfg))
	return &pluginv1.ConfigureResponse{}, nil
}

type ldapAuthenticator interface {
	CheckConnection(context.Context) error
	Authenticate(context.Context, string, string) (*ldapauth.User, error)
}

type authServer struct {
	pluginv1.UnimplementedAuthProviderServer

	mu            sync.RWMutex
	authenticator ldapAuthenticator
}

func (s *authServer) SetAuthenticator(authenticator ldapAuthenticator) {
	s.mu.Lock()
	s.authenticator = authenticator
	s.mu.Unlock()
}

func (s *authServer) Authenticate(ctx context.Context, req *pluginv1.AuthenticateRequest) (*pluginv1.AuthenticateResponse, error) {
	s.mu.RLock()
	authenticator := s.authenticator
	s.mu.RUnlock()
	if authenticator == nil {
		return nil, status.Error(codes.FailedPrecondition, "LDAP authentication is not configured")
	}

	if connectionTestRequested(req.GetMetadata()) {
		if err := authenticator.CheckConnection(ctx); err != nil {
			stage := ldapauth.StageOf(err)
			slog.ErrorContext(ctx, "LDAP connection check failed", "stage", stage, "error", err)
			return nil, status.Errorf(codes.Unavailable, "LDAP connection check failed during %s", stage)
		}
		claims, err := structpb.NewStruct(map[string]any{connectionTestAckClaimKey: true})
		if err != nil {
			return nil, status.Error(codes.Internal, "could not construct LDAP connection-check response")
		}
		return &pluginv1.AuthenticateResponse{Claims: claims}, nil
	}

	user, err := authenticator.Authenticate(ctx, req.GetUsername(), req.GetPassword())
	if err != nil {
		if errors.Is(err, ldapauth.ErrInvalidCredentials) || errors.Is(err, ldapauth.ErrGroupDenied) {
			return &pluginv1.AuthenticateResponse{}, nil
		}
		stage := ldapauth.StageOf(err)
		slog.ErrorContext(ctx, "LDAP authentication failed", "stage", stage, "error", err)
		return nil, status.Errorf(codes.Unavailable, "LDAP authentication failed during %s", stage)
	}

	claimValues := map[string]any{
		"username": user.Username,
		"dn":       user.DN,
		"groups":   stringsToAny(user.Groups),
	}
	if user.Role != "" {
		claimValues[siloRoleClaimKey] = user.Role
		claimValues[siloRoleManagedClaimKey] = true
	}
	claims, err := structpb.NewStruct(claimValues)
	if err != nil {
		return nil, status.Error(codes.Internal, "could not construct LDAP identity claims")
	}
	return &pluginv1.AuthenticateResponse{
		ExternalSubject: user.Subject,
		DisplayName:     user.DisplayName,
		Email:           user.Email,
		Claims:          claims,
	}, nil
}

func connectionTestRequested(metadata *structpb.Struct) bool {
	if metadata == nil {
		return false
	}
	value, ok := metadata.AsMap()[connectionTestMetadataKey].(bool)
	return ok && value
}

func stringsToAny(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func main() {
	manifest, err := publicmanifest.LoadWithChecksum(manifestJSON, version)
	if err != nil {
		panic(fmt.Errorf("load plugin manifest: %w", err))
	}

	auth := &authServer{}
	runtime := &runtimeServer{
		manifest: manifest,
		auth:     auth,
	}

	sdkruntime.Serve(sdkruntime.ServeConfig{
		Servers: sdkruntime.CapabilityServers{
			Runtime:      runtime,
			AuthProvider: auth,
		},
	})
}
