package main

import (
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
