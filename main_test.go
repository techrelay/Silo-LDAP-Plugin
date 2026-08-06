package main

import (
	"testing"

	publicmanifest "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/manifest"
)

func TestManifestIsValid(t *testing.T) {
	if _, err := publicmanifest.Load(manifestJSON); err != nil {
		t.Fatalf("manifest is invalid: %v", err)
	}
}
