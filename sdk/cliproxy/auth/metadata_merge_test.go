package auth

import "testing"

func TestMergeExistingAuthMetadataDoesNotKeepAStaleProfileDir(t *testing.T) {
	target := &Auth{Metadata: map[string]any{"plugin_quota": map[string]any{"availability": "available"}}}
	MergeExistingAuthMetadata(target, map[string]any{
		"profile_dir":   "/stale/profile",
		"plugin_quota":  map[string]any{"availability": "unavailable"},
		"operator_note": "keep",
	})
	if _, exists := target.Metadata["profile_dir"]; exists {
		t.Fatalf("stale profile_dir was merged: %#v", target.Metadata)
	}
	if target.Metadata["operator_note"] != "keep" {
		t.Fatalf("operator metadata = %#v", target.Metadata["operator_note"])
	}
	quota, _ := target.Metadata["plugin_quota"].(map[string]any)
	if quota["availability"] != "available" {
		t.Fatalf("plugin_quota was replaced by the stale file: %#v", target.Metadata["plugin_quota"])
	}
}
