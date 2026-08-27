package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// pluginQuotaContractFixture mirrors the generic plugin quota contract as a
// plugin publishes it: a provider-neutral, versioned payload parked under one
// auth-metadata key.
func pluginQuotaContractFixture() map[string]any {
	return map[string]any{
		"schema":       "cliproxy.plugin.quota",
		"version":      1,
		"provider":     "cursor-acp",
		"availability": "available",
		"observed_at":  "2026-08-26T09:15:00Z",
		"ttl_seconds":  900,
		"windows": []any{
			map[string]any{
				"id":             "subscription",
				"label":          "Monthly usage",
				"kind":           "monthly",
				"unit":           "requests",
				"used":           125,
				"limit":          500,
				"remaining":      375,
				"used_percent":   25,
				"unlimited":      false,
				"window_start":   "2026-08-01T00:00:00Z",
				"window_end":     "2026-09-01T00:00:00Z",
				"reset_at":       "2026-09-01T00:00:00Z",
				"reset_accuracy": "exact",
			},
		},
	}
}

// secretMetadataFixture carries the credential material auth metadata really
// holds. None of it may reach a management list response.
func secretMetadataFixture() map[string]any {
	return map[string]any{
		"access_token":  "SECRET-access-token",
		"refresh_token": "SECRET-refresh-token",
		"id_token":      "SECRET-id-token",
		"cookies":       "SECRET-cookie-jar",
		"profile_dir":   "/SECRET/profile/path",
		"StorageJSON":   "SECRET-storage-json",
		"raw_response":  map[string]any{"body": "SECRET-upstream-body"},
		"api_key":       "SECRET-api-key",
	}
}

func listAuthFileEntries(t *testing.T, records ...*coreauth.Auth) []map[string]any {
	t.Helper()
	t.Setenv("MANAGEMENT_PASSWORD", "")

	manager := coreauth.NewManager(nil, nil, nil)
	for _, record := range records {
		if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
			t.Fatalf("failed to register auth record %s: %v", record.ID, errRegister)
		}
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	h.tokenStore = &memoryAuthStore{}

	rec := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(rec)
	ginCtx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files", nil)
	h.ListAuthFiles(ginCtx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected list status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	for _, secret := range []string{"SECRET-access-token", "SECRET-refresh-token", "SECRET-id-token", "SECRET-cookie-jar", "/SECRET/profile/path", "SECRET-storage-json", "SECRET-upstream-body", "SECRET-api-key"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("auth-files response leaked %q: %s", secret, rec.Body.String())
		}
	}

	var payload struct {
		Files []map[string]any `json:"files"`
	}
	if errUnmarshal := json.Unmarshal(rec.Body.Bytes(), &payload); errUnmarshal != nil {
		t.Fatalf("failed to decode list payload: %v", errUnmarshal)
	}
	return payload.Files
}

func pluginAuthRecord(id string, metadata map[string]any) *coreauth.Auth {
	return &coreauth.Auth{
		ID:         id,
		Provider:   "plugin-provider",
		Label:      "cursor account",
		Attributes: map[string]string{"runtime_only": "true"},
		Metadata:   metadata,
	}
}

func TestListAuthFiles_ExposesPluginQuotaMetadata(t *testing.T) {
	metadata := secretMetadataFixture()
	metadata["type"] = "plugin-provider"
	metadata["plugin_quota"] = pluginQuotaContractFixture()

	files := listAuthFileEntries(t, pluginAuthRecord("plugin-auth-1", metadata))
	if len(files) != 1 {
		t.Fatalf("expected 1 auth entry, got %d", len(files))
	}

	entryMetadata, ok := files[0]["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("expected metadata object on list entry, got %#v", files[0]["metadata"])
	}
	if len(entryMetadata) != 1 {
		t.Fatalf("metadata exposed keys outside the allowlist: %#v", entryMetadata)
	}
	quota, ok := entryMetadata["plugin_quota"].(map[string]any)
	if !ok {
		t.Fatalf("expected metadata.plugin_quota object, got %#v", entryMetadata["plugin_quota"])
	}
	if quota["schema"] != "cliproxy.plugin.quota" {
		t.Fatalf("plugin_quota schema = %#v, want cliproxy.plugin.quota", quota["schema"])
	}
	if quota["version"] != float64(1) {
		t.Fatalf("plugin_quota version = %#v, want 1", quota["version"])
	}
	if quota["availability"] != "available" {
		t.Fatalf("plugin_quota availability = %#v, want available", quota["availability"])
	}
	windows, ok := quota["windows"].([]any)
	if !ok || len(windows) != 1 {
		t.Fatalf("expected 1 published window, got %#v", quota["windows"])
	}
	window, ok := windows[0].(map[string]any)
	if !ok {
		t.Fatalf("expected window object, got %#v", windows[0])
	}
	if window["id"] != "subscription" || window["used"] != float64(125) || window["limit"] != float64(500) {
		t.Fatalf("window lost contract fields: %#v", window)
	}
}

func TestListAuthFiles_OmitsMetadataWithoutPluginQuota(t *testing.T) {
	metadata := secretMetadataFixture()
	metadata["type"] = "plugin-provider"

	files := listAuthFileEntries(t, pluginAuthRecord("plugin-auth-1", metadata))
	if len(files) != 1 {
		t.Fatalf("expected 1 auth entry, got %d", len(files))
	}
	if raw, ok := files[0]["metadata"]; ok {
		t.Fatalf("metadata exposed without a plugin quota contract: %#v", raw)
	}
}

func TestListAuthFiles_PluginQuotaLeavesExistingFieldsUnchanged(t *testing.T) {
	withoutQuota := secretMetadataFixture()
	withoutQuota["type"] = "plugin-provider"
	withQuota := secretMetadataFixture()
	withQuota["type"] = "plugin-provider"
	withQuota["plugin_quota"] = pluginQuotaContractFixture()

	files := listAuthFileEntries(t,
		pluginAuthRecord("plugin-auth-1", withoutQuota),
		pluginAuthRecord("plugin-auth-2", withQuota),
	)
	if len(files) != 2 {
		t.Fatalf("expected 2 auth entries, got %d", len(files))
	}

	byID := map[string]map[string]any{}
	for _, file := range files {
		id, _ := file["id"].(string)
		byID[id] = file
	}
	baseline, quotaEntry := byID["plugin-auth-1"], byID["plugin-auth-2"]
	if baseline == nil || quotaEntry == nil {
		t.Fatalf("missing auth entries: %#v", byID)
	}

	for key, want := range baseline {
		if key == "id" || key == "name" || key == "auth_index" {
			continue
		}
		got, ok := quotaEntry[key]
		if !ok {
			t.Fatalf("publishing plugin quota dropped existing field %q", key)
		}
		wantJSON, _ := json.Marshal(want)
		gotJSON, _ := json.Marshal(got)
		if string(wantJSON) != string(gotJSON) {
			t.Fatalf("publishing plugin quota changed field %q: %s != %s", key, gotJSON, wantJSON)
		}
	}

	added := make([]string, 0, 1)
	for key := range quotaEntry {
		if _, ok := baseline[key]; !ok {
			added = append(added, key)
		}
	}
	sort.Strings(added)
	if len(added) != 1 || added[0] != "metadata" {
		t.Fatalf("publishing plugin quota added unexpected fields: %v", added)
	}
}

func TestAuthListMetadataRejectsPayloadsOutsideTheContract(t *testing.T) {
	cases := map[string]any{
		"nil payload":     nil,
		"wrong schema":    map[string]any{"schema": "some.other.schema", "version": 1},
		"missing schema":  map[string]any{"version": 1, "availability": "available"},
		"missing version": map[string]any{"schema": "cliproxy.plugin.quota"},
		"string version":  map[string]any{"schema": "cliproxy.plugin.quota", "version": "1"},
		"not an object":   "cliproxy.plugin.quota",
		"array payload":   []any{map[string]any{"schema": "cliproxy.plugin.quota", "version": 1}},
		"unmarshalable":   make(chan int),
	}
	for name, payload := range cases {
		auth := &coreauth.Auth{ID: "plugin-auth-1", Metadata: map[string]any{"plugin_quota": payload}}
		if got := authListMetadata(auth); got != nil {
			t.Fatalf("%s republished as metadata: %#v", name, got)
		}
	}

	if got := authListMetadata(nil); got != nil {
		t.Fatalf("nil auth returned metadata: %#v", got)
	}
	if got := authListMetadata(&coreauth.Auth{ID: "plugin-auth-1"}); got != nil {
		t.Fatalf("auth without metadata returned metadata: %#v", got)
	}
}
