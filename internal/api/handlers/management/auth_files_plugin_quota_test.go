package management

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
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

// secretSentinels are the credential-material values planted beside the
// contract; nestedSecretSentinels are the ones planted inside it. Neither set
// may appear anywhere in a management list response.
func secretSentinels() []string {
	return []string{"SECRET-access-token", "SECRET-refresh-token", "SECRET-id-token", "SECRET-cookie-jar", "/SECRET/profile/path", "SECRET-storage-json", "SECRET-upstream-body", "SECRET-api-key"}
}

func nestedSecretSentinels() []string {
	return []string{"NESTED-access-token", "NESTED-refresh-token", "NESTED-cookie-jar", "/NESTED/profile/path", "NESTED-upstream-body", "NESTED-session-key"}
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
	for _, secret := range append(secretSentinels(), nestedSecretSentinels()...) {
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
		if key == "id" || key == "name" || key == "auth_index" || key == "created_at" || key == "modtime" || key == "updated_at" {
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

// hostilePluginQuotaFixture is a contract whose envelope and window carry the
// correct schema and version but smuggle credential material in extra fields.
// Auth metadata is plugin-controlled, so a valid-looking wrapper is not
// evidence that its contents are safe.
func hostilePluginQuotaFixture() map[string]any {
	contract := pluginQuotaContractFixture()
	contract["access_token"] = "NESTED-access-token"
	contract["refresh_token"] = "NESTED-refresh-token"
	contract["cookies"] = "NESTED-cookie-jar"
	contract["profile_dir"] = "/NESTED/profile/path"
	contract["raw_response"] = map[string]any{"body": "NESTED-upstream-body"}

	window := contract["windows"].([]any)[0].(map[string]any)
	window["session_key"] = "NESTED-session-key"
	window["debug"] = map[string]any{"upstream": "NESTED-upstream-body"}
	return contract
}

func TestListAuthFiles_DropsSecretsNestedInsidePluginQuota(t *testing.T) {
	metadata := secretMetadataFixture()
	metadata["type"] = "plugin-provider"
	metadata["plugin_quota"] = hostilePluginQuotaFixture()

	// listAuthFileEntries fails the test if any sentinel appears in the body.
	files := listAuthFileEntries(t, pluginAuthRecord("plugin-auth-1", metadata))
	if len(files) != 1 {
		t.Fatalf("expected 1 auth entry, got %d", len(files))
	}
	quota, ok := files[0]["metadata"].(map[string]any)["plugin_quota"].(map[string]any)
	if !ok {
		t.Fatalf("expected metadata.plugin_quota object, got %#v", files[0]["metadata"])
	}

	for _, field := range []string{"access_token", "refresh_token", "cookies", "profile_dir", "raw_response"} {
		if _, present := quota[field]; present {
			t.Fatalf("contract republished non-contract field %q: %#v", field, quota)
		}
	}

	// The allowlisted envelope survives the projection intact.
	if quota["schema"] != "cliproxy.plugin.quota" || quota["version"] != float64(1) {
		t.Fatalf("projection lost contract identity: %#v", quota)
	}
	if quota["availability"] != "available" || quota["provider"] != "cursor-acp" {
		t.Fatalf("projection lost envelope fields: %#v", quota)
	}
	if quota["observed_at"] != "2026-08-26T09:15:00Z" || quota["ttl_seconds"] != float64(900) {
		t.Fatalf("projection lost freshness fields: %#v", quota)
	}

	// The projection must be lossless for a real producer: these are exactly
	// the envelope fields the golden cursor-acp contract emits and the manager
	// UI reads, so a missing one would silently degrade a valid observation.
	envelope := make([]string, 0, len(quota))
	for field := range quota {
		envelope = append(envelope, field)
	}
	sort.Strings(envelope)
	wantEnvelope := []string{"availability", "observed_at", "provider", "schema", "ttl_seconds", "version", "windows"}
	if strings.Join(envelope, ",") != strings.Join(wantEnvelope, ",") {
		t.Fatalf("projected envelope = %v, want %v", envelope, wantEnvelope)
	}

	windows, ok := quota["windows"].([]any)
	if !ok || len(windows) != 1 {
		t.Fatalf("expected 1 projected window, got %#v", quota["windows"])
	}
	window := windows[0].(map[string]any)
	for _, field := range []string{"session_key", "debug"} {
		if _, present := window[field]; present {
			t.Fatalf("window republished non-contract field %q: %#v", field, window)
		}
	}
	want := map[string]any{
		"id": "subscription", "label": "Monthly usage", "kind": "monthly", "unit": "requests",
		"used": float64(125), "limit": float64(500), "remaining": float64(375),
		"used_percent": float64(25), "unlimited": false,
		"window_start": "2026-08-01T00:00:00Z", "window_end": "2026-09-01T00:00:00Z",
		"reset_at": "2026-09-01T00:00:00Z", "reset_accuracy": "exact",
	}
	for field, expected := range want {
		if window[field] != expected {
			t.Fatalf("window field %q = %#v, want %#v", field, window[field], expected)
		}
	}
	if len(window) != len(want) {
		t.Fatalf("window carries fields outside the version-1 allowlist: %#v", window)
	}
}

func TestPluginQuotaMetadataRejectsUnsupportedVersions(t *testing.T) {
	for _, version := range []any{0, 2, 99, -1, 1.5} {
		payload := pluginQuotaContractFixture()
		payload["version"] = version
		if got, ok := pluginQuotaMetadata(payload); ok {
			t.Fatalf("version %#v accepted: %#v", version, got)
		}
	}
}

func TestPluginQuotaMetadataRejectsMalformedRequiredFields(t *testing.T) {
	cases := map[string]func(map[string]any){
		"missing availability": func(p map[string]any) { delete(p, "availability") },
		"numeric availability": func(p map[string]any) { p["availability"] = 1 },
		"null availability":    func(p map[string]any) { p["availability"] = nil },
		"missing schema":       func(p map[string]any) { delete(p, "schema") },
		"missing version":      func(p map[string]any) { delete(p, "version") },
	}
	for name, mutate := range cases {
		payload := pluginQuotaContractFixture()
		mutate(payload)
		if got, ok := pluginQuotaMetadata(payload); ok {
			t.Fatalf("%s accepted: %#v", name, got)
		}
	}
}

func TestPluginQuotaMetadataDropsUnusableWindowsWithoutFailingTheContract(t *testing.T) {
	payload := pluginQuotaContractFixture()
	good := payload["windows"].([]any)[0]
	payload["windows"] = []any{
		map[string]any{"label": "no id"},
		map[string]any{"id": "   "},
		map[string]any{"id": 7},
		"not an object",
		good,
	}
	quota, ok := pluginQuotaMetadata(payload)
	if !ok {
		t.Fatalf("unusable windows failed the whole contract")
	}
	windows, _ := quota["windows"].([]any)
	if len(windows) != 1 {
		t.Fatalf("expected only the identifiable window, got %#v", windows)
	}
	if windows[0].(map[string]any)["id"] != "subscription" {
		t.Fatalf("kept the wrong window: %#v", windows[0])
	}
}

func TestPluginQuotaMetadataBoundsWindowsAndText(t *testing.T) {
	payload := pluginQuotaContractFixture()
	windows := make([]any, 0, 64)
	for i := 0; i < 64; i++ {
		windows = append(windows, map[string]any{"id": fmt.Sprintf("window-%d", i)})
	}
	payload["windows"] = windows
	quota, ok := pluginQuotaMetadata(payload)
	if !ok {
		t.Fatalf("bounded contract rejected")
	}
	if got := len(quota["windows"].([]any)); got != 32 {
		t.Fatalf("published %d windows, want the 32-window cap", got)
	}

	// An over-long allowlisted string is dropped rather than truncated, so a
	// bounded field can never carry a large exfiltration payload.
	payload = pluginQuotaContractFixture()
	payload["provider"] = strings.Repeat("x", 4096)
	payload["windows"].([]any)[0].(map[string]any)["label"] = strings.Repeat("y", 4096)
	quota, ok = pluginQuotaMetadata(payload)
	if !ok {
		t.Fatalf("contract with an over-long field rejected")
	}
	if _, present := quota["provider"]; present {
		t.Fatalf("over-long provider republished: %#v", quota["provider"])
	}
	window := quota["windows"].([]any)[0].(map[string]any)
	if _, present := window["label"]; present {
		t.Fatalf("over-long label republished: %#v", window["label"])
	}
	if window["id"] != "subscription" {
		t.Fatalf("bounding dropped the window identity: %#v", window)
	}
}

// An oversized encoded payload must not reach the response even when every
// individual field is within its own bound.
func TestPluginQuotaMetadataProjectsSpendAndDailyAllowlist(t *testing.T) {
	payload := pluginQuotaContractFixture()
	payload["spend"] = map[string]any{
		"currency": "USD", "metered_cents": 98655, "today_cents": 458,
		"period_cents": 124717, "latest_tokens": 2_900_000, "period_tokens": 1.1e9,
		"period_days": 30, "cookie": "WorkosCursorSessionToken=secret",
	}
	payload["daily"] = []any{
		map[string]any{"date": "2026-08-26", "cost_cents": 19800, "tokens": 12_000, "raw_event": "drop-me"},
		map[string]any{"date": "bad", "cost_cents": 1},
	}
	quota, ok := pluginQuotaMetadata(payload)
	if !ok {
		t.Fatal("contract with spend was rejected")
	}
	spend, _ := quota["spend"].(map[string]any)
	if spend["metered_cents"] != float64(98655) || spend["cookie"] != nil {
		t.Fatalf("spend projection = %#v", spend)
	}
	daily, _ := quota["daily"].([]any)
	if len(daily) != 1 {
		t.Fatalf("daily = %#v", daily)
	}
	day := daily[0].(map[string]any)
	if day["date"] != "2026-08-26" || day["raw_event"] != nil {
		t.Fatalf("daily row = %#v", day)
	}
}

func TestPluginQuotaMetadataKeepsEncodedSizeBound(t *testing.T) {
	payload := pluginQuotaContractFixture()
	windows := make([]any, 0, 4096)
	for i := 0; i < 4096; i++ {
		windows = append(windows, map[string]any{"id": fmt.Sprintf("window-%d", i), "label": strings.Repeat("z", 200)})
	}
	payload["windows"] = windows
	if got, ok := pluginQuotaMetadata(payload); ok {
		t.Fatalf("oversized contract accepted: %d windows", len(got["windows"].([]any)))
	}
}

func TestPluginQuotaMetadataSanitizesBeforeEnforcingEncodedSizeBound(t *testing.T) {
	payload := pluginQuotaContractFixture()
	windows := make([]any, 0, maxPluginQuotaWindows)
	for i := 0; i < maxPluginQuotaWindows; i++ {
		windows = append(windows, map[string]any{
			"id":    fmt.Sprintf("window-%d", i),
			"label": strings.Repeat("'", 200),
			"kind":  strings.Repeat("'", 200),
			"unit":  strings.Repeat("'", 200),
		})
	}
	payload["windows"] = windows
	encoded, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		t.Fatalf("marshal raw quota: %v", errMarshal)
	}
	if len(encoded) >= maxPluginQuotaMetadataBytes {
		t.Fatalf("raw quota size = %d, want below %d", len(encoded), maxPluginQuotaMetadataBytes)
	}
	if got, ok := pluginQuotaMetadata(payload); ok {
		t.Fatalf("quota expanded beyond the sanitized size limit was accepted: %#v", got)
	}
}

func TestPluginQuotaMetadataSanitizesAllowlistedStrings(t *testing.T) {
	payload := pluginQuotaContractFixture()
	payload["provider"] = "<script>alert('quota')</script>"
	quota, ok := pluginQuotaMetadata(payload)
	if !ok {
		t.Fatal("valid quota contract was rejected")
	}
	if quota["provider"] != html.EscapeString(payload["provider"].(string)) {
		t.Fatalf("provider was not sanitized: %#v", quota["provider"])
	}
}

func TestPluginQuotaMetadataDropsNonnumericTokenCounters(t *testing.T) {
	payload := pluginQuotaContractFixture()
	payload["spend"] = map[string]any{
		"latest_tokens": "secret-token-value",
		"period_tokens": map[string]any{"value": 1},
		"metered_cents": 42,
	}
	payload["daily"] = []any{
		map[string]any{"date": "2026-08-26", "cost_cents": 12, "tokens": []any{1}},
	}
	quota, ok := pluginQuotaMetadata(payload)
	if !ok {
		t.Fatal("valid quota contract was rejected")
	}
	spend := quota["spend"].(map[string]any)
	if _, exists := spend["latest_tokens"]; exists {
		t.Fatalf("string token counter was published: %#v", spend)
	}
	if _, exists := spend["period_tokens"]; exists {
		t.Fatalf("object token counter was published: %#v", spend)
	}
	if spend["metered_cents"] != float64(42) {
		t.Fatalf("numeric spend counter was not preserved: %#v", spend)
	}
	daily := quota["daily"].([]any)
	if _, exists := daily[0].(map[string]any)["tokens"]; exists {
		t.Fatalf("array token counter was published: %#v", daily[0])
	}
}
