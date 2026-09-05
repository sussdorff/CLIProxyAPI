package management

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/credentialweight"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/htmlsanitize"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

var lastRefreshKeys = []string{"last_refresh", "lastRefresh", "last_refreshed_at", "lastRefreshedAt"}

var (
	callbackForwardersMu  sync.Mutex
	callbackForwarders    = make(map[int]*callbackForwarder)
	authFileEntryMu       sync.Mutex
	errAuthFileMustBeJSON = errors.New("auth file must be .json")
	errAuthFileNotFound   = errors.New("auth file not found")
	errPluginVirtualAuth  = errors.New("plugin virtual auth cannot be modified directly; edit or delete the source auth file")
	newCodexOAuthService  = func(cfg *config.Config) codexOAuthService { return codex.NewCodexAuth(cfg) }
)

func extractLastRefreshTimestamp(meta map[string]any) (time.Time, bool) {
	if len(meta) == 0 {
		return time.Time{}, false
	}
	for _, key := range lastRefreshKeys {
		if val, ok := meta[key]; ok {
			if ts, ok1 := parseLastRefreshValue(val); ok1 {
				return ts, true
			}
		}
	}
	return time.Time{}, false
}

func parseLastRefreshValue(v any) (time.Time, bool) {
	switch val := v.(type) {
	case string:
		s := strings.TrimSpace(val)
		if s == "" {
			return time.Time{}, false
		}
		layouts := []string{time.RFC3339, time.RFC3339Nano, "2006-01-02 15:04:05", "2006-01-02T15:04:05Z07:00"}
		for _, layout := range layouts {
			if ts, err := time.Parse(layout, s); err == nil {
				return ts.UTC(), true
			}
		}
		if unix, err := strconv.ParseInt(s, 10, 64); err == nil && unix > 0 {
			return time.Unix(unix, 0).UTC(), true
		}
	case float64:
		if val <= 0 {
			return time.Time{}, false
		}
		return time.Unix(int64(val), 0).UTC(), true
	case int64:
		if val <= 0 {
			return time.Time{}, false
		}
		return time.Unix(val, 0).UTC(), true
	case int:
		if val <= 0 {
			return time.Time{}, false
		}
		return time.Unix(int64(val), 0).UTC(), true
	case json.Number:
		if i, err := val.Int64(); err == nil && i > 0 {
			return time.Unix(i, 0).UTC(), true
		}
	}
	return time.Time{}, false
}

func (h *Handler) ListAuthFiles(c *gin.Context) {
	if h == nil {
		c.JSON(500, gin.H{"error": "handler not initialized"})
		return
	}
	if h.authManager == nil {
		h.listAuthFilesFromDisk(c)
		return
	}
	nameFilter := strings.TrimSpace(c.Query("name"))
	authIndexFilter := strings.TrimSpace(c.Query("auth_index"))
	auths := h.authManager.List()
	files := make([]gin.H, 0, len(auths))
	for _, auth := range auths {
		if !matchesAuthFileLookup(auth, nameFilter, authIndexFilter) {
			continue
		}
		if entry := h.buildAuthFileEntry(auth); entry != nil {
			files = append(files, entry)
		}
	}
	sort.Slice(files, func(i, j int) bool {
		nameI, _ := files[i]["name"].(string)
		nameJ, _ := files[j]["name"].(string)
		return strings.ToLower(nameI) < strings.ToLower(nameJ)
	})
	c.JSON(200, gin.H{"files": files})
}

func lockedAuthIndex(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	authFileEntryMu.Lock()
	defer authFileEntryMu.Unlock()
	return strings.TrimSpace(auth.EnsureIndex())
}

func matchesAuthFileLookup(auth *coreauth.Auth, name string, authIndex string) bool {
	if auth == nil {
		return false
	}
	if name != "" && strings.TrimSpace(auth.ID) != name && strings.TrimSpace(auth.FileName) != name {
		return false
	}
	if authIndex != "" && lockedAuthIndex(auth) != authIndex {
		return false
	}
	return true
}

func (h *Handler) lookupAuthFile(name string, authIndex string) (*coreauth.Auth, bool) {
	name = strings.TrimSpace(name)
	authIndex = strings.TrimSpace(authIndex)
	if h == nil || h.authManager == nil || name == "" {
		return nil, false
	}
	if authIndex == "" {
		if auth, ok := h.authManager.GetByID(name); ok {
			return auth, true
		}
		auths := h.authManager.List()
		for _, auth := range auths {
			if auth != nil && strings.TrimSpace(auth.FileName) == name {
				return auth, true
			}
		}
		return nil, false
	}
	auths := h.authManager.List()
	for _, auth := range auths {
		if matchesAuthFileLookup(auth, name, authIndex) {
			return auth, true
		}
	}
	return nil, false
}

// GetAuthFileModels returns the models supported by a specific auth file
func (h *Handler) GetAuthFileModels(c *gin.Context) {
	name := c.Query("name")
	if name == "" {
		c.JSON(400, gin.H{"error": "name is required"})
		return
	}

	// Try to find auth ID via authManager
	var authID string
	if h.authManager != nil {
		auths := h.authManager.List()
		for _, auth := range auths {
			if auth.FileName == name || auth.ID == name {
				authID = auth.ID
				break
			}
		}
	}

	if authID == "" {
		authID = name // fallback to filename as ID
	}

	// Get models from registry
	reg := registry.GetGlobalRegistry()
	models := reg.GetModelsForClient(authID)

	result := make([]gin.H, 0, len(models))
	for _, m := range models {
		entry := gin.H{
			"id": m.ID,
		}
		if m.DisplayName != "" {
			entry["display_name"] = m.DisplayName
		}
		if m.Type != "" {
			entry["type"] = m.Type
		}
		if m.OwnedBy != "" {
			entry["owned_by"] = m.OwnedBy
		}
		result = append(result, entry)
	}

	c.JSON(200, gin.H{"models": result})
}

// List auth files from disk when the auth manager is unavailable.
func (h *Handler) listAuthFilesFromDisk(c *gin.Context) {
	nameFilter := strings.TrimSpace(c.Query("name"))
	authIndexFilter := strings.TrimSpace(c.Query("auth_index"))
	entries, err := os.ReadDir(h.cfg.AuthDir)
	if err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("failed to read auth dir: %v", err)})
		return
	}
	files := make([]gin.H, 0)
	if authIndexFilter != "" {
		c.JSON(200, gin.H{"files": files})
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if nameFilter != "" && name != nameFilter {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(name), ".json") {
			continue
		}
		if info, errInfo := e.Info(); errInfo == nil {
			fileData := gin.H{"name": name, "size": info.Size(), "modtime": info.ModTime()}

			// Read file to get type field
			full := filepath.Join(h.cfg.AuthDir, name)
			if data, errRead := os.ReadFile(full); errRead == nil {
				typeValue := gjson.GetBytes(data, "type").String()
				emailValue := gjson.GetBytes(data, "email").String()
				fileData["type"] = typeValue
				fileData["email"] = emailValue
				if projectID := strings.TrimSpace(gjson.GetBytes(data, "project_id").String()); projectID != "" {
					fileData["project_id"] = projectID
				}
				if pv := gjson.GetBytes(data, "priority"); pv.Exists() {
					switch pv.Type {
					case gjson.Number:
						fileData["priority"] = int(pv.Int())
					case gjson.String:
						if parsed, errAtoi := strconv.Atoi(strings.TrimSpace(pv.String())); errAtoi == nil {
							fileData["priority"] = parsed
						}
					}
				}
				if wv := gjson.GetBytes(data, coreauth.AttributeWeight); wv.Exists() {
					var rawWeight string
					switch wv.Type {
					case gjson.Number:
						rawWeight = wv.Raw
					case gjson.String:
						rawWeight = wv.String()
					}
					if rawWeight != "" {
						if weight, errWeight := credentialweight.ParseString(rawWeight); errWeight == nil {
							fileData[coreauth.AttributeWeight] = weight
						}
					}
				}
				if nv := gjson.GetBytes(data, "note"); nv.Exists() && nv.Type == gjson.String {
					if trimmed := strings.TrimSpace(nv.String()); trimmed != "" {
						fileData["note"] = trimmed
					}
				}
				if wv := gjson.GetBytes(data, "websockets"); wv.Exists() {
					switch wv.Type {
					case gjson.True:
						fileData["websockets"] = true
					case gjson.False:
						fileData["websockets"] = false
					case gjson.String:
						if parsed, errParse := strconv.ParseBool(strings.TrimSpace(wv.String())); errParse == nil {
							fileData["websockets"] = parsed
						}
					}
				}
				if requestRetry, okRetry := authFileRequestRetryFromJSON(data); okRetry {
					fileData["request_retry"] = requestRetry
				}
			}

			files = append(files, fileData)
		}
	}
	c.JSON(200, gin.H{"files": files})
}

func (h *Handler) buildAuthFileEntry(auth *coreauth.Auth) gin.H {
	authFileEntryMu.Lock()
	defer authFileEntryMu.Unlock()
	return h.buildAuthFileEntryLocked(auth)
}

func (h *Handler) buildAuthFileEntryLocked(auth *coreauth.Auth) gin.H {
	if auth == nil {
		return nil
	}
	auth.EnsureIndex()
	runtimeOnly := isRuntimeOnlyAuth(auth)
	if runtimeOnly && (auth.Disabled || auth.Status == coreauth.StatusDisabled) {
		return nil
	}
	path := strings.TrimSpace(authAttribute(auth, "path"))
	if path == "" && !runtimeOnly {
		return nil
	}
	name := strings.TrimSpace(auth.FileName)
	if name == "" {
		name = auth.ID
	}
	entry := gin.H{
		"id":             auth.ID,
		"auth_index":     auth.Index,
		"name":           name,
		"type":           strings.TrimSpace(auth.Provider),
		"provider":       strings.TrimSpace(auth.Provider),
		"label":          auth.Label,
		"status":         auth.Status,
		"status_message": auth.StatusMessage,
		"disabled":       auth.Disabled,
		"unavailable":    auth.Unavailable,
		"runtime_only":   runtimeOnly,
		"source":         "memory",
		"size":           int64(0),
	}
	entry["success"] = auth.Success
	entry["failed"] = auth.Failed
	entry["recent_requests"] = auth.RecentRequestsSnapshot(time.Now())
	entry["quota"] = quotaObservationPayloadForProvider(auth.Provider, auth.Quota)
	if modelQuotas := modelQuotaObservationPayload(auth.Provider, auth.ModelStates); len(modelQuotas) > 0 {
		entry["model_quotas"] = modelQuotas
	}
	if email := authEmail(auth); email != "" {
		entry["email"] = email
	}
	if projectID := authProjectID(auth); projectID != "" {
		entry["project_id"] = projectID
	}
	if accountType, account := auth.AccountInfo(); accountType != "" || account != "" {
		if accountType != "" {
			entry["account_type"] = accountType
		}
		if account != "" {
			entry["account"] = account
		}
	}
	if !auth.CreatedAt.IsZero() {
		entry["created_at"] = auth.CreatedAt
	}
	if !auth.UpdatedAt.IsZero() {
		entry["modtime"] = auth.UpdatedAt
		entry["updated_at"] = auth.UpdatedAt
	}
	if !auth.LastRefreshedAt.IsZero() {
		entry["last_refresh"] = auth.LastRefreshedAt
	}
	if !auth.NextRetryAfter.IsZero() {
		entry["next_retry_after"] = auth.NextRetryAfter
	}
	if path != "" {
		entry["path"] = path
		entry["source"] = "file"
		if info, err := os.Stat(path); err == nil {
			entry["size"] = info.Size()
			entry["modtime"] = info.ModTime()
		} else if os.IsNotExist(err) {
			// Hide credentials removed from disk but still lingering in memory.
			if !runtimeOnly && (auth.Disabled || auth.Status == coreauth.StatusDisabled || strings.EqualFold(strings.TrimSpace(auth.StatusMessage), "removed via management api")) {
				return nil
			}
			entry["source"] = "memory"
		} else {
			log.WithError(err).Warnf("failed to stat auth file %s", path)
		}
	}
	if claims := extractCodexIDTokenClaims(auth); claims != nil {
		entry["id_token"] = claims
	}
	// Expose priority from Attributes (set by synthesizer from JSON "priority" field).
	// Fall back to Metadata for auths registered via UploadAuthFile (no synthesizer).
	if p := strings.TrimSpace(authAttribute(auth, "priority")); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil {
			entry["priority"] = parsed
		}
	} else if auth.Metadata != nil {
		if rawPriority, ok := auth.Metadata["priority"]; ok {
			switch v := rawPriority.(type) {
			case float64:
				entry["priority"] = int(v)
			case int:
				entry["priority"] = v
			case string:
				if parsed, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
					entry["priority"] = parsed
				}
			}
		}
	}
	// Expose note from Attributes (set by synthesizer from JSON "note" field).
	// Fall back to Metadata for auths registered via UploadAuthFile (no synthesizer).
	if note := strings.TrimSpace(authAttribute(auth, "note")); note != "" {
		entry["note"] = note
	} else if auth.Metadata != nil {
		if rawNote, ok := auth.Metadata["note"].(string); ok {
			if trimmed := strings.TrimSpace(rawNote); trimmed != "" {
				entry["note"] = trimmed
			}
		}
	}
	if weight, ok := authWeightValue(auth); ok {
		entry[coreauth.AttributeWeight] = weight
	}
	if websockets, ok := authWebsocketsValue(auth); ok {
		entry["websockets"] = websockets
	}
	if requestRetry, ok := auth.RequestRetryOverride(); ok {
		entry["request_retry"] = requestRetry
	}
	if metadata := authListMetadata(auth); len(metadata) > 0 {
		entry["metadata"] = metadata
	}
	return entry
}

// The generic plugin quota contract lets any plugin publish normalized quota
// windows that a manager UI can render without a provider-specific adapter. It
// travels under one auth-metadata key and carries consumption only.
const (
	pluginQuotaMetadataKey = "plugin_quota"
	pluginQuotaSchema      = "cliproxy.plugin.quota"
	// pluginQuotaSupportedVersion is the only contract version this build knows
	// how to project. A payload announcing any other version is not published,
	// because its fields cannot be assumed to still mean what is assumed here.
	pluginQuotaSupportedVersion = 1
	// maxPluginQuotaMetadataBytes bounds the encoded contract so an oversized
	// plugin payload cannot inflate every entry of the management response.
	maxPluginQuotaMetadataBytes = 64 << 10
	// maxPluginQuotaWindows and maxPluginQuotaTextBytes bound what one plugin
	// can place on an entry through the allowlisted fields themselves.
	maxPluginQuotaWindows   = 32
	maxPluginQuotaTextBytes = 256
	maxPluginQuotaDailyDays = 32
)

// The version-1 field allowlists. Auth metadata is plugin-controlled all the
// way down, so a well-formed envelope is no evidence that what it wraps is
// safe: the payload is projected field by field instead of copied, and any key
// not named here is dropped wherever it appears. That is what stops a hostile
// plugin from smuggling a token, cookie, profile path, or raw upstream body to
// the management API by nesting it inside an otherwise valid contract.
//
// schema, version and availability are handled separately because they are
// required and validated rather than merely copied; id is required per window.
var (
	pluginQuotaStringFields = []string{"provider", "observed_at"}
	pluginQuotaNumberFields = []string{"ttl_seconds"}

	pluginQuotaWindowStringFields = []string{"label", "kind", "unit", "window_start", "window_end", "reset_at", "reset_accuracy"}
	pluginQuotaWindowNumberFields = []string{"used", "limit", "remaining", "used_percent"}
	pluginQuotaWindowBoolFields   = []string{"unlimited"}

	pluginQuotaSpendStringFields = []string{"currency"}
	pluginQuotaSpendNumberFields = []string{
		"metered_cents", "today_cents", "period_cents", "latest_tokens", "period_tokens", "period_days",
	}
	pluginQuotaDailyStringFields = []string{"date"}
	pluginQuotaDailyNumberFields = []string{"cost_cents", "tokens"}
)

// authListMetadata returns the auth metadata a management client may observe.
// Auth metadata also holds credential material - refresh tokens, access tokens,
// id tokens, cookies, profile paths, persisted storage - so nothing is exposed
// by default. Only the keys named here are copied; every other key, known or
// unknown, stays omitted.
func authListMetadata(auth *coreauth.Auth) map[string]any {
	if auth == nil || len(auth.Metadata) == 0 {
		return nil
	}
	quota, ok := pluginQuotaMetadata(auth.Metadata[pluginQuotaMetadataKey])
	if !ok {
		return nil
	}
	return map[string]any{pluginQuotaMetadataKey: quota}
}

// pluginQuotaMetadata projects the plugin quota contract onto a detached,
// JSON-safe value built from the version-1 allowlist. Nothing is passed
// through: the result is assembled from named fields, so a field the plugin
// invented is dropped rather than republished.
//
// A malformed required envelope field fails the whole contract, since without
// schema, version, or availability a consumer cannot tell an observation from a
// placeholder. A malformed window is dropped on its own instead, matching how
// the consumer treats a window it cannot identify.
//
// Rejecting a payload never touches credential availability: the auth keeps its
// own status and stays in rotation with no quota to display.
func pluginQuotaMetadata(raw any) (map[string]any, bool) {
	payload, ok := decodePluginQuotaPayload(raw)
	if !ok {
		return nil, false
	}
	if schema, _ := payload["schema"].(string); schema != pluginQuotaSchema {
		return nil, false
	}
	version, okVersion := payload["version"].(float64)
	if !okVersion || version != pluginQuotaSupportedVersion {
		return nil, false
	}
	availability, okAvailability := payload["availability"].(string)
	if !okAvailability || len(availability) > maxPluginQuotaTextBytes {
		return nil, false
	}

	projected := map[string]any{
		"schema":       pluginQuotaSchema,
		"version":      version,
		"availability": availability,
	}
	copyAllowlistedStrings(projected, payload, pluginQuotaStringFields)
	copyAllowlistedNumbers(projected, payload, pluginQuotaNumberFields)
	projected["windows"] = projectPluginQuotaWindows(payload["windows"])
	if spend, ok := projectPluginQuotaSpend(payload["spend"]); ok {
		projected["spend"] = spend
	}
	if daily := projectPluginQuotaDaily(payload["daily"]); len(daily) > 0 {
		projected["daily"] = daily
	}
	sanitized, ok := htmlsanitize.JSONValue(projected).(map[string]any)
	if !ok {
		return nil, false
	}
	encoded, errMarshal := json.Marshal(sanitized)
	if errMarshal != nil || len(encoded) > maxPluginQuotaMetadataBytes {
		return nil, false
	}
	return sanitized, true
}

// decodePluginQuotaPayload detaches the plugin's value through a bounded JSON
// round trip, so the response encoder never walks a map a plugin still holds
// and an oversized payload is refused before it is inspected.
func decodePluginQuotaPayload(raw any) (map[string]any, bool) {
	if raw == nil {
		return nil, false
	}
	encoded, errMarshal := json.Marshal(raw)
	if errMarshal != nil || len(encoded) > maxPluginQuotaMetadataBytes {
		return nil, false
	}
	var payload map[string]any
	if errUnmarshal := json.Unmarshal(encoded, &payload); errUnmarshal != nil {
		return nil, false
	}
	return payload, true
}

// projectPluginQuotaWindows keeps only windows that carry a usable identity.
// The result is always non-nil so an unavailable contract serializes as an
// empty list rather than as null.
func projectPluginQuotaWindows(raw any) []any {
	items, _ := raw.([]any)
	windows := make([]any, 0, len(items))
	for _, item := range items {
		if len(windows) >= maxPluginQuotaWindows {
			break
		}
		source, okSource := item.(map[string]any)
		if !okSource {
			continue
		}
		id, okID := source["id"].(string)
		if !okID || strings.TrimSpace(id) == "" || len(id) > maxPluginQuotaTextBytes {
			continue
		}
		window := map[string]any{"id": id}
		copyAllowlistedStrings(window, source, pluginQuotaWindowStringFields)
		copyAllowlistedNumbers(window, source, pluginQuotaWindowNumberFields)
		for _, field := range pluginQuotaWindowBoolFields {
			if value, okValue := source[field].(bool); okValue {
				window[field] = value
			}
		}
		windows = append(windows, window)
	}
	return windows
}

func projectPluginQuotaSpend(raw any) (map[string]any, bool) {
	source, ok := raw.(map[string]any)
	if !ok {
		return nil, false
	}
	spend := map[string]any{}
	copyAllowlistedStrings(spend, source, pluginQuotaSpendStringFields)
	copyAllowlistedNumbers(spend, source, pluginQuotaSpendNumberFields)
	if len(spend) == 0 {
		return nil, false
	}
	return spend, true
}

func projectPluginQuotaDaily(raw any) []any {
	items, _ := raw.([]any)
	days := make([]any, 0, len(items))
	for _, item := range items {
		if len(days) >= maxPluginQuotaDailyDays {
			break
		}
		source, ok := item.(map[string]any)
		if !ok {
			continue
		}
		date, ok := source["date"].(string)
		if !ok || len(date) != 10 || len(date) > maxPluginQuotaTextBytes {
			continue
		}
		day := map[string]any{"date": date}
		copyAllowlistedNumbers(day, source, pluginQuotaDailyNumberFields)
		if _, hasCost := day["cost_cents"]; !hasCost {
			continue
		}
		days = append(days, day)
	}
	return days
}

// copyAllowlistedStrings copies the named text fields when present and within
// the size bound. An over-long value is dropped rather than truncated: a
// truncated timestamp would be a wrong value where an absent one is merely
// unknown, and truncating is not a bound an exfiltration attempt respects.
func copyAllowlistedStrings(dst, src map[string]any, fields []string) {
	for _, field := range fields {
		value, ok := src[field].(string)
		if !ok || len(value) > maxPluginQuotaTextBytes {
			continue
		}
		dst[field] = value
	}
}

// copyAllowlistedNumbers copies the named numeric fields. A value of any other
// JSON type is dropped rather than coerced.
func copyAllowlistedNumbers(dst, src map[string]any, fields []string) {
	for _, field := range fields {
		if value, ok := src[field].(float64); ok {
			dst[field] = value
		}
	}
}

func authFileRequestRetryFromJSON(data []byte) (int, bool) {
	var metadata map[string]any
	if errUnmarshal := json.Unmarshal(data, &metadata); errUnmarshal != nil {
		return 0, false
	}
	return (&coreauth.Auth{Metadata: metadata}).RequestRetryOverride()
}

// quotaObservationPayload exposes only passive provider observations. Cooldown
// fields are intentionally excluded so this management response cannot be
// mistaken for scheduler state or influence scheduling behavior.
func quotaObservationPayloadForProvider(provider string, quota coreauth.QuotaState) gin.H {
	if !coreauth.ProviderSupportsQuotaObservation(provider) {
		return quotaObservationPayload(coreauth.QuotaState{})
	}
	return quotaObservationPayload(quota)
}

func quotaObservationPayload(quota coreauth.QuotaState) gin.H {
	observed := gin.H{}
	if !quota.ObservedAt.IsZero() {
		observed["observed_at"] = quota.ObservedAt
	}
	signals := make(map[string]string, len(quota.Signals))
	for key, value := range quota.Signals {
		signals[key] = value
	}
	observed["signals"] = signals
	return observed
}

func modelQuotaObservationPayload(provider string, states map[string]*coreauth.ModelState) gin.H {
	if !coreauth.ProviderSupportsQuotaObservation(provider) {
		return gin.H{}
	}
	observations := gin.H{}
	for model, state := range states {
		if state == nil {
			continue
		}
		if state.Quota.ObservedAt.IsZero() && len(state.Quota.Signals) == 0 {
			continue
		}
		observations[model] = quotaObservationPayloadForProvider(provider, state.Quota)
	}
	return observations
}

func authWeightValue(auth *coreauth.Auth) (int64, bool) {
	if auth == nil {
		return 0, false
	}
	if rawWeight := strings.TrimSpace(authAttribute(auth, coreauth.AttributeWeight)); rawWeight != "" {
		weight, errWeight := credentialweight.ParseString(rawWeight)
		return weight, errWeight == nil
	}
	if auth.Metadata == nil {
		return 0, false
	}
	rawWeight, ok := auth.Metadata[coreauth.AttributeWeight]
	if !ok || rawWeight == nil {
		return 0, false
	}
	weight, errWeight := credentialweight.ParseValue(rawWeight)
	return weight, errWeight == nil
}

func authWebsocketsValue(auth *coreauth.Auth) (bool, bool) {
	if auth == nil {
		return false, false
	}
	if auth.Attributes != nil {
		if raw := strings.TrimSpace(auth.Attributes["websockets"]); raw != "" {
			parsed, errParse := strconv.ParseBool(raw)
			if errParse == nil {
				return parsed, true
			}
		}
	}
	if auth.Metadata == nil {
		return false, false
	}
	raw, ok := auth.Metadata["websockets"]
	if !ok || raw == nil {
		return false, false
	}
	switch v := raw.(type) {
	case bool:
		return v, true
	case string:
		parsed, errParse := strconv.ParseBool(strings.TrimSpace(v))
		if errParse == nil {
			return parsed, true
		}
	}
	return false, false
}

func authProjectID(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Metadata != nil {
		if v, ok := auth.Metadata["project_id"].(string); ok {
			if projectID := strings.TrimSpace(v); projectID != "" {
				return projectID
			}
		}
	}
	if auth.Attributes != nil {
		if projectID := strings.TrimSpace(auth.Attributes["project_id"]); projectID != "" {
			return projectID
		}
	}
	return ""
}

func extractCodexIDTokenClaims(auth *coreauth.Auth) gin.H {
	if auth == nil || auth.Metadata == nil {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return nil
	}
	idTokenRaw, ok := auth.Metadata["id_token"].(string)
	if !ok {
		return nil
	}
	idToken := strings.TrimSpace(idTokenRaw)
	if idToken == "" {
		return nil
	}
	claims, err := codex.ParseJWTToken(idToken)
	if err != nil || claims == nil {
		return nil
	}

	result := gin.H{}
	if v := strings.TrimSpace(claims.CodexAuthInfo.ChatgptAccountID); v != "" {
		result["chatgpt_account_id"] = v
	}
	if v := strings.TrimSpace(claims.CodexAuthInfo.ChatgptPlanType); v != "" {
		result["plan_type"] = v
	}
	if v := claims.CodexAuthInfo.ChatgptSubscriptionActiveStart; v != nil {
		result["chatgpt_subscription_active_start"] = v
	}
	if v := claims.CodexAuthInfo.ChatgptSubscriptionActiveUntil; v != nil {
		result["chatgpt_subscription_active_until"] = v
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

func authEmail(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Metadata != nil {
		if v, ok := auth.Metadata["email"].(string); ok {
			return strings.TrimSpace(v)
		}
	}
	if auth.Attributes != nil {
		if v := strings.TrimSpace(auth.Attributes["email"]); v != "" {
			return v
		}
		if v := strings.TrimSpace(auth.Attributes["account_email"]); v != "" {
			return v
		}
	}
	return ""
}

func authAttribute(auth *coreauth.Auth, key string) string {
	if auth == nil || len(auth.Attributes) == 0 {
		return ""
	}
	return auth.Attributes[key]
}

func isRuntimeOnlyAuth(auth *coreauth.Auth) bool {
	if auth == nil || len(auth.Attributes) == 0 {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(auth.Attributes["runtime_only"]), "true")
}

func isUnsafeAuthFileName(name string) bool {
	if strings.TrimSpace(name) == "" {
		return true
	}
	if strings.ContainsAny(name, "/\\") {
		return true
	}
	if filepath.VolumeName(name) != "" {
		return true
	}
	return false
}
