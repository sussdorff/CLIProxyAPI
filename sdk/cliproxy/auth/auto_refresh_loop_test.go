package auth

import (
	"strings"
	"testing"
	"time"
)

type testRefreshEvaluator struct{}

func (testRefreshEvaluator) ShouldRefresh(time.Time, *Auth) bool { return false }

func setRefreshLeadFactory(t *testing.T, provider string, factory func() *time.Duration) {
	t.Helper()
	key := strings.ToLower(strings.TrimSpace(provider))
	refreshLeadMu.Lock()
	prev, hadPrev := refreshLeadFactories[key]
	if factory == nil {
		delete(refreshLeadFactories, key)
	} else {
		refreshLeadFactories[key] = factory
	}
	refreshLeadMu.Unlock()
	t.Cleanup(func() {
		refreshLeadMu.Lock()
		if hadPrev {
			refreshLeadFactories[key] = prev
		} else {
			delete(refreshLeadFactories, key)
		}
		refreshLeadMu.Unlock()
	})
}

func TestNextRefreshCheckAt_DisabledUnschedule(t *testing.T) {
	now := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)
	expiry := now.Add(time.Hour)
	lead := 10 * time.Minute
	setRefreshLeadFactory(t, "disabled-schedule", func() *time.Duration {
		d := lead
		return &d
	})

	auth := &Auth{
		ID:       "a1",
		Provider: "disabled-schedule",
		Disabled: true,
		Status:   StatusDisabled,
		Metadata: map[string]any{
			"email":      "x@example.com",
			"expires_at": expiry.Format(time.RFC3339),
		},
	}

	got, ok := nextRefreshCheckAt(now, auth, 15*time.Minute)
	if !ok {
		t.Fatalf("nextRefreshCheckAt() ok = false, want true")
	}
	want := expiry.Add(-lead)
	if !got.Equal(want) {
		t.Fatalf("nextRefreshCheckAt() = %s, want %s", got, want)
	}
}

func TestNextRefreshCheckAt_APIKeyUnschedule(t *testing.T) {
	now := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)
	auth := &Auth{ID: "a1", Provider: "test", Attributes: map[string]string{"api_key": "k"}}
	if _, ok := nextRefreshCheckAt(now, auth, 15*time.Minute); ok {
		t.Fatalf("nextRefreshCheckAt() ok = true, want false")
	}
}

func TestNextRefreshCheckAt_NextRefreshAfterGate(t *testing.T) {
	now := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)
	nextAfter := now.Add(30 * time.Minute)
	auth := &Auth{
		ID:               "a1",
		Provider:         "test",
		NextRefreshAfter: nextAfter,
		Metadata:         map[string]any{"email": "x@example.com"},
	}
	got, ok := nextRefreshCheckAt(now, auth, 15*time.Minute)
	if !ok {
		t.Fatalf("nextRefreshCheckAt() ok = false, want true")
	}
	if !got.Equal(nextAfter) {
		t.Fatalf("nextRefreshCheckAt() = %s, want %s", got, nextAfter)
	}
}

func TestNextRefreshAfterControlsSchedulingAndDueRefresh(t *testing.T) {
	deadline := time.Date(2026, 4, 12, 0, 30, 0, 0, time.UTC)
	auth := &Auth{
		ID:               "a1",
		Provider:         "test",
		NextRefreshAfter: deadline,
		Metadata:         map[string]any{"email": "x@example.com"},
	}
	manager := NewManager(nil, &RoundRobinSelector{}, nil)

	testCases := []struct {
		name        string
		now         time.Time
		wantNext    time.Time
		wantRefresh bool
	}{
		{
			name:        "before deadline schedules the refresh",
			now:         deadline.Add(-time.Second),
			wantNext:    deadline,
			wantRefresh: false,
		},
		{
			name:        "at deadline is due",
			now:         deadline,
			wantNext:    deadline,
			wantRefresh: true,
		},
		{
			name:        "after deadline is due",
			now:         deadline.Add(time.Second),
			wantNext:    deadline.Add(time.Second),
			wantRefresh: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			gotNext, scheduled := nextRefreshCheckAt(testCase.now, auth, 15*time.Minute)
			if !scheduled {
				t.Fatal("nextRefreshCheckAt() scheduled = false, want true")
			}
			if !gotNext.Equal(testCase.wantNext) {
				t.Fatalf("nextRefreshCheckAt() = %s, want %s", gotNext, testCase.wantNext)
			}
			if gotRefresh := manager.shouldRefresh(auth, testCase.now); gotRefresh != testCase.wantRefresh {
				t.Fatalf("shouldRefresh() = %t, want %t", gotRefresh, testCase.wantRefresh)
			}
		})
	}
}

func TestNextRefreshCheckAt_PreferredInterval_PicksEarliestCandidate(t *testing.T) {
	now := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)
	expiry := now.Add(20 * time.Minute)
	auth := &Auth{
		ID:              "a1",
		Provider:        "test",
		LastRefreshedAt: now,
		Metadata: map[string]any{
			"email":                    "x@example.com",
			"expires_at":               expiry.Format(time.RFC3339),
			"refresh_interval_seconds": 900, // 15m
		},
	}
	got, ok := nextRefreshCheckAt(now, auth, 15*time.Minute)
	if !ok {
		t.Fatalf("nextRefreshCheckAt() ok = false, want true")
	}
	want := expiry.Add(-15 * time.Minute)
	if !got.Equal(want) {
		t.Fatalf("nextRefreshCheckAt() = %s, want %s", got, want)
	}
}

func TestNextRefreshCheckAt_ProviderLead_Expiry(t *testing.T) {
	now := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)
	expiry := now.Add(time.Hour)
	lead := 10 * time.Minute
	setRefreshLeadFactory(t, "provider-lead-expiry", func() *time.Duration {
		d := lead
		return &d
	})

	auth := &Auth{
		ID:       "a1",
		Provider: "provider-lead-expiry",
		Metadata: map[string]any{
			"email":      "x@example.com",
			"expires_at": expiry.Format(time.RFC3339),
		},
	}

	got, ok := nextRefreshCheckAt(now, auth, 15*time.Minute)
	if !ok {
		t.Fatalf("nextRefreshCheckAt() ok = false, want true")
	}
	want := expiry.Add(-lead)
	if !got.Equal(want) {
		t.Fatalf("nextRefreshCheckAt() = %s, want %s", got, want)
	}
}

func TestNextRefreshCheckAt_RelativeExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)
	issuedAt := now.Add(-15 * time.Minute)
	lead := 30 * time.Minute
	setRefreshLeadFactory(t, "relative-expiry", func() *time.Duration {
		d := lead
		return &d
	})

	auth := &Auth{
		ID:       "relative-expiry-auth",
		Provider: "relative-expiry",
		Metadata: map[string]any{
			"access_token": "test-access",
			"expires_in":   3600,
			"timestamp":    int(issuedAt.UnixMilli()),
		},
	}

	got, ok := nextRefreshCheckAt(now, auth, 15*time.Minute)
	want := issuedAt.Add(time.Hour - lead)
	if !ok || !got.Equal(want) {
		t.Fatalf("nextRefreshCheckAt() = (%s, %t), want (%s, true)", got, ok, want)
	}
}

func TestNextRefreshCheckAt_RefreshEvaluatorFallback(t *testing.T) {
	now := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)
	interval := 15 * time.Minute
	auth := &Auth{
		ID:       "a1",
		Provider: "test",
		Metadata: map[string]any{"email": "x@example.com"},
		Runtime:  testRefreshEvaluator{},
	}
	got, ok := nextRefreshCheckAt(now, auth, interval)
	if !ok {
		t.Fatalf("nextRefreshCheckAt() ok = false, want true")
	}
	want := now.Add(interval)
	if !got.Equal(want) {
		t.Fatalf("nextRefreshCheckAt() = %s, want %s", got, want)
	}
}
