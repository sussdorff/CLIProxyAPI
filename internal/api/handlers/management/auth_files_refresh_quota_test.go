package management

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestRefreshAuthFileQuotaRejectsUnusableRequests(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	manager := coreauth.NewManager(nil, nil, nil)
	if _, err := manager.Register(context.Background(), pluginAuthRecord("plugin-auth-1", map[string]any{"type": "cursor-acp"})); err != nil {
		t.Fatal(err)
	}
	handler := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)

	cases := []struct {
		name string
		body string
		want int
	}{
		{name: "missing name", body: `{}`, want: http.StatusBadRequest},
		{name: "unknown auth", body: `{"name":"missing.json"}`, want: http.StatusNotFound},
		{name: "no plugin host", body: `{"name":"plugin-auth-1"}`, want: http.StatusServiceUnavailable},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ginCtx, _ := gin.CreateTestContext(recorder)
			ginCtx.Request = httptest.NewRequest(http.MethodPost, "/v0/management/auth-files/refresh-quota", strings.NewReader(testCase.body))
			ginCtx.Request.Header.Set("Content-Type", "application/json")
			handler.RefreshAuthFileQuota(ginCtx)
			if recorder.Code != testCase.want {
				t.Fatalf("status = %d, want %d body=%s", recorder.Code, testCase.want, recorder.Body.String())
			}
		})
	}
}
