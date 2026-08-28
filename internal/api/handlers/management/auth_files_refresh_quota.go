package management

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// RefreshAuthFileQuota asks a plugin auth provider to re-observe quota and
// persist the result on the auth record. Built-in providers keep their own
// collectors; this endpoint only handles plugin credentials.
func (h *Handler) RefreshAuthFileQuota(c *gin.Context) {
	if h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}

	var req struct {
		Name      string `json:"name"`
		AuthIndex string `json:"auth_index"`
	}
	if errBindJSON := c.ShouldBindJSON(&req); errBindJSON != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	auth, ok := h.lookupAuthFile(name, req.AuthIndex)
	if !ok || auth == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "auth not found"})
		return
	}
	if h.pluginHost == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "plugin host unavailable"})
		return
	}

	refreshed, handled, errRefresh := h.pluginHost.RefreshAuth(c.Request.Context(), auth)
	if errRefresh != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "plugin quota refresh failed"})
		return
	}
	if !handled || refreshed == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "auth is not a plugin credential"})
		return
	}
	if refreshed.Runtime == nil {
		refreshed.Runtime = auth.Runtime
	}

	updated, errUpdate := h.authManager.Update(c.Request.Context(), refreshed)
	if errUpdate != nil || updated == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist refreshed quota"})
		return
	}

	response := gin.H{"status": "ok", "name": strings.TrimSpace(updated.FileName)}
	if response["name"] == "" {
		response["name"] = updated.ID
	}
	if quota, okQuota := pluginQuotaMetadata(updated.Metadata[pluginQuotaMetadataKey]); okQuota {
		response["metadata"] = gin.H{pluginQuotaMetadataKey: quota}
	}
	c.JSON(http.StatusOK, response)
}
