package test

import (
	"os"
	"strings"
	"testing"
)

func TestForkMainImageWorkflowContract(t *testing.T) {
	raw, err := os.ReadFile("../.github/workflows/fork-main-image.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(raw)
	for _, required := range []string{
		"branches: [main]",
		"packages: write",
		"cancel-in-progress: false",
		"ghcr.io/sussdorff/cli-proxy-api",
		"linux/amd64,linux/arm64",
		"type=raw,value=${{ github.sha }}",
		"type=raw,value=main",
		"org.opencontainers.image.source=https://github.com/sussdorff/CLIProxyAPI",
		"org.opencontainers.image.revision=${{ github.sha }}",
		"org.opencontainers.image.created=${{ steps.build_context.outputs.created }}",
		"GITHUB_REPOSITORY",
		`GITHUB_REF}" != "refs/heads/main`,
		"^[0-9a-f]{40}$",
		"image_digest: ${{ steps.build.outputs.digest }}",
		"id: build",
		"GITHUB_STEP_SUMMARY",
		`"digest":"%s"`,
		`"${{ steps.build.outputs.digest }}"`,
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("workflow is missing %q", required)
		}
	}
	if strings.Contains(workflow, "eceasy/cli-proxy-api") || strings.Contains(workflow, "router-for-me/CLIProxyAPI") {
		t.Fatal("fork main workflow may not publish or identify itself as upstream")
	}
	if strings.Contains(workflow, "cancel-in-progress: true") {
		t.Fatal("a newer main build may not cancel publication for an older main SHA")
	}
}

func TestDockerfileCarriesForkProvenance(t *testing.T) {
	raw, err := os.ReadFile("../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	dockerfile := string(raw)
	for _, required := range []string{
		"ARG SOURCE=unknown", "ARG REVISION=unknown", "ARG CREATED=unknown",
		`org.opencontainers.image.source="$SOURCE"`,
		`org.opencontainers.image.revision="$REVISION"`,
		`org.opencontainers.image.created="$CREATED"`,
	} {
		if !strings.Contains(dockerfile, required) {
			t.Errorf("Dockerfile is missing %q", required)
		}
	}
}
