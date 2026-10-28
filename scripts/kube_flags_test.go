package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type flagsResult struct {
	kubeFlags  []string
	remaining  []string
	namespace  string
	targetHost string
	display    string
	hint       string
}

// extractFlags sources functions.sh and runs extract_kube_flags with the given args
func extractFlags(t *testing.T, env []string, args ...string) (flagsResult, error) {
	t.Helper()
	script := `
source ./functions.sh >/dev/null
extract_kube_flags "$@" >/dev/null
rm -rf "$MANIFEST_OUTPUT_PATH"
K8S_CLI_BIN=oc
printf 'FLAG\t%s\n' "${KUBE_FLAGS[@]}"
printf 'ARG\t%s\n' "${REMAINING_ARGS[@]}"
printf 'NS\t%s\n' "$namespace"
printf 'HOST\t%s\n' "$targetHost"
printf 'DISPLAY\t%s\n' "$(kube_flags_display)"
printf 'HINT\t%s\n' "$(netobserv_cmd cleanup)"
`
	cmd := exec.Command("bash", append([]string{"-c", script, "test"}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return flagsResult{}, err
	}
	var r flagsResult
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		key, value, _ := strings.Cut(line, "\t")
		switch key {
		case "FLAG":
			if value != "" {
				r.kubeFlags = append(r.kubeFlags, value)
			}
		case "ARG":
			if value != "" {
				r.remaining = append(r.remaining, value)
			}
		case "NS":
			r.namespace = value
		case "HOST":
			r.targetHost = value
		case "DISPLAY":
			r.display = value
		case "HINT":
			r.hint = value
		}
	}
	return r, nil
}

func TestExtractKubeFlags(t *testing.T) {
	r, err := extractFlags(t, nil, "flows", "--as=admin", "--context", "ctx", "--drops", "--as-group", "g1", "--as-group=g2")
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, []string{"--as=admin", "--context=ctx", "--as-group=g1", "--as-group=g2"}, r.kubeFlags)
	assert.Equal(t, []string{"flows", "--drops"}, r.remaining)

	r, err = extractFlags(t, nil, "--kubeconfig", "/tmp/kc", "packets", "--port=8080")
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, []string{"--kubeconfig=/tmp/kc"}, r.kubeFlags)
	assert.Equal(t, []string{"packets", "--port=8080"}, r.remaining)
}

func TestExtractKubeFlagsBooleans(t *testing.T) {
	r, err := extractFlags(t, nil, "flows", "-s", "https://api:6443", "--insecure-skip-tls-verify", "--disable-compression=false", "--background")
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, []string{"--server=https://api:6443", "--insecure-skip-tls-verify", "--disable-compression=false"}, r.kubeFlags)
	assert.Equal(t, []string{"flows", "--background"}, r.remaining)
}

func TestExtractKubeFlagsNamespace(t *testing.T) {
	r, err := extractFlags(t, nil, "flows", "-n", "my-ns")
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, "my-ns", r.namespace)
	assert.Equal(t, "collector.my-ns.svc.cluster.local", r.targetHost)
	assert.Empty(t, r.kubeFlags)

	r, err = extractFlags(t, nil, "flows", "--namespace=other")
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, "other", r.namespace)

	// flag takes precedence over NETOBSERV_NAMESPACE
	r, err = extractFlags(t, []string{"NETOBSERV_NAMESPACE=from-env"}, "flows", "-n", "from-flag")
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, "from-flag", r.namespace)

	r, err = extractFlags(t, []string{"NETOBSERV_NAMESPACE=from-env"}, "flows")
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, "from-env", r.namespace)
}

func TestExtractKubeFlagsDisplay(t *testing.T) {
	r, err := extractFlags(t, nil, "flows", "--as", "user with space", "--token", "secret", "--password=pw")
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, "--as=user with space", r.kubeFlags[0])
	assert.Equal(t, "'--as=user with space' --token=<redacted> --password=<redacted>", strings.TrimSpace(r.display))
	assert.NotContains(t, r.hint, "secret")

	r, err = extractFlags(t, nil, "cleanup", "--context=c", "-n", "ns")
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, "oc netobserv cleanup --context=c -n ns", r.hint)
}

func TestExtractKubeFlagsMissingValue(t *testing.T) {
	_, err := extractFlags(t, nil, "flows", "--context")
	assert.Error(t, err)
}

// TestKubeFlagsForwarded runs the netobserv command against a fake oc binary and checks
// that every cluster call receives the forwarded flags.
func TestKubeFlagsForwarded(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	fakeOC := "#!/usr/bin/env bash\necho \"$*\" >> \"" + log + "\"\n"
	if !assert.NoError(t, os.WriteFile(filepath.Join(dir, "oc"), []byte(fakeOC), 0o755)) {
		return
	}

	cmd := exec.Command("bash", "./commands/netobserv", "--context=ctx", "cleanup", "--as", "admin", "-n", "my-ns")
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if !assert.NoError(t, err, string(out)) {
		return
	}

	data, err := os.ReadFile(log)
	if !assert.NoError(t, err) {
		return
	}
	calls := strings.Split(strings.TrimSpace(string(data)), "\n")
	assert.NotEmpty(t, calls)
	for _, call := range calls {
		assert.True(t, strings.HasPrefix(call, "--context=ctx --as=admin "), call)
	}
	assert.Contains(t, string(data), "delete namespace my-ns")
}
