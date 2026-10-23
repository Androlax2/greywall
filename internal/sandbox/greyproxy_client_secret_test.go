package sandbox

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

const testAPIToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// recordedCall is one request the fake greyproxy API received.
type recordedCall struct {
	method        string
	path          string
	authorization string
	body          map[string]any
}

// fakeGreyproxyAPI records every request and answers like greyproxy does.
func fakeGreyproxyAPI(t *testing.T) (*httptest.Server, func() []recordedCall) {
	t.Helper()
	var mutex sync.Mutex
	var calls []recordedCall
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := recordedCall{method: r.Method, path: r.URL.Path, authorization: r.Header.Get("Authorization")}
		if rawBody, _ := io.ReadAll(r.Body); len(rawBody) > 0 {
			if err := json.Unmarshal(rawBody, &call.body); err != nil {
				t.Errorf("request body is not JSON: %v", err)
			}
		}
		mutex.Lock()
		calls = append(calls, call)
		mutex.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"session_id":"s","expires_at":"x","credential_count":0,"rules_created":0}`))
	}))
	t.Cleanup(server.Close)
	return server, func() []recordedCall {
		mutex.Lock()
		defer mutex.Unlock()
		return append([]recordedCall(nil), calls...)
	}
}

// useGreyproxyDataDir points greyproxy's data dir lookup at a fresh directory,
// optionally holding an API token file.
func useGreyproxyDataDir(t *testing.T, token string) string {
	t.Helper()
	dataDir := t.TempDir()
	t.Setenv("GREYPROXY_DATA_HOME", dataDir)
	if token != "" {
		if err := os.WriteFile(filepath.Join(dataDir, "api-token"), []byte(token+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dataDir
}

func TestGenerateClientSecret_IsLongEnoughForGreyproxy(t *testing.T) {
	secret, err := GenerateClientSecret()
	if err != nil {
		t.Fatalf("GenerateClientSecret: %v", err)
	}
	if len(secret) < 32 {
		t.Errorf("secret has %d characters; greyproxy rejects fewer than 32", len(secret))
	}
	if secret == "proxy" {
		t.Error("secret must not be the shared password \"proxy\"")
	}
}

func TestGenerateClientSecret_DiffersBetweenCalls(t *testing.T) {
	first, err := GenerateClientSecret()
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateClientSecret()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Error("two calls returned the same secret")
	}
}

func TestGenerateClientSecret_IsSafeInsideAProxyURL(t *testing.T) {
	secret, err := GenerateClientSecret()
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(secret, ":@/?#%+= ") {
		t.Errorf("secret %q contains characters that need escaping in a URL", secret)
	}
}

func TestRegisterSession_SendsClientSecret(t *testing.T) {
	useGreyproxyDataDir(t, "")
	server, calls := fakeGreyproxyAPI(t)

	opts := &RegisterSessionOptions{ClientSecret: "a-client-secret-of-at-least-32-characters"}
	if _, err := RegisterSession("session-1", "opencode", nil, nil, nil, server.URL, opts); err != nil {
		t.Fatalf("RegisterSession: %v", err)
	}

	recorded := calls()
	if len(recorded) != 1 {
		t.Fatalf("expected 1 request, got %d", len(recorded))
	}
	if got := recorded[0].body["client_secret"]; got != opts.ClientSecret {
		t.Errorf("client_secret = %v, want %q", got, opts.ClientSecret)
	}
}

func TestRegisterSession_OmitsClientSecretWhenNoneIsSet(t *testing.T) {
	useGreyproxyDataDir(t, "")
	server, calls := fakeGreyproxyAPI(t)

	if _, err := RegisterSession("session-1", "opencode", nil, nil, nil, server.URL, nil); err != nil {
		t.Fatalf("RegisterSession: %v", err)
	}

	if _, present := calls()[0].body["client_secret"]; present {
		t.Error("client_secret is sent although no secret was set")
	}
}

// Every call greywall makes to greyproxy's API must carry the token when
// greyproxy created one, or a greyproxy with requireApiToken refuses it.
func TestGreyproxyAPICalls_SendTheAPIToken(t *testing.T) {
	cases := []struct {
		name string
		call func(apiBase string) error
	}{
		{"register", func(apiBase string) error {
			_, err := RegisterSession("session-1", "opencode", nil, nil, nil, apiBase, nil)
			return err
		}},
		{"heartbeat", func(apiBase string) error { return HeartbeatSession("session-1", apiBase) }},
		{"delete", func(apiBase string) error { return DeleteSession("session-1", apiBase) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useGreyproxyDataDir(t, testAPIToken)
			server, calls := fakeGreyproxyAPI(t)

			if err := tc.call(server.URL); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}

			if got := calls()[0].authorization; got != "Bearer "+testAPIToken {
				t.Errorf("Authorization = %q, want the token from api-token", got)
			}
		})
	}
}

// An older greyproxy has no api-token file: greywall must keep working
// against it, without a header.
func TestGreyproxyAPICalls_SendNoTokenWhenGreyproxyHasNone(t *testing.T) {
	useGreyproxyDataDir(t, "")
	server, calls := fakeGreyproxyAPI(t)

	if _, err := RegisterSession("session-1", "opencode", nil, nil, nil, server.URL, nil); err != nil {
		t.Fatalf("RegisterSession: %v", err)
	}

	if got := calls()[0].authorization; got != "" {
		t.Errorf("Authorization = %q, want none", got)
	}
}

func TestGreyproxyAPICalls_FailWhenTheTokenFileIsReadableByOthers(t *testing.T) {
	dataDir := useGreyproxyDataDir(t, testAPIToken)
	if err := os.Chmod(filepath.Join(dataDir, "api-token"), 0o644); err != nil { // #nosec G302 -- deliberately insecure fixture verifies that registration rejects readable tokens
		t.Fatal(err)
	}
	server, calls := fakeGreyproxyAPI(t)

	_, err := RegisterSession("session-1", "opencode", nil, nil, nil, server.URL, nil)
	if err == nil {
		t.Fatal("RegisterSession succeeded with a token file other users can read")
	}
	if len(calls()) != 0 {
		t.Error("a request was sent although the token could not be trusted")
	}
}

func TestGreyproxyDataDir_FollowsGreyproxysLookupOrder(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	t.Setenv("GREYPROXY_DATA_HOME", "/custom/greyproxy")
	t.Setenv("XDG_DATA_HOME", "/xdg")
	if got := greyproxyDataDir(); got != "/custom/greyproxy" {
		t.Errorf("with GREYPROXY_DATA_HOME: got %q", got)
	}

	t.Setenv("GREYPROXY_DATA_HOME", "")
	if got := greyproxyDataDir(); got != "/xdg/greyproxy" {
		t.Errorf("with XDG_DATA_HOME: got %q", got)
	}

	t.Setenv("XDG_DATA_HOME", "")
	wantDefault := filepath.Join(home, ".local", "share", "greyproxy")
	if runtime.GOOS == "darwin" {
		wantDefault = filepath.Join(home, "Library", "Application Support", "greyproxy")
	}
	if got := greyproxyDataDir(); got != wantDefault {
		t.Errorf("default: got %q, want %q", got, wantDefault)
	}
}
