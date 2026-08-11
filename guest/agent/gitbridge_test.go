package main

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func gitBridgeServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	t.Setenv(brokerURLEnv, srv.URL)
	t.Setenv(workloadTokenEnv, "ephemeral-workload-token")
	return srv
}

func writeGitResponse(w http.ResponseWriter, output, exit, evidenceStatus, message string) {
	w.Header().Set("Trailer", strings.Join([]string{gitExitTrailer, gitErrorTrailer, gitEvidenceTrailer}, ", "))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, output)
	w.Header().Set(gitExitTrailer, exit)
	w.Header().Set(gitEvidenceTrailer, evidenceStatus)
	w.Header().Set(gitErrorTrailer, base64.RawStdEncoding.EncodeToString([]byte(message)))
}

func TestRunGitBridgeStreamsAuthenticatedUploadPack(t *testing.T) {
	gitBridgeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/git/git-upload-pack" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer ephemeral-workload-token" {
			t.Errorf("Authorization = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != "request" {
			t.Errorf("request = %q", body)
		}
		writeGitResponse(w, "response", "0", "not-required", "")
	})
	var output strings.Builder
	if err := runGitBridge([]string{"git-upload-pack"}, strings.NewReader("request"), &output); err != nil {
		t.Fatalf("runGitBridge: %v", err)
	}
	if output.String() != "response" {
		t.Fatalf("output = %q, want response", output.String())
	}
}

func TestRunGitBridgeAcceptsCompletedReceivePack(t *testing.T) {
	gitBridgeServer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeGitResponse(w, "push result", "0", "completed", "")
	})
	var output strings.Builder
	if err := runGitBridge([]string{"git-receive-pack"}, strings.NewReader("push"), &output); err != nil {
		t.Fatalf("runGitBridge: %v", err)
	}
	if output.String() != "push result" {
		t.Fatalf("output = %q", output.String())
	}
}

func TestRunGitBridgeFailsClosedOnBrokerStatusAndTrailers(t *testing.T) {
	for _, tc := range []struct {
		name     string
		handler  http.HandlerFunc
		service  string
		wantText string
	}{
		{
			name: "HTTP denial",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "denied", http.StatusForbidden)
			},
			service:  "git-upload-pack",
			wantText: "HTTP 403",
		},
		{
			name: "missing exit",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Trailer", gitEvidenceTrailer)
				w.WriteHeader(http.StatusOK)
				w.Header().Set(gitEvidenceTrailer, "not-required")
			},
			service:  "git-upload-pack",
			wantText: "exit trailer",
		},
		{
			name: "malformed exit",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeGitResponse(w, "", "not-a-number", "not-required", "")
			},
			service:  "git-upload-pack",
			wantText: "malformed Git exit",
		},
		{
			name: "missing evidence",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Trailer", gitExitTrailer)
				w.WriteHeader(http.StatusOK)
				w.Header().Set(gitExitTrailer, "0")
			},
			service:  "git-upload-pack",
			wantText: "evidence trailer",
		},
		{
			name: "completion evidence failure",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeGitResponse(w, "upstream success", "1", "failed", "completion evidence failed")
			},
			service:  "git-receive-pack",
			wantText: "completion evidence failed",
		},
		{
			name: "SSH failure",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeGitResponse(w, "", "255", "failed", "publickey denied")
			},
			service:  "git-upload-pack",
			wantText: "publickey denied",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gitBridgeServer(t, tc.handler)
			err := runGitBridge([]string{tc.service}, strings.NewReader("input"), io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("runGitBridge error = %v, want %q", err, tc.wantText)
			}
		})
	}
}

func TestRunGitBridgeRejectsUnsupportedServiceBeforeNetwork(t *testing.T) {
	called := false
	gitBridgeServer(t, func(http.ResponseWriter, *http.Request) { called = true })
	for _, args := range [][]string{{}, {"git-upload-archive"}, {"git-upload-pack", "extra"}} {
		if err := runGitBridge(args, strings.NewReader(""), io.Discard); err == nil {
			t.Fatalf("runGitBridge(%v) succeeded", args)
		}
	}
	if called {
		t.Fatal("unsupported service reached broker")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestRunGitBridgeFailsOnResponseCopyError(t *testing.T) {
	gitBridgeServer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeGitResponse(w, "response", "0", "not-required", "")
	})
	err := runGitBridge([]string{"git-upload-pack"}, strings.NewReader(""), failingWriter{})
	if err == nil || !strings.Contains(err.Error(), "copy Git protocol response") {
		t.Fatalf("runGitBridge error = %v", err)
	}
}
