package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const (
	brokerURLEnv     = "BOXEDAI_BROKER_URL"
	workloadTokenEnv = "BOXEDAI_WORKLOAD_TOKEN"
	// sessionIDEnv and agentIDEnv carry the BoxedAi session id and the
	// controller-minted Primary Agent id into the Claude hooks, so the hook
	// derives child agent ids and names the Primary as parent (DESIGN.md "Agent
	// hierarchy and attribution"). Neither is a secret.
	sessionIDEnv       = "BOXEDAI_SESSION_ID"
	agentIDEnv         = "BOXEDAI_AGENT_ID"
	gitExitTrailer     = "X-BoxedAI-Git-Exit"
	gitErrorTrailer    = "X-BoxedAI-Git-Error"
	gitEvidenceTrailer = "X-BoxedAI-Git-Evidence"
	maxBridgeErrorBody = 4096
)

// runGitBridge is the process launched by Git's ext transport. It deliberately
// runs before loading the root-only supervisor config: the harness receives only
// its ephemeral workload token and broker address through its own environment.
func runGitBridge(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) != 1 || (args[0] != "git-upload-pack" && args[0] != "git-receive-pack") {
		return errors.New("only git-upload-pack and git-receive-pack are permitted")
	}
	brokerURL := strings.TrimRight(os.Getenv(brokerURLEnv), "/")
	parsed, err := url.Parse(brokerURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("invalid %s", brokerURLEnv)
	}
	token := os.Getenv(workloadTokenEnv)
	if token == "" {
		return fmt.Errorf("missing %s", workloadTokenEnv)
	}

	req, err := http.NewRequest(http.MethodPost, brokerURL+"/v1/git/"+args[0], stdin)
	if err != nil {
		return fmt.Errorf("build broker request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("contact broker: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBridgeErrorBody))
		if readErr != nil {
			return fmt.Errorf("broker returned HTTP %d and its error body could not be read: %w", resp.StatusCode, readErr)
		}
		return fmt.Errorf("broker returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if _, err := io.Copy(stdout, resp.Body); err != nil {
		return fmt.Errorf("copy Git protocol response: %w", err)
	}

	exitValue, ok := singleTrailer(resp.Trailer, gitExitTrailer)
	if !ok {
		return errors.New("broker response is missing a valid Git exit trailer")
	}
	exitCode, err := strconv.Atoi(exitValue)
	if err != nil || exitCode < 0 || exitCode > 255 {
		return errors.New("broker response has a malformed Git exit trailer")
	}
	evidenceStatus, ok := singleTrailer(resp.Trailer, gitEvidenceTrailer)
	if !ok {
		return errors.New("broker response is missing a valid Git evidence trailer")
	}
	errorValue := resp.Trailer.Get(gitErrorTrailer)
	errorMessage := ""
	if errorValue != "" {
		decoded, err := base64.RawStdEncoding.DecodeString(errorValue)
		if err != nil {
			return errors.New("broker response has a malformed Git error trailer")
		}
		errorMessage = strings.TrimSpace(string(decoded))
	}

	wantEvidence := "not-required"
	if args[0] == "git-receive-pack" {
		wantEvidence = "completed"
	}
	if exitCode == 0 {
		if evidenceStatus != wantEvidence {
			return fmt.Errorf("broker reported successful Git transport without %s evidence status", wantEvidence)
		}
		return nil
	}
	if evidenceStatus != "failed" {
		return errors.New("broker reported failed Git transport without failed evidence status")
	}
	if errorMessage == "" {
		errorMessage = "host SSH transport failed"
	}
	return fmt.Errorf("host Git transport exited %d: %s", exitCode, errorMessage)
}

func singleTrailer(header http.Header, name string) (string, bool) {
	values, ok := header[http.CanonicalHeaderKey(name)]
	returnValue := ""
	if ok && len(values) == 1 {
		returnValue = strings.TrimSpace(values[0])
	}
	return returnValue, ok && len(values) == 1 && returnValue != ""
}
