package vm

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

const guestGitBridgeURL = "ext::/usr/local/bin/boxedai-guest-agent git-bridge %S"

// githubHarnessEnv rewrites only the current repository's exact and canonical
// remote URLs to the guest agent's authenticated bridge. The host SSH identity
// remains outside the VM.
func githubHarnessEnv(cfg Config) ([]string, error) {
	if cfg.GitHubRepository == "" {
		return nil, nil
	}
	owner, name, ok := strings.Cut(cfg.GitHubRepository, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return nil, fmt.Errorf("vm: invalid GitHub repository %q", cfg.GitHubRepository)
	}

	remotes := []string{
		cfg.GitHubRemote,
		cfg.GitHubSSHURL,
		"https://github.com/" + cfg.GitHubRepository + ".git",
		"https://github.com/" + cfg.GitHubRepository,
		"git@github.com:" + cfg.GitHubRepository + ".git",
		"git@github.com:" + cfg.GitHubRepository,
		"ssh://git@github.com/" + cfg.GitHubRepository + ".git",
		"ssh://git@github.com/" + cfg.GitHubRepository,
	}

	unique := make([]string, 0, len(remotes))
	for _, remote := range remotes {
		if remote != "" && !slices.Contains(unique, remote) {
			unique = append(unique, remote)
		}
	}

	env := []string{"GIT_CONFIG_COUNT=" + strconv.Itoa(len(unique)+1)}
	for i, remote := range unique {
		env = append(env,
			"GIT_CONFIG_KEY_"+strconv.Itoa(i)+"=url."+guestGitBridgeURL+".insteadOf",
			"GIT_CONFIG_VALUE_"+strconv.Itoa(i)+"="+remote,
		)
	}
	protocolIndex := len(unique)
	// BOXEDAI_BROKER_URL / BOXEDAI_WORKLOAD_TOKEN, which the git bridge reads,
	// are set unconditionally by harnessEnv for claude and codex — the
	// lefthook/righthook capture hooks need them even without GitHub access.
	env = append(env,
		"GIT_CONFIG_KEY_"+strconv.Itoa(protocolIndex)+"=protocol.ext.allow",
		"GIT_CONFIG_VALUE_"+strconv.Itoa(protocolIndex)+"=user",
		"GIT_TERMINAL_PROMPT=0",
		"GCM_INTERACTIVE=never",
	)
	return env, nil
}
