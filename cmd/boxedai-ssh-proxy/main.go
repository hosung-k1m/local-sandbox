package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"boxedai/internal/evidence"
	"boxedai/internal/remoteaccess"
	"boxedai/internal/session"
)

func main() {
	flags := flag.NewFlagSet("boxedai-ssh-proxy", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	sessionID := flags.String("session", "", "running BoxedAi session id")
	grantID := flags.String("grant", "", "sealed human access grant id")
	surface := flags.String("surface", "", "authorized access surface")
	uid := flags.Int64("uid", 0, "authorized guest uid")
	workspace := flags.String("workspace", "", "authorized guest workspace")
	if err := flags.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if flags.NArg() != 0 || !validSessionID(*sessionID) || *grantID == "" || *uid != 5000 || *workspace != remoteaccess.WorkspaceTarget {
		fmt.Fprintln(os.Stderr, "boxedai-ssh-proxy: invalid fixed access contract")
		os.Exit(2)
	}
	authorizeFresh := func() error {
		binding, err := session.LoadRunningHumanAccessBinding(*sessionID)
		if err != nil {
			return err
		}
		controller := remoteaccess.NewController(remoteaccess.NewBroker(binding, true), nil)
		return controller.AuthorizeRequest(remoteaccess.LaunchRequest{SessionID: *sessionID, GrantID: *grantID, Surface: evidence.AccessSurface(*surface), UID: *uid})
	}
	if err := authorizeFresh(); err != nil {
		fmt.Fprintf(os.Stderr, "boxedai-ssh-proxy: relay admission denied: %v\n", err)
		os.Exit(1)
	}
	bridgeCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-bridgeCtx.Done():
				return
			case <-ticker.C:
				if err := authorizeFresh(); err != nil {
					cancel()
					return
				}
			}
		}
	}()
	socketPath := filepath.Join(session.SessionDir(*sessionID), "remote-access", "guest.sock")
	if err := remoteaccess.BridgeUnixSocket(bridgeCtx, socketPath, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "boxedai-ssh-proxy: bridge failed: %v\n", err)
		os.Exit(1)
	}
}

func validSessionID(id string) bool {
	return id != "" && id != "." && id != ".." && !strings.ContainsAny(id, "/\\")
}
