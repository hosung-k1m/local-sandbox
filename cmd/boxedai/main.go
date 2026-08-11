// Command boxedai launches AI coding agents in a sandboxed Lima VM and produces
// independently verifiable audit evidence. All behavior lives in internal/cli;
// this entrypoint only dispatches.
package main

import "boxedai/internal/cli"

func main() {
	cli.Execute()
}
