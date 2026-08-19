//go:build !linux

package main

import "fmt"

func probeLowerMountAccess(string, ...int64) error {
	return fmt.Errorf("mediated workspace requires Linux setfsuid support")
}
