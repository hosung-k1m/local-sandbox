//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// probeLowerMountAccess proves on one locked OS thread that neither workload
// nor human identities can bypass the FUSE mount by reaching the lower path.
// Every Setfsuid transition is restored to UID 0 before the thread is reused.
func probeLowerMountAccess(path string, uids ...int64) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for _, uid := range uids {
		if uid < 0 || uid > int64(^uint32(0)) {
			return fmt.Errorf("invalid lower-mount fsuid %d", uid)
		}
		previous, err := unix.SetfsuidRetUid(int(uid))
		if err != nil {
			return fmt.Errorf("setfsuid %d: %w", uid, err)
		}
		if previous != 0 {
			_, _ = unix.SetfsuidRetUid(0)
			return fmt.Errorf("setfsuid %d found prior fsuid %d, want root", uid, previous)
		}
		for _, access := range []struct {
			name string
			call func() error
		}{
			{"open", func() error {
				file, err := os.Open(path)
				if file != nil {
					_ = file.Close()
				}
				return err
			}},
			{"stat", func() error { _, err := os.Stat(path); return err }},
			{"readdir", func() error { _, err := os.ReadDir(path); return err }},
		} {
			if err := access.call(); !errors.Is(err, syscall.EACCES) {
				_, _ = unix.SetfsuidRetUid(0)
				return fmt.Errorf("lower mount %s as uid %d = %v, want EACCES", access.name, uid, err)
			}
		}
		restored, err := unix.SetfsuidRetUid(0)
		if err != nil {
			return fmt.Errorf("restore root fsuid after uid %d: %w", uid, err)
		}
		if restored != int(uid) {
			return fmt.Errorf("restore root fsuid found current fsuid %d, want %d", restored, uid)
		}
	}
	return nil
}
