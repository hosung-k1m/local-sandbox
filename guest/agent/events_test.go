package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"syscall"
	"testing"
	"time"

	"boxedai/internal/evidence"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

func TestProcessExecutedIncludesParentExecIdentity(t *testing.T) {
	event := newProcessExecutedEvent(ProcInfo{
		Pid: 10, Ppid: 1, Uid: 4242, ExecID: "child", ParentExecID: "parent", Observer: "tetragon",
	})

	if event.Attrs[evidence.AttrProcessParentExecID] != "parent" {
		t.Fatalf("parent exec id = %v, want parent", event.Attrs[evidence.AttrProcessParentExecID])
	}
}

func TestMediatedWorkspaceCandidateUsesKernelRequestUID(t *testing.T) {
	delivered := make(chan evidence.Event, 1)
	batch := NewBatcher(func(events []evidence.Event) error {
		delivered <- events[0]
		return nil
	})
	batchCtx, cancelBatch := context.WithCancel(context.Background())
	defer cancelBatch()
	go batch.Run(batchCtx)
	node := newMediatedWorkspaceNode(&fs.LoopbackRoot{Path: t.TempDir()}, batch, nil, nil)
	ctx := fuse.NewContext(context.Background(), &fuse.Caller{Owner: fuse.Owner{Uid: 4242}})
	if errno := node.emit(ctx, evidence.MutationOperationWrite, "main.go", 11, true, evidence.MutationOpenReadWrite, mutationBasisCaller); errno != 0 {
		t.Fatalf("emit = %v", errno)
	}
	event := <-delivered
	if event.Attrs[evidence.AttrMutationUID] != int64(4242) {
		t.Fatalf("mutation uid = %v, want kernel request uid", event.Attrs[evidence.AttrMutationUID])
	}
	if event.Attrs[evidence.AttrMutationPosition] != int64(11) {
		t.Fatalf("mutation position = %v, want 11", event.Attrs[evidence.AttrMutationPosition])
	}
}

func testMediatedSubjectBinding(t *testing.T) (*evidence.SessionSubjectMap, *evidence.HumanAccessGrant) {
	t.Helper()
	now := time.Now()
	subjects := &evidence.SessionSubjectMap{
		SessionID: "bx-20260818-162327-a1b2c3d4",
		Subjects: []evidence.SessionSubject{
			{UID: evidence.WorkloadUID, ActorClass: evidence.MutationActorAgent},
			{UID: evidence.HumanUID, ActorClass: evidence.MutationActorHuman, SubjectID: "operator", GrantID: "grant"},
		},
	}
	grant := &evidence.HumanAccessGrant{
		SessionID:        subjects.SessionID,
		GrantID:          "grant",
		SubjectID:        "operator",
		ExpiresAt:        now.Add(time.Minute),
		AllowedSurfaces:  []evidence.AccessSurface{evidence.AccessSurfaceBrowserTerminal},
		UID:              evidence.HumanUID,
		CredentialDigest: evidence.SHA256Hex([]byte("credential")),
	}
	return subjects, grant
}

func TestMediatedWorkspaceDeniesUnmappedDirectoryAccessAndCountsIt(t *testing.T) {
	subjects, grant := testMediatedSubjectBinding(t)
	node := newMediatedWorkspaceNode(&fs.LoopbackRoot{Path: t.TempDir()}, NewBatcher(func([]evidence.Event) error { return nil }), subjects, grant)
	ctx := fuse.NewContext(context.Background(), &fuse.Caller{Owner: fuse.Owner{Uid: 6000}})
	before := mediatedWorkspaceAccessDenials.Load()
	if _, _, errno := node.OpendirHandle(ctx, 0); errno != syscall.EACCES {
		t.Fatalf("OpendirHandle errno = %v, want EACCES", errno)
	}
	if _, errno := node.Readdir(ctx); errno != syscall.EACCES {
		t.Fatalf("Readdir errno = %v, want EACCES", errno)
	}
	if got := mediatedWorkspaceAccessDenials.Load() - before; got != 2 {
		t.Fatalf("mediated access denials = %d, want 2", got)
	}
}

func TestMediatedWorkspaceWithholdsPassthroughFromWritableHandles(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "workspace-file")
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	defer file.Close()
	fd, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		t.Fatalf("dup file: %v", err)
	}
	handle := fs.NewLoopbackFile(fd)
	if _, ok := handle.(fs.FilePassthroughFder); !ok {
		t.Fatal("read-only loopback handle does not offer kernel passthrough")
	}
	wrapped := &mediatedWorkspaceFile{inner: handle}
	if _, ok := any(wrapped).(fs.FilePassthroughFder); ok {
		t.Fatal("writable mediated handle must not offer kernel passthrough")
	}
	allocator, ok := any(wrapped).(fs.FileAllocater)
	if !ok {
		t.Fatal("writable mediated handle must expose Allocate refusal")
	}
	if errno := allocator.Allocate(context.Background(), 0, 1, 0); errno != syscall.EOPNOTSUPP {
		t.Fatalf("Allocate errno = %v, want EOPNOTSUPP", errno)
	}
	if _, ok := any(wrapped).(fs.FileIoctler); ok {
		t.Fatal("writable mediated handle must not expose Ioctl")
	}
}

func TestMediatedWorkspaceFileExposesOnlyDeliberateInterfaces(t *testing.T) {
	assertInterfaceSurface(t, any(&mediatedWorkspaceFile{}), map[string]bool{
		"FilePassthroughFder": false, "FileReleaser": true, "FileGetattrer": true, "FileStatxer": false,
		"FileReader": true, "FileWriter": true, "FileGetlker": true, "FileSetlker": true,
		"FileSetlkwer": true, "FileLseeker": true, "FileFlusher": true, "FileFsyncer": true,
		"FileSetattrer": false, "FileAllocater": true, "FileIoctler": false, "FileReaddirenter": false,
		"FileLookuper": false, "FileFsyncdirer": false, "FileSeekdirer": false, "FileReleasedirer": false,
	}, map[string]any{
		"FilePassthroughFder": (*fs.FilePassthroughFder)(nil), "FileReleaser": (*fs.FileReleaser)(nil),
		"FileGetattrer": (*fs.FileGetattrer)(nil), "FileStatxer": (*fs.FileStatxer)(nil),
		"FileReader": (*fs.FileReader)(nil), "FileWriter": (*fs.FileWriter)(nil),
		"FileGetlker": (*fs.FileGetlker)(nil), "FileSetlker": (*fs.FileSetlker)(nil),
		"FileSetlkwer": (*fs.FileSetlkwer)(nil), "FileLseeker": (*fs.FileLseeker)(nil),
		"FileFlusher": (*fs.FileFlusher)(nil), "FileFsyncer": (*fs.FileFsyncer)(nil),
		"FileSetattrer": (*fs.FileSetattrer)(nil), "FileAllocater": (*fs.FileAllocater)(nil),
		"FileIoctler": (*fs.FileIoctler)(nil), "FileReaddirenter": (*fs.FileReaddirenter)(nil),
		"FileLookuper": (*fs.FileLookuper)(nil), "FileFsyncdirer": (*fs.FileFsyncdirer)(nil),
		"FileSeekdirer": (*fs.FileSeekdirer)(nil), "FileReleasedirer": (*fs.FileReleasedirer)(nil),
	})
}

func TestMediatedWorkspaceNodeExposesOnlyDeliberateInterfaces(t *testing.T) {
	assertInterfaceSurface(t, any(&mediatedWorkspaceNode{}), map[string]bool{
		"NodeStatfser": true, "NodeAccesser": false, "NodeGetattrer": true, "NodeSetattrer": true,
		"NodeOnAdder": false, "NodeGetxattrer": true, "NodeSetxattrer": true, "NodeRemovexattrer": true,
		"NodeListxattrer": true, "NodeReadlinker": true, "NodeOpener": true, "NodeReader": false,
		"NodeWriter": false, "NodeFsyncer": false, "NodeFlusher": false, "NodeReleaser": false,
		"NodeAllocater": false, "NodeCopyFileRanger": true, "NodeStatxer": runtime.GOOS == "linux",
		"NodeLseeker": false, "NodeGetlker": false, "NodeSetlker": false, "NodeSetlkwer": false,
		"NodeIoctler": false, "NodeOnForgetter": false, "NodeLookuper": true, "NodeWrapChilder": false,
		"NodeOpendirer": false, "NodeOpendirHandler": true, "NodeReaddirer": true, "NodeMkdirer": true,
		"NodeMknoder": true, "NodeLinker": true, "NodeSymlinker": true, "NodeCreater": true,
		"NodeUnlinker": true, "NodeRmdirer": true, "NodeRenamer": true,
	}, map[string]any{
		"NodeStatfser": (*fs.NodeStatfser)(nil), "NodeAccesser": (*fs.NodeAccesser)(nil),
		"NodeGetattrer": (*fs.NodeGetattrer)(nil), "NodeSetattrer": (*fs.NodeSetattrer)(nil),
		"NodeOnAdder": (*fs.NodeOnAdder)(nil), "NodeGetxattrer": (*fs.NodeGetxattrer)(nil),
		"NodeSetxattrer": (*fs.NodeSetxattrer)(nil), "NodeRemovexattrer": (*fs.NodeRemovexattrer)(nil),
		"NodeListxattrer": (*fs.NodeListxattrer)(nil), "NodeReadlinker": (*fs.NodeReadlinker)(nil),
		"NodeOpener": (*fs.NodeOpener)(nil), "NodeReader": (*fs.NodeReader)(nil),
		"NodeWriter": (*fs.NodeWriter)(nil), "NodeFsyncer": (*fs.NodeFsyncer)(nil),
		"NodeFlusher": (*fs.NodeFlusher)(nil), "NodeReleaser": (*fs.NodeReleaser)(nil),
		"NodeAllocater": (*fs.NodeAllocater)(nil), "NodeCopyFileRanger": (*fs.NodeCopyFileRanger)(nil),
		"NodeStatxer": (*fs.NodeStatxer)(nil), "NodeLseeker": (*fs.NodeLseeker)(nil),
		"NodeGetlker": (*fs.NodeGetlker)(nil), "NodeSetlker": (*fs.NodeSetlker)(nil),
		"NodeSetlkwer": (*fs.NodeSetlkwer)(nil), "NodeIoctler": (*fs.NodeIoctler)(nil),
		"NodeOnForgetter": (*fs.NodeOnForgetter)(nil), "NodeLookuper": (*fs.NodeLookuper)(nil),
		"NodeWrapChilder": (*fs.NodeWrapChilder)(nil), "NodeOpendirer": (*fs.NodeOpendirer)(nil),
		"NodeOpendirHandler": (*fs.NodeOpendirHandler)(nil), "NodeReaddirer": (*fs.NodeReaddirer)(nil),
		"NodeMkdirer": (*fs.NodeMkdirer)(nil), "NodeMknoder": (*fs.NodeMknoder)(nil),
		"NodeLinker": (*fs.NodeLinker)(nil), "NodeSymlinker": (*fs.NodeSymlinker)(nil),
		"NodeCreater": (*fs.NodeCreater)(nil), "NodeUnlinker": (*fs.NodeUnlinker)(nil),
		"NodeRmdirer": (*fs.NodeRmdirer)(nil), "NodeRenamer": (*fs.NodeRenamer)(nil),
	})
}

func assertInterfaceSurface(t *testing.T, value any, want map[string]bool, interfaces map[string]any) {
	t.Helper()
	valueType := reflect.TypeOf(value)
	for name, expected := range want {
		interfaceType := reflect.TypeOf(interfaces[name]).Elem()
		if got := valueType.Implements(interfaceType); got != expected {
			t.Errorf("%s implements %s = %t, want %t", valueType, name, got, expected)
		}
	}
}

func TestMediatedWorkspaceWritableHandleWritePreadFsyncClose(t *testing.T) {
	lower, err := os.OpenFile(filepath.Join(t.TempDir(), "workspace-file"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open lower file: %v", err)
	}
	defer lower.Close()
	fd, err := syscall.Dup(int(lower.Fd()))
	if err != nil {
		t.Fatalf("dup lower file: %v", err)
	}
	node := newMediatedWorkspaceNode(&fs.LoopbackRoot{Path: filepath.Dir(lower.Name())}, testMediatedWorkspaceBatcher(t), nil, nil)
	handle := node.newFileHandle(fs.NewLoopbackFile(fd), filepath.Base(lower.Name()), evidence.MutationOpenReadWrite, evidence.WorkloadUID, nil)
	if written, errno := handle.Write(context.Background(), []byte("written"), 0); written != 7 || errno != 0 {
		t.Fatalf("Write = %d/%v, want 7/0", written, errno)
	}
	result, errno := handle.Read(context.Background(), make([]byte, 7), 0)
	if errno != 0 {
		t.Fatalf("Read errno = %v", errno)
	}
	data, status := result.Bytes(make([]byte, 7))
	if status != fuse.OK || string(data) != "written" {
		t.Fatalf("pread = %q/%v, want written/OK", data, status)
	}
	if errno := handle.Fsync(context.Background(), 0); errno != 0 {
		t.Fatalf("Fsync errno = %v", errno)
	}
	if errno := handle.Release(context.Background()); errno != 0 {
		t.Fatalf("Release errno = %v", errno)
	}
	if err := syscall.Fstat(fd, &syscall.Stat_t{}); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("backing fd after Release = %v, want EBADF", err)
	}
}

func TestMediatedWorkspaceRepeatedWritableHandleCloseReleasesBackingFD(t *testing.T) {
	lower, err := os.OpenFile(filepath.Join(t.TempDir(), "workspace-file"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open lower file: %v", err)
	}
	defer lower.Close()
	node := newMediatedWorkspaceNode(&fs.LoopbackRoot{Path: filepath.Dir(lower.Name())}, testMediatedWorkspaceBatcher(t), nil, nil)
	for i := 0; i < 8; i++ {
		fd, err := syscall.Dup(int(lower.Fd()))
		if err != nil {
			t.Fatalf("dup lower file %d: %v", i, err)
		}
		handle := node.newFileHandle(fs.NewLoopbackFile(fd), filepath.Base(lower.Name()), evidence.MutationOpenReadWrite, evidence.WorkloadUID, nil)
		if _, errno := handle.Write(context.Background(), []byte("x"), int64(i)); errno != 0 {
			t.Fatalf("Write %d errno = %v", i, errno)
		}
		if errno := handle.Release(context.Background()); errno != 0 {
			t.Fatalf("Release %d errno = %v", i, errno)
		}
		if err := syscall.Fstat(fd, &syscall.Stat_t{}); !errors.Is(err, syscall.EBADF) {
			t.Fatalf("backing fd %d after Release = %v, want EBADF", i, err)
		}
	}
	node.openers.mu.Lock()
	defer node.openers.mu.Unlock()
	if len(node.openers.byInode) != 0 {
		t.Fatalf("openers after repeated close = %#v, want empty", node.openers.byInode)
	}
}

func TestMediatedWorkspaceRejectsFallocateAndWithholdsIoctl(t *testing.T) {
	lower, err := os.OpenFile(filepath.Join(t.TempDir(), "workspace-file"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open lower file: %v", err)
	}
	defer lower.Close()
	if _, err := lower.Write([]byte("unchanged")); err != nil {
		t.Fatalf("seed lower file: %v", err)
	}
	fd, err := syscall.Dup(int(lower.Fd()))
	if err != nil {
		t.Fatalf("dup lower file: %v", err)
	}
	node := newMediatedWorkspaceNode(&fs.LoopbackRoot{Path: filepath.Dir(lower.Name())}, testMediatedWorkspaceBatcher(t), nil, nil)
	handle := node.newFileHandle(fs.NewLoopbackFile(fd), filepath.Base(lower.Name()), evidence.MutationOpenReadWrite, evidence.WorkloadUID, nil)
	defer handle.Release(context.Background())
	if errno := any(handle).(fs.FileAllocater).Allocate(context.Background(), 0, 4096, 0); errno != syscall.ENOTSUP && errno != syscall.EOPNOTSUPP {
		t.Fatalf("Allocate errno = %v, want ENOTSUP", errno)
	}
	// With no FileIoctler, go-fuse's default FUSE_IOCTL dispatcher returns ENOTSUP.
	if _, ok := any(handle).(fs.FileIoctler); ok {
		t.Fatal("writable mediated handle must not expose Ioctl")
	}
	data, err := os.ReadFile(lower.Name())
	if err != nil {
		t.Fatalf("read lower file: %v", err)
	}
	if string(data) != "unchanged" {
		t.Fatalf("lower file = %q, want unchanged", data)
	}
}

func testMediatedWorkspaceBatcher(t *testing.T) *Batcher {
	t.Helper()
	batch := NewBatcher(func([]evidence.Event) error { return nil })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go batch.Run(ctx)
	return batch
}

type lifecycleHandle struct{}

func (lifecycleHandle) Read(context.Context, []byte, int64) (fuse.ReadResult, syscall.Errno) {
	return fuse.ReadResultData([]byte("read")), 0
}

func (lifecycleHandle) Release(context.Context) syscall.Errno { return syscall.EBADF }
func (lifecycleHandle) Flush(context.Context) syscall.Errno   { return syscall.EIO }
func (lifecycleHandle) Fsync(context.Context, uint32) syscall.Errno {
	return syscall.EROFS
}
func (lifecycleHandle) Lseek(context.Context, uint64, uint32) (uint64, syscall.Errno) {
	return 9, 0
}
func (lifecycleHandle) Getattr(context.Context, *fuse.AttrOut) syscall.Errno { return syscall.ENODATA }
func (lifecycleHandle) Getlk(context.Context, uint64, *fuse.FileLock, uint32, *fuse.FileLock) syscall.Errno {
	return syscall.EAGAIN
}
func (lifecycleHandle) Setlk(context.Context, uint64, *fuse.FileLock, uint32) syscall.Errno {
	return syscall.EBUSY
}
func (lifecycleHandle) Setlkw(context.Context, uint64, *fuse.FileLock, uint32) syscall.Errno {
	return syscall.EDEADLK
}

func TestMediatedWorkspaceWritableHandleDelegatesSafeLifecycle(t *testing.T) {
	handle := &mediatedWorkspaceFile{inner: lifecycleHandle{}, node: newMediatedWorkspaceNode(&fs.LoopbackRoot{Path: t.TempDir()}, NewBatcher(func([]evidence.Event) error { return nil }), nil, nil), openerKey: "file", openerID: 1}
	result, errno := handle.Read(context.Background(), make([]byte, 4), 0)
	data, status := result.Bytes(nil)
	if errno != 0 || status != fuse.OK || string(data) != "read" {
		t.Fatalf("Read = %q/%v/%v, want read/0/OK", data, errno, status)
	}
	if errno := handle.Flush(context.Background()); errno != syscall.EIO {
		t.Fatalf("Flush errno = %v, want EIO", errno)
	}
	if errno := handle.Fsync(context.Background(), 0); errno != syscall.EROFS {
		t.Fatalf("Fsync errno = %v, want EROFS", errno)
	}
	if offset, errno := handle.Lseek(context.Background(), 0, 0); offset != 9 || errno != 0 {
		t.Fatalf("Lseek = %d/%v, want 9/0", offset, errno)
	}
	if errno := handle.Getattr(context.Background(), &fuse.AttrOut{}); errno != syscall.ENODATA {
		t.Fatalf("Getattr errno = %v, want ENODATA", errno)
	}
	if errno := handle.Getlk(context.Background(), 0, &fuse.FileLock{}, 0, &fuse.FileLock{}); errno != syscall.EAGAIN {
		t.Fatalf("Getlk errno = %v, want EAGAIN", errno)
	}
	if errno := handle.Setlk(context.Background(), 0, &fuse.FileLock{}, 0); errno != syscall.EBUSY {
		t.Fatalf("Setlk errno = %v, want EBUSY", errno)
	}
	if errno := handle.Setlkw(context.Background(), 0, &fuse.FileLock{}, 0); errno != syscall.EDEADLK {
		t.Fatalf("Setlkw errno = %v, want EDEADLK", errno)
	}
	if errno := handle.Release(context.Background()); errno != syscall.EBADF {
		t.Fatalf("Release errno = %v, want EBADF", errno)
	}
}

func TestWorkspaceOpenerRegistryMarksConflictingFallbackAmbiguous(t *testing.T) {
	registry := newWorkspaceOpenerRegistry()
	registry.add("42", evidence.WorkloadUID)
	isSubject := func(uid int64) bool { return uid == evidence.WorkloadUID || uid == evidence.HumanUID }
	if uid, basis := registry.resolve("42", -1, isSubject); uid != evidence.WorkloadUID || basis != mutationBasisFallback {
		t.Fatalf("one opener fallback = %d/%s, want agent/opener_fallback", uid, basis)
	}
	if uid, basis := registry.resolve("42", 0, isSubject); uid != evidence.WorkloadUID || basis != mutationBasisFallback {
		t.Fatalf("root caller = %d/%s, want agent/opener_fallback", uid, basis)
	}
	registry.add("42", evidence.HumanUID)
	if _, basis := registry.resolve("42", 0, isSubject); basis != mutationBasisAmbiguous {
		t.Fatalf("conflicting opener basis = %s, want ambiguous", basis)
	}
}

func TestMediatedWorkspaceRejectsMissingLowerMount(t *testing.T) {
	cfg := Config{WorkspacePath: t.TempDir(), WorkspaceLowerPath: filepath.Join(t.TempDir(), "missing-lower")}
	if err := startMediatedWorkspace(cfg, NewBatcher(func([]evidence.Event) error { return nil })); err == nil {
		t.Fatal("startMediatedWorkspace: want missing lower mount error")
	}
}

func TestEvalMountinfoWritableVirtiofs(t *testing.T) {
	const path = "/var/lib/boxedai/private/workspace-lower"
	tests := []struct {
		name        string
		mountinfo   string
		wantMatches int
		wantOK      bool
	}{
		{
			name:        "single writable virtiofs mount",
			mountinfo:   "123 45 0:34 / " + path + " rw,relatime - virtiofs lima-9f2a rw,noatime\n",
			wantMatches: 1,
			wantOK:      true,
		},
		{
			// The trap case: a superblock option containing the substring
			// "ro" (errors=remount-ro) must not be misread as read-only when
			// the mount is actually rw. Token-exact matching must pass this.
			name:        "rw mount with errors=remount-ro superblock option still passes",
			mountinfo:   "123 45 0:34 / " + path + " rw,relatime - virtiofs lima-9f2a rw,errors=remount-ro\n",
			wantMatches: 1,
			wantOK:      true,
		},
		{
			name:        "read-only mount fails",
			mountinfo:   "123 45 0:34 / " + path + " ro,relatime - virtiofs lima-9f2a ro\n",
			wantMatches: 1,
			wantOK:      false,
		},
		{
			name: "two mounts at the path fails",
			mountinfo: "123 45 0:34 / " + path + " rw,relatime - virtiofs lima-9f2a rw\n" +
				"124 46 0:35 / " + path + " rw,relatime - virtiofs lima-ab12 rw\n",
			wantMatches: 2,
			wantOK:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, ok := evalMountinfoWritableVirtiofs(tt.mountinfo, path)
			if matches != tt.wantMatches || ok != tt.wantOK {
				t.Fatalf("evalMountinfoWritableVirtiofs = %d/%t, want %d/%t", matches, ok, tt.wantMatches, tt.wantOK)
			}
		})
	}
}

func TestMediatedWorkspaceMediatesEveryPotentiallyMutatingOpen(t *testing.T) {
	for _, flags := range []uint32{
		uint32(syscall.O_WRONLY),
		uint32(syscall.O_RDWR),
		uint32(syscall.O_TRUNC),
		uint32(syscall.O_APPEND),
		uint32(syscall.O_CREAT),
	} {
		if readOnlyOpen(flags) {
			t.Fatalf("readOnlyOpen(%#x) = true for a potentially mutating open", flags)
		}
	}
	if !readOnlyOpen(uint32(syscall.O_RDONLY)) {
		t.Fatal("readOnlyOpen(O_RDONLY) = false")
	}
}

type recordingWriter struct{ writes int }

func (w *recordingWriter) Write(context.Context, []byte, int64) (uint32, syscall.Errno) {
	w.writes++
	return 1, 0
}

func TestMediatedWorkspaceRefusesWriteWhenRecorderCannotAcknowledge(t *testing.T) {
	batch := NewBatcher(func([]evidence.Event) error { return errors.New("recorder unavailable") })
	batchCtx, cancelBatch := context.WithCancel(context.Background())
	defer cancelBatch()
	go batch.Run(batchCtx)
	writer := &recordingWriter{}
	node := newMediatedWorkspaceNode(&fs.LoopbackRoot{Path: t.TempDir()}, batch, nil, nil)
	file := &mediatedWorkspaceFile{inner: writer, node: node, path: "main.go", mode: evidence.MutationOpenWriteOnly, openerKey: "main.go"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, errno := file.Write(ctx, []byte("x"), 0); errno != syscall.EIO {
		t.Fatalf("Write errno = %v, want EIO", errno)
	}
	if writer.writes != 0 {
		t.Fatalf("backing writes = %d, want 0 after recorder failure", writer.writes)
	}
}

func TestProcessExitDistinguishesCodeSignalAndUnknown(t *testing.T) {
	code := int64(0)
	tests := []struct {
		name        string
		status      ProcessExitStatus
		wantStatus  string
		wantOutcome evidence.Outcome
	}{
		{name: "code", status: ProcessExitStatus{Code: &code}, wantStatus: "code", wantOutcome: evidence.OutcomeSuccess},
		{name: "signal", status: ProcessExitStatus{Signal: "SIGKILL"}, wantStatus: "signal", wantOutcome: evidence.OutcomeInterrupted},
		{name: "signal overrides status field", status: ProcessExitStatus{Code: &code, Signal: "SIGKILL"}, wantStatus: "signal", wantOutcome: evidence.OutcomeInterrupted},
		{name: "unknown", status: ProcessExitStatus{}, wantStatus: "unknown", wantOutcome: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := newProcessExitedEvent(ProcInfo{Pid: 10, Observer: "tetragon"}, tt.status)
			if event.Attrs[attrProcessExitStatus] != tt.wantStatus || event.Outcome != tt.wantOutcome {
				t.Fatalf("status/outcome = %v/%s, want %s/%s", event.Attrs[attrProcessExitStatus], event.Outcome, tt.wantStatus, tt.wantOutcome)
			}
		})
	}
}
