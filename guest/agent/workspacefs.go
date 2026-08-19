package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"boxedai/internal/evidence"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// workspaceDigestCapBytes bounds each guest candidate. The host overwrites this
// candidate digest from its own workspace view before the recorder seals it.
const workspaceDigestCapBytes = 8 * 1024 * 1024
const workspaceMutationDeliveryTimeout = 10 * time.Second
const workspaceAccessDenyLogInterval = time.Minute

var mediatedWorkspaceAccessDenials atomic.Uint64

var mediatedWorkspaceAccessDenyLog struct {
	sync.Mutex
	last time.Time
}

func startMediatedWorkspace(cfg Config, batch *Batcher) error {
	if err := verifyMediatedWorkspacePrerequisites(cfg); err != nil {
		return err
	}
	st := syscall.Stat_t{}
	if err := syscall.Stat(cfg.WorkspaceLowerPath, &st); err != nil {
		return fmt.Errorf("stat lower workspace %s: %w", cfg.WorkspaceLowerPath, err)
	}
	if err := os.MkdirAll(cfg.WorkspacePath, 0o755); err != nil {
		return fmt.Errorf("create mediated workspace mount %s: %w", cfg.WorkspacePath, err)
	}
	rootData := &fs.LoopbackRoot{Path: cfg.WorkspaceLowerPath, Dev: uint64(st.Dev)}
	root := newMediatedWorkspaceNode(rootData, batch, cfg.SubjectMap, cfg.HumanAccessGrant)
	rootData.RootNode = root
	rootData.NewNode = func(data *fs.LoopbackRoot, _ *fs.Inode, _ string, _ *syscall.Stat_t) fs.InodeEmbedder {
		return newMediatedWorkspaceNodeWithOpeners(data, batch, cfg.SubjectMap, cfg.HumanAccessGrant, root.openers)
	}
	server, err := fs.Mount(cfg.WorkspacePath, root, &fs.Options{MountOptions: fuse.MountOptions{AllowOther: true}})
	if err != nil {
		return fmt.Errorf("mount mediated workspace: %w", err)
	}
	if server.KernelSettings().Flags64()&fuse.CAP_PASSTHROUGH == 0 {
		_ = server.Unmount()
		return fmt.Errorf("guest kernel does not support FUSE passthrough")
	}
	// No writeback-cache rejection here: KernelSettings() reports the flags the
	// kernel OFFERED in FUSE_INIT, not the ones that were negotiated. go-fuse never
	// requests CAP_WRITEBACK_CACHE -- it is absent from the INIT capability
	// allowlist in go-fuse's fuse/opcode.go -- so the writeback cache is never
	// actually enabled and every write still reaches this mediator for attribution.
	// Kernels >= 7.0 advertise the capability unconditionally, so testing the OFFER
	// (as this did) rejected every otherwise-valid mount and crash-looped the agent.
	return nil
}

type mediatedWorkspaceNode struct {
	fs.LoopbackNode
	batch      *Batcher
	subjectMap *evidence.SessionSubjectMap
	grant      *evidence.HumanAccessGrant
	openers    *workspaceOpenerRegistry
}

func newMediatedWorkspaceNode(root *fs.LoopbackRoot, batch *Batcher, subjectMap *evidence.SessionSubjectMap, grant *evidence.HumanAccessGrant) *mediatedWorkspaceNode {
	return newMediatedWorkspaceNodeWithOpeners(root, batch, subjectMap, grant, newWorkspaceOpenerRegistry())
}

func newMediatedWorkspaceNodeWithOpeners(root *fs.LoopbackRoot, batch *Batcher, subjectMap *evidence.SessionSubjectMap, grant *evidence.HumanAccessGrant, openers *workspaceOpenerRegistry) *mediatedWorkspaceNode {
	return &mediatedWorkspaceNode{LoopbackNode: fs.LoopbackNode{RootData: root}, batch: batch, subjectMap: subjectMap, grant: grant, openers: openers}
}

// Open returns the loopback handle unchanged only for genuinely read-only opens.
// go-fuse then registers its backing FD and requests kernel FOPEN_PASSTHROUGH.
// Every writable or O_RDWR handle is wrapped, which deliberately withholds that
// interface and keeps subsequent writes inside this mediator.
func (n *mediatedWorkspaceNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	// Authorization is deliberately at open, before a backing descriptor exists.
	// Lookup/Getattr remain ungated so ordinary filesystem inspection is intact.
	if !readOnlyOpen(flags) {
		if errno := n.authorize(ctx, evidence.MutationOperationWrite); errno != 0 {
			return nil, 0, errno
		}
		if errno := n.emit(ctx, evidence.MutationOperationWrite, n.relativePath(), 0, true, openMode(flags), mutationBasisCaller); errno != 0 {
			return nil, 0, errno
		}
		if flags&syscall.O_TRUNC != 0 {
			if errno := n.emit(ctx, evidence.MutationOperationTruncate, n.relativePath(), 0, false, openMode(flags), mutationBasisCaller); errno != 0 {
				return nil, 0, errno
			}
		}
	}
	fh, fuseFlags, errno := n.LoopbackNode.Open(ctx, flags)
	if errno != 0 || readOnlyOpen(flags) {
		return fh, fuseFlags, errno
	}
	return n.newFileHandle(fh, n.relativePath(), openMode(flags), callerUID(ctx), n.EmbeddedInode()), fuseFlags, 0
}

// OpendirHandle and Readdir are explicit gates because LoopbackNode's directory
// interfaces otherwise let an unmapped UID enumerate mediated workspace names.
// Lookup/Getattr intentionally remain available for ordinary path inspection.
func (n *mediatedWorkspaceNode) OpendirHandle(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	if errno := n.authorize(ctx, evidence.MutationOperationMetadata); errno != 0 {
		return nil, 0, errno
	}
	return n.LoopbackNode.OpendirHandle(ctx, flags)
}

func (n *mediatedWorkspaceNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	if errno := n.authorize(ctx, evidence.MutationOperationMetadata); errno != 0 {
		return nil, errno
	}
	return n.LoopbackNode.Readdir(ctx)
}

func (n *mediatedWorkspaceNode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	path := n.childPath(name)
	if errno := n.authorize(ctx, evidence.MutationOperationReplace); errno != 0 {
		return nil, nil, 0, errno
	}
	if errno := n.emit(ctx, evidence.MutationOperationReplace, path, 0, false, openMode(flags), mutationBasisCaller); errno != 0 {
		return nil, nil, 0, errno
	}
	inode, fh, fuseFlags, errno := n.LoopbackNode.Create(ctx, name, flags, mode, out)
	if errno != 0 {
		return inode, fh, fuseFlags, errno
	}
	return inode, n.newFileHandle(fh, path, openMode(flags), callerUID(ctx), inode), fuseFlags, 0
}

func (n *mediatedWorkspaceNode) Unlink(ctx context.Context, name string) syscall.Errno {
	if errno := n.emit(ctx, evidence.MutationOperationDelete, n.childPath(name), 0, false, evidence.MutationOpenWriteOnly, mutationBasisCaller); errno != 0 {
		return errno
	}
	errno := n.LoopbackNode.Unlink(ctx, name)
	return errno
}

func (n *mediatedWorkspaceNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	if errno := n.emit(ctx, evidence.MutationOperationDelete, n.childPath(name), 0, false, evidence.MutationOpenWriteOnly, mutationBasisCaller); errno != 0 {
		return errno
	}
	errno := n.LoopbackNode.Rmdir(ctx, name)
	return errno
}

func (n *mediatedWorkspaceNode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if errno := n.emit(ctx, evidence.MutationOperationMetadata, n.childPath(name), 0, false, evidence.MutationOpenWriteOnly, mutationBasisCaller); errno != 0 {
		return nil, errno
	}
	inode, errno := n.LoopbackNode.Mkdir(ctx, name, mode, out)
	return inode, errno
}

func (n *mediatedWorkspaceNode) Mknod(ctx context.Context, name string, mode, rdev uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if errno := n.emit(ctx, evidence.MutationOperationReplace, n.childPath(name), 0, false, evidence.MutationOpenWriteOnly, mutationBasisCaller); errno != 0 {
		return nil, errno
	}
	inode, errno := n.LoopbackNode.Mknod(ctx, name, mode, rdev, out)
	return inode, errno
}

func (n *mediatedWorkspaceNode) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if errno := n.emit(ctx, evidence.MutationOperationReplace, n.childPath(name), 0, false, evidence.MutationOpenWriteOnly, mutationBasisCaller); errno != 0 {
		return nil, errno
	}
	inode, errno := n.LoopbackNode.Symlink(ctx, target, name, out)
	return inode, errno
}

func (n *mediatedWorkspaceNode) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if errno := n.emit(ctx, evidence.MutationOperationMetadata, n.childPath(name), 0, false, evidence.MutationOpenWriteOnly, mutationBasisCaller); errno != 0 {
		return nil, errno
	}
	inode, errno := n.LoopbackNode.Link(ctx, target, name, out)
	return inode, errno
}

func (n *mediatedWorkspaceNode) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	path := n.childPath(newName)
	if parent, ok := newParent.(*mediatedWorkspaceNode); ok {
		path = parent.childPath(newName)
	}
	if errno := n.emit(ctx, evidence.MutationOperationRename, path, 0, false, evidence.MutationOpenWriteOnly, mutationBasisCaller); errno != 0 {
		return errno
	}
	return n.LoopbackNode.Rename(ctx, name, newParent, newName, flags)
}

func (n *mediatedWorkspaceNode) Setattr(ctx context.Context, fh fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	operation := evidence.MutationOperationMetadata
	if _, ok := in.GetSize(); ok {
		operation = evidence.MutationOperationTruncate
	}
	if errno := n.emit(ctx, operation, n.relativePath(), 0, false, evidence.MutationOpenWriteOnly, mutationBasisCaller); errno != 0 {
		return errno
	}
	errno := n.LoopbackNode.Setattr(ctx, fh, in, out)
	return errno
}

func (n *mediatedWorkspaceNode) Setxattr(ctx context.Context, attr string, data []byte, flags uint32) syscall.Errno {
	if errno := n.emit(ctx, evidence.MutationOperationMetadata, n.relativePath(), 0, false, evidence.MutationOpenWriteOnly, mutationBasisCaller); errno != 0 {
		return errno
	}
	return n.LoopbackNode.Setxattr(ctx, attr, data, flags)
}

func (n *mediatedWorkspaceNode) Removexattr(ctx context.Context, attr string) syscall.Errno {
	if errno := n.emit(ctx, evidence.MutationOperationMetadata, n.relativePath(), 0, false, evidence.MutationOpenWriteOnly, mutationBasisCaller); errno != 0 {
		return errno
	}
	return n.LoopbackNode.Removexattr(ctx, attr)
}

func (n *mediatedWorkspaceNode) CopyFileRange(context.Context, fs.FileHandle, uint64, *fs.Inode, fs.FileHandle, uint64, uint64, uint64) (uint32, syscall.Errno) {
	return 0, syscall.EOPNOTSUPP
}

type mutationBasis string

const (
	mutationBasisCaller    mutationBasis = "caller"
	mutationBasisFallback  mutationBasis = "opener_fallback"
	mutationBasisAmbiguous mutationBasis = "ambiguous"
)

func (n *mediatedWorkspaceNode) authorize(ctx context.Context, operation evidence.MutationOperation) syscall.Errno {
	if n.subjectMap == nil {
		return 0
	}
	if !n.subjectMap.AllowsMutation(callerUID(ctx), n.grant, operation, time.Now()) {
		noteMediatedWorkspaceAccessDenied(callerUID(ctx), operation)
		return syscall.EACCES
	}
	return 0
}

func noteMediatedWorkspaceAccessDenied(uid int64, operation evidence.MutationOperation) {
	mediatedWorkspaceAccessDenials.Add(1)
	mediatedWorkspaceAccessDenyLog.Lock()
	defer mediatedWorkspaceAccessDenyLog.Unlock()
	if time.Since(mediatedWorkspaceAccessDenyLog.last) < workspaceAccessDenyLogInterval {
		return
	}
	mediatedWorkspaceAccessDenyLog.last = time.Now()
	log.Printf("agent: denied mediated workspace %s for uid %d", operation, uid)
}

func (n *mediatedWorkspaceNode) emit(ctx context.Context, operation evidence.MutationOperation, path string, position int64, positional bool, mode evidence.MutationOpenMode, basis mutationBasis) syscall.Errno {
	if errno := n.authorize(ctx, operation); errno != 0 {
		return errno
	}
	return n.emitWithUID(ctx, callerUID(ctx), callerUID(ctx), operation, path, position, positional, mode, basis)
}

// emitWithUID is used by an already-authorized file descriptor. Do not add an
// authorization check here: Write is intentionally not a second authorization
// point, because its caller identity may be absent or differ after Open.
func (n *mediatedWorkspaceNode) emitWithUID(ctx context.Context, uid, openerUID int64, operation evidence.MutationOperation, path string, position int64, positional bool, mode evidence.MutationOpenMode, basis mutationBasis) syscall.Errno {
	digest := n.digest(path)
	actor := evidence.MutationActorUnattributed
	if n.subjectMap != nil {
		actor = evidence.MutationActorFor(uid, *n.subjectMap, n.grant, time.Now())
	}
	attrs := map[string]any{
		evidence.AttrMutationUID:          uid,
		evidence.AttrMutationOpenerUID:    openerUID,
		evidence.AttrMutationActorClass:   string(actor),
		evidence.AttrMutationBasis:        string(basis),
		evidence.AttrMutationOpenMode:     string(mode),
		evidence.AttrMutationOperation:    string(operation),
		evidence.AttrMutationPath:         path,
		evidence.AttrContentDigest:        digest,
		evidence.AttrContentCapture:       string(evidence.CaptureDigestOnly),
		evidence.AttrMutationPositionKind: string(evidence.MutationPositionNonPositional),
	}
	if positional {
		attrs[evidence.AttrMutationPositionKind] = string(evidence.MutationPositionPositional)
		attrs[evidence.AttrMutationPosition] = position
	}
	if n.grant != nil && actor == evidence.MutationActorHuman {
		attrs[evidence.AttrHumanAccessGrantID] = n.grant.GrantID
		attrs[evidence.AttrHumanAccessSubjectID] = n.grant.SubjectID
	}
	flushCtx, cancel := context.WithTimeout(ctx, workspaceMutationDeliveryTimeout)
	defer cancel()
	if err := n.batch.AddAndFlush(flushCtx, evidence.Event{
		Name:        evidence.EventWorkspaceMutated,
		Time:        time.Now(),
		MonotonicNS: monotonicNS(),
		Class:       evidence.ClassKernelObserved,
		Outcome:     evidence.OutcomeSuccess,
		Body:        "workspace mutation " + path,
		Attrs:       attrs,
	}); err != nil {
		return syscall.EIO
	}
	return 0
}

func (n *mediatedWorkspaceNode) digest(path string) string {
	file, err := os.Open(filepath.Join(n.RootData.Path, filepath.FromSlash(path)))
	if err != nil {
		return evidence.SHA256Hex(nil)
	}
	defer file.Close()
	hash := sha256.New()
	_, _ = io.CopyN(hash, file, workspaceDigestCapBytes)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func (n *mediatedWorkspaceNode) relativePath() string {
	return strings.TrimPrefix(filepath.ToSlash(n.Path(n.Root())), "/")
}

func (n *mediatedWorkspaceNode) childPath(name string) string {
	return strings.TrimPrefix(filepath.ToSlash(filepath.Join(n.relativePath(), name)), "/")
}

type mediatedWorkspaceFile struct {
	inner     fs.FileHandle
	node      *mediatedWorkspaceNode
	path      string
	mode      evidence.MutationOpenMode
	openerKey string
	openerID  uint64
}

func (n *mediatedWorkspaceNode) newFileHandle(inner fs.FileHandle, path string, mode evidence.MutationOpenMode, uid int64, inode *fs.Inode) *mediatedWorkspaceFile {
	key := n.inodeKey(inode, path)
	id := n.openers.add(key, uid)
	return &mediatedWorkspaceFile{inner: inner, node: n, path: path, mode: mode, openerKey: key, openerID: id}
}

func (f *mediatedWorkspaceFile) Write(ctx context.Context, data []byte, offset int64) (uint32, syscall.Errno) {
	writer, ok := f.inner.(fs.FileWriter)
	if !ok {
		return 0, syscall.EIO
	}
	uid, basis := f.node.openers.resolve(f.openerKey, callerUID(ctx), f.node.isSubjectUID)
	if errno := f.node.emitWithUID(ctx, uid, f.openerUID(), evidence.MutationOperationWrite, f.path, offset, true, f.mode, basis); errno != 0 {
		return 0, errno
	}
	return writer.Write(ctx, data, offset)
}

func (f *mediatedWorkspaceFile) Read(ctx context.Context, dest []byte, offset int64) (fuse.ReadResult, syscall.Errno) {
	reader, ok := f.inner.(fs.FileReader)
	if !ok {
		return nil, syscall.EIO
	}
	return reader.Read(ctx, dest, offset)
}

func (f *mediatedWorkspaceFile) Release(ctx context.Context) syscall.Errno {
	f.node.openers.remove(f.openerKey, f.openerID)
	releaser, ok := f.inner.(fs.FileReleaser)
	if !ok {
		return 0
	}
	return releaser.Release(ctx)
}

func (f *mediatedWorkspaceFile) Flush(ctx context.Context) syscall.Errno {
	flusher, ok := f.inner.(fs.FileFlusher)
	if !ok {
		return 0
	}
	return flusher.Flush(ctx)
}

func (f *mediatedWorkspaceFile) Fsync(ctx context.Context, flags uint32) syscall.Errno {
	fsyncer, ok := f.inner.(fs.FileFsyncer)
	if !ok {
		return 0
	}
	return fsyncer.Fsync(ctx, flags)
}

func (f *mediatedWorkspaceFile) Getattr(ctx context.Context, out *fuse.AttrOut) syscall.Errno {
	getter, ok := f.inner.(fs.FileGetattrer)
	if !ok {
		return syscall.EIO
	}
	return getter.Getattr(ctx, out)
}

func (f *mediatedWorkspaceFile) Lseek(ctx context.Context, offset uint64, whence uint32) (uint64, syscall.Errno) {
	seeker, ok := f.inner.(fs.FileLseeker)
	if !ok {
		return 0, syscall.EOPNOTSUPP
	}
	return seeker.Lseek(ctx, offset, whence)
}

func (f *mediatedWorkspaceFile) Getlk(ctx context.Context, owner uint64, lock *fuse.FileLock, flags uint32, out *fuse.FileLock) syscall.Errno {
	locker, ok := f.inner.(fs.FileGetlker)
	if !ok {
		return syscall.EOPNOTSUPP
	}
	return locker.Getlk(ctx, owner, lock, flags, out)
}

func (f *mediatedWorkspaceFile) Setlk(ctx context.Context, owner uint64, lock *fuse.FileLock, flags uint32) syscall.Errno {
	locker, ok := f.inner.(fs.FileSetlker)
	if !ok {
		return syscall.EOPNOTSUPP
	}
	return locker.Setlk(ctx, owner, lock, flags)
}

func (f *mediatedWorkspaceFile) Setlkw(ctx context.Context, owner uint64, lock *fuse.FileLock, flags uint32) syscall.Errno {
	locker, ok := f.inner.(fs.FileSetlkwer)
	if !ok {
		return syscall.EOPNOTSUPP
	}
	return locker.Setlkw(ctx, owner, lock, flags)
}

func (*mediatedWorkspaceFile) Allocate(context.Context, uint64, uint64, uint32) syscall.Errno {
	return syscall.EOPNOTSUPP
}

type workspaceOpenerRegistry struct {
	mu      sync.Mutex
	nextID  uint64
	byInode map[string]map[uint64]int64
}

func newWorkspaceOpenerRegistry() *workspaceOpenerRegistry {
	return &workspaceOpenerRegistry{byInode: make(map[string]map[uint64]int64)}
}

func (r *workspaceOpenerRegistry) add(inode string, uid int64) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextID++
	if r.byInode[inode] == nil {
		r.byInode[inode] = make(map[uint64]int64)
	}
	r.byInode[inode][r.nextID] = uid
	return r.nextID
}

func (r *workspaceOpenerRegistry) remove(inode string, id uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byInode[inode], id)
	if len(r.byInode[inode]) == 0 {
		delete(r.byInode, inode)
	}
}

// resolve uses the kernel caller only when the sealed subject map recognizes it.
// Kernel writeback and supervisor-root contexts are not subject-map principals, so
// they must fall back to the active opener set rather than acquiring attribution.
func (r *workspaceOpenerRegistry) resolve(inode string, caller int64, isSubjectUID func(int64) bool) (int64, mutationBasis) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if caller >= 0 && isSubjectUID(caller) {
		return caller, mutationBasisCaller
	}
	openers := r.byInode[inode]
	if len(openers) == 0 {
		return -1, mutationBasisAmbiguous
	}
	var uid int64 = -1
	for _, openerUID := range openers {
		if uid >= 0 && openerUID != uid {
			return -1, mutationBasisAmbiguous
		}
		uid = openerUID
	}
	return uid, mutationBasisFallback
}

func (n *mediatedWorkspaceNode) isSubjectUID(uid int64) bool {
	if n.subjectMap == nil {
		return false
	}
	for _, subject := range n.subjectMap.Subjects {
		if subject.UID == uid {
			return true
		}
	}
	return false
}

func (f *mediatedWorkspaceFile) openerUID() int64 {
	f.node.openers.mu.Lock()
	defer f.node.openers.mu.Unlock()
	return f.node.openers.byInode[f.openerKey][f.openerID]
}

func (n *mediatedWorkspaceNode) inodeKey(inode *fs.Inode, path string) string {
	if inode != nil && inode.StableAttr().Ino != 0 {
		return strconv.FormatUint(n.RootData.Dev, 10) + ":" + strconv.FormatUint(inode.StableAttr().Ino, 10)
	}
	return path
}

func callerUID(ctx context.Context) int64 {
	caller, ok := fuse.FromContext(ctx)
	if !ok {
		return -1
	}
	return int64(caller.Uid)
}

func openMode(flags uint32) evidence.MutationOpenMode {
	if flags&syscall.O_RDWR != 0 {
		return evidence.MutationOpenReadWrite
	}
	return evidence.MutationOpenWriteOnly
}

func readOnlyOpen(flags uint32) bool {
	return flags&syscall.O_ACCMODE == syscall.O_RDONLY && flags&(syscall.O_APPEND|syscall.O_CREAT|syscall.O_EXCL|syscall.O_TRUNC) == 0
}

func verifyMediatedWorkspacePrerequisites(cfg Config) error {
	if cfg.SubjectMap == nil || cfg.HumanAccessGrant == nil {
		return fmt.Errorf("mediated workspace requires sealed subject binding")
	}
	if err := cfg.SubjectMap.Validate(); err != nil {
		return fmt.Errorf("validate mediated subject map: %w", err)
	}
	if err := cfg.HumanAccessGrant.Validate(); err != nil {
		return fmt.Errorf("validate mediated human access grant: %w", err)
	}
	if cfg.SubjectMap.SessionID != cfg.SessionID || cfg.HumanAccessGrant.SessionID != cfg.SessionID {
		return fmt.Errorf("mediated workspace subject binding does not match session")
	}
	if err := requireKernel69(); err != nil {
		return err
	}
	if err := requireSysAdmin(); err != nil {
		return err
	}
	if err := requireWritableVirtiofsLowerMount(cfg.WorkspaceLowerPath); err != nil {
		return err
	}
	if err := requireRootOnlyPrivateLowerParent(cfg.WorkspaceLowerPath); err != nil {
		return err
	}
	if err := probeLowerMountAccess(cfg.WorkspaceLowerPath, cfg.WorkloadUID, evidence.HumanUID); err != nil {
		return err
	}
	if err := probeLowerMountWriteThrough(cfg.WorkspaceLowerPath); err != nil {
		return err
	}
	return nil
}

func requireKernel69() error {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return fmt.Errorf("read guest kernel release: %w", err)
	}
	parts := strings.SplitN(strings.TrimSpace(string(data)), ".", 3)
	if len(parts) < 2 {
		return fmt.Errorf("parse guest kernel release %q", strings.TrimSpace(string(data)))
	}
	major, majorErr := strconv.Atoi(parts[0])
	minor, minorErr := strconv.Atoi(parts[1])
	if majorErr != nil || minorErr != nil || major < 6 || major == 6 && minor < 9 {
		return fmt.Errorf("guest kernel %q does not support FUSE passthrough; require >= 6.9", strings.TrimSpace(string(data)))
	}
	return nil
}

func requireSysAdmin() error {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return fmt.Errorf("read guest capabilities: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		value, ok := strings.CutPrefix(line, "CapEff:\t")
		if !ok {
			continue
		}
		caps, err := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
		if err != nil || caps&(uint64(1)<<21) == 0 {
			return fmt.Errorf("guest supervisor lacks CAP_SYS_ADMIN")
		}
		return nil
	}
	return fmt.Errorf("guest supervisor capability state missing CapEff")
}

// requireWritableVirtiofsLowerMount verifies the lower workspace is backed by
// exactly one writable virtiofs mount at its expected mountpoint. It
// deliberately does NOT pin the virtiofs source tag: Lima assigns the
// virtiofs device tag itself (its mount schema has no `tag:` field, so a
// host-chosen value is silently dropped and Lima substitutes its own
// `lima-<hash>`), so a fixed expected tag can never match. The anchor is the
// mountpoint, which only root can mount over -- requireRootOnlyPrivateLowerParent
// proves its parent is root:root 0700 -- so the workload and human uids cannot
// introduce a competing mount there.
func requireWritableVirtiofsLowerMount(path string) error {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return fmt.Errorf("read guest mount state: %w", err)
	}
	matches, ok := evalMountinfoWritableVirtiofs(string(data), path)
	if matches == 1 && ok {
		return nil
	}
	if matches > 1 {
		return fmt.Errorf("guest lower workspace %s has %d mounts, want exactly one", path, matches)
	}
	return fmt.Errorf("guest lower workspace %s is not a single writable virtiofs mount", path)
}

// evalMountinfoWritableVirtiofs scans an in-memory /proc/self/mountinfo-format
// string for lines whose mountpoint field (space-split index 4) equals path.
// matches counts every such line regardless of type (more than one is always
// a failure); ok is true only when there is exactly one and it is a
// read-write virtiofs mount with a non-empty source tag. Factored out of
// requireWritableVirtiofsLowerMount as a pure function so the token-exact
// rw/ro parsing can be unit tested against fixed mountinfo text without a
// live /proc.
func evalMountinfoWritableVirtiofs(mountinfo, path string) (matches int, ok bool) {
	var fields []string
	var line string
	for _, candidate := range strings.Split(mountinfo, "\n") {
		f := strings.Fields(candidate)
		if len(f) < 7 || f[4] != path {
			continue
		}
		matches++
		fields, line = f, candidate
	}
	if matches != 1 {
		return matches, false
	}
	separator := strings.Index(line, " - ")
	if separator < 0 {
		return matches, false
	}
	post := strings.Fields(strings.TrimSpace(line[separator+3:]))
	if len(post) < 3 || post[0] != "virtiofs" || post[1] == "" {
		return matches, false
	}
	// TOKEN-EXACT, never strings.Contains: a superblock option like
	// "errors=remount-ro" must not be misread as read-only just because it
	// contains the substring "ro". Both the per-mount options (fields[5]) and
	// the superblock options (post[2]) are checked.
	if !mountOptionsAreReadWrite(fields[5]) || !mountOptionsAreReadWrite(post[2]) {
		return matches, false
	}
	return matches, true
}

// mountOptionsAreReadWrite reports whether a comma-separated mountinfo option
// list carries the exact "rw" token and not the exact "ro" token. This is
// token-exact rather than substring matching so options like
// "errors=remount-ro" are never mistaken for a read-only mount.
func mountOptionsAreReadWrite(opts string) bool {
	var rw, ro bool
	for _, opt := range strings.Split(opts, ",") {
		switch opt {
		case "rw":
			rw = true
		case "ro":
			ro = true
		}
	}
	return rw && !ro
}

func requireRootOnlyPrivateLowerParent(path string) error {
	parent := filepath.Dir(path)
	info, err := os.Stat(parent)
	if err != nil {
		return fmt.Errorf("stat guest lower workspace parent %s: %w", parent, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("read ownership of guest lower workspace parent %s", parent)
	}
	if stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("guest lower workspace parent %s is not root:root mode 0700", parent)
	}
	return nil
}

// probeLowerMountWriteThrough proves the lower workspace mount actually
// accepts writes before the FUSE mediator starts trusting it as a write-through
// backing store. Without this, a regression back to a read-only virtiofs mount
// would surface only as a silent EROFS on the first agent or human write, deep
// inside the mediator, instead of failing the guest agent closed at startup.
// The guest agent already runs as root (fsuid 0), so this uses plain os
// operations -- no setfsuid impersonation dance like probeLowerMountAccess
// needs to test unprivileged uids. The probe file is created with O_EXCL: an
// EEXIST here is a hard failure, since nothing else may have written to the
// lower before this check runs. The sentinel is unlinked before returning
// (success or failure), so it can never appear in any manifest.
func probeLowerMountWriteThrough(path string) error {
	probe := filepath.Join(path, ".boxedai-write-probe")
	file, err := os.OpenFile(probe, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create lower workspace write probe %s: %w", probe, err)
	}
	// Best-effort safety net so the sentinel is unlinked even if a step below
	// fails and returns early. The explicit os.Remove on the success path is
	// what actually reports a removal failure; by then the file is already
	// gone, so this deferred second attempt is a harmless no-op.
	defer os.Remove(probe)
	if _, err := file.Write([]byte("boxedai-write-probe")); err != nil {
		_ = file.Close()
		return fmt.Errorf("write lower workspace write probe %s: %w", probe, err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync lower workspace write probe %s: %w", probe, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close lower workspace write probe %s: %w", probe, err)
	}
	if err := os.Remove(probe); err != nil {
		return fmt.Errorf("remove lower workspace write probe %s: %w", probe, err)
	}
	return nil
}
