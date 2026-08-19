package remoteaccess

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestBridgeUnixSocketForwardsBytesBothDirections(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "ba")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "ssh.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		if _, err := io.WriteString(conn, "from-guest"); err != nil {
			serverDone <- err
			return
		}
		buf := make([]byte, len("from-client"))
		_, err = io.ReadFull(conn, buf)
		if err == nil && string(buf) != "from-client" {
			err = io.ErrUnexpectedEOF
		}
		serverDone <- err
	}()

	clientIn, clientInWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer clientIn.Close()
	defer clientInWriter.Close()
	clientOut := new(testBuffer)
	go func() {
		_, _ = io.WriteString(clientInWriter, "from-client")
		_ = clientInWriter.Close()
	}()
	if err := BridgeUnixSocket(context.Background(), path, clientIn, clientOut); err != nil {
		t.Fatalf("bridge: %v", err)
	}
	if got := clientOut.String(); got != "from-guest" {
		t.Fatalf("stdout = %q, want from-guest", got)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server: %v", err)
	}
}

type testBuffer struct{ data []byte }

func (b *testBuffer) Write(p []byte) (int, error) {
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *testBuffer) String() string { return string(b.data) }
