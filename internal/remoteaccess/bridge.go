package remoteaccess

import (
	"context"
	"errors"
	"io"
	"net"
)

// BridgeUnixSocket connects a local SSH ProxyCommand's standard input/output
// to one controller-resolved Unix socket. The socket path must be resolved by
// the controller from the session identity; this function does not interpret
// client-provided paths or invoke Lima management SSH.
func BridgeUnixSocket(ctx context.Context, socketPath string, stdin io.Reader, stdout io.Writer) error {
	if socketPath == "" {
		return ErrHostConfigurationUnavailable
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	if err != nil {
		return err
	}
	defer conn.Close()

	type result struct{ err error }
	results := make(chan result, 2)
	go func() {
		_, err := io.Copy(conn, stdin)
		if closeWriter, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = closeWriter.CloseWrite()
		}
		results <- result{err: err}
	}()
	go func() {
		_, err := io.Copy(stdout, conn)
		results <- result{err: err}
	}()

	var firstErr error
	for i := 0; i < 2; i++ {
		select {
		case <-ctx.Done():
			_ = conn.Close()
			return ctx.Err()
		case current := <-results:
			if current.err != nil && !errors.Is(current.err, net.ErrClosed) && !errors.Is(current.err, io.EOF) && firstErr == nil {
				firstErr = current.err
			}
		}
	}
	return firstErr
}
