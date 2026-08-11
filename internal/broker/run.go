package broker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const (
	execTimeout   = 60 * time.Second
	maxToolOutput = 1 << 20  // 1 MiB stdout cap
	maxStderr     = 64 << 10 // bounded stderr for error context
)

// placeholderRE matches {{name}} template placeholders.
var placeholderRE = regexp.MustCompile(`\{\{(\w+)\}\}`)

// substituteArgv fills {{name}} placeholders in the adapter template from the argument
// map. Substitution is strict: every placeholder must have a value, and every supplied
// argument must be consumed by some placeholder. There is no shell — the result is an
// exec argv used directly.
func substituteArgv(template []string, args map[string]string) ([]string, error) {
	used := make(map[string]bool, len(args))
	var missing []string
	out := make([]string, len(template))
	for i, tok := range template {
		out[i] = placeholderRE.ReplaceAllStringFunc(tok, func(m string) string {
			name := placeholderRE.FindStringSubmatch(m)[1]
			v, ok := args[name]
			if !ok {
				missing = append(missing, name)
				return ""
			}
			used[name] = true
			return v
		})
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing value(s) for placeholder(s): %s", strings.Join(missing, ", "))
	}
	for k := range args {
		if !used[k] {
			return nil, fmt.Errorf("unknown argument %q", k)
		}
	}
	return out, nil
}

// runCommand executes argv directly (no shell) with a 60s timeout, capturing stdout up
// to maxToolOutput. It reports whether stdout was truncated at the cap.
func runCommand(ctx context.Context, argv []string) (stdout []byte, truncated bool, err error) {
	if len(argv) == 0 {
		return nil, false, errors.New("empty argv")
	}
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	out := &cappedBuffer{limit: maxToolOutput}
	errBuf := &cappedBuffer{limit: maxStderr}
	cmd.Stdout = out
	cmd.Stderr = errBuf

	runErr := cmd.Run()
	if runErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return out.buf.Bytes(), out.truncated, fmt.Errorf("command %q timed out after %s", argv[0], execTimeout)
		}
		return out.buf.Bytes(), out.truncated, fmt.Errorf("command %q failed: %w (stderr: %s)", argv[0], runErr, strings.TrimSpace(errBuf.buf.String()))
	}
	return out.buf.Bytes(), out.truncated, nil
}

// cappedBuffer is an io.Writer that retains at most limit bytes, dropping the rest while
// reporting a full write so the child process is not killed by a short-write error.
type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if remaining := c.limit - c.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			c.buf.Write(p[:remaining])
			c.truncated = true
		} else {
			c.buf.Write(p)
		}
	} else if len(p) > 0 {
		c.truncated = true
	}
	return len(p), nil
}
