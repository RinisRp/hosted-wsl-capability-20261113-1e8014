package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func TestRelayHelperProcess(t *testing.T) {
	if os.Getenv("BRIDGE_TEST_HELPER") != "1" {
		return
	}
	mode := os.Getenv("BRIDGE_TEST_MODE")
	if mode == "eof-tail" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			os.Exit(8)
		}
		time.Sleep(time.Second)
		_, err = os.Stdout.Write(append(data, []byte("EOF-TAIL")...))
		if err != nil {
			os.Exit(9)
		}
		os.Exit(0)
	}
	if mode == "tail" {
		data := make([]byte, 16)
		if _, err := io.ReadFull(os.Stdin, data); err != nil {
			os.Exit(8)
		}
		_, _ = os.Stdout.Write(data[:8])
		time.Sleep(40 * time.Millisecond)
		_, _ = os.Stdout.Write(append(data[8:], []byte("TAIL")...))
		os.Exit(0)
	}
	if mode == "blocked" {
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	if mode == "stderr" {
		_, _ = os.Stderr.Write(bytes.Repeat([]byte{'x'}, 20000))
	}
	_, err := io.Copy(os.Stdout, os.Stdin)
	if err != nil {
		os.Exit(8)
	}
	if mode == "exit7" {
		os.Exit(7)
	}
	os.Exit(0)
}

func helperCommand(mode string) func(string) *exec.Cmd {
	return func(string) *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=^TestRelayHelperProcess$")
		cmd.Env = append(minimalWindowsEnvironment(), "BRIDGE_TEST_HELPER=1", "BRIDGE_TEST_MODE="+mode)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
		return cmd
	}
}

func freshNonce(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal("nonce fixture failed")
	}
	return hex.EncodeToString(b)
}

func fixtureBridge(t *testing.T, mode string, limit time.Duration) *bridge {
	t.Helper()
	n := freshNonce(t)
	b, err := openBridge(n, "hosted-wsl-"+n, helperCommand(mode), limit)
	if err != nil {
		t.Fatal("owned fixture pipe failed")
	}
	t.Cleanup(func() {
		b.mu.Lock()
		stopped := b.stopping
		b.mu.Unlock()
		if !stopped {
			_ = b.stop(3 * time.Second)
		}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			b.mu.Lock()
			n := len(b.active)
			b.mu.Unlock()
			if n == 0 {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Error("owned fixture relay still active after cleanup")
	})
	return b
}

func waitRecords(t *testing.T, b *bridge, n int) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		b.mu.Lock()
		done := len(b.records) >= n && len(b.active) == 0
		b.mu.Unlock()
		if done {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("owned relay did not reach terminal state")
}

func roundtrip(b *bridge, payload []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := winio.DialPipeContext(ctx, b.path)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return err
	}
	written := make(chan error, 1)
	go func() {
		n, e := io.Copy(conn, bytes.NewReader(payload))
		if e == nil && n != int64(len(payload)) {
			e = io.ErrShortWrite
		}
		written <- e
	}()
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, got); err != nil {
		return err
	}
	if err = <-written; err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return errors.New("binary payload mismatch")
	}
	return nil
}

func TestNonceDistributionRefusals(t *testing.T) {
	good := strings.Repeat("a", 32)
	for _, c := range [][2]string{{"", "hosted-wsl-"}, {"../x", "hosted-wsl-../x"}, {strings.Repeat("A", 32), "hosted-wsl-" + strings.Repeat("A", 32)}, {good, "foreign-" + good}, {good, "hosted-wsl-" + strings.Repeat("b", 32)}} {
		if b, err := openBridge(c[0], c[1], helperCommand("echo"), time.Second); err == nil || b != nil {
			t.Fatal("invalid ownership was accepted")
		}
	}
}

func TestGeneratedProtectedOwnerSystemDescriptor(t *testing.T) {
	sid, sddl, err := currentOwnerSDDL()
	if err != nil {
		t.Fatal("owner descriptor failed")
	}
	if sddl != "O:"+sid+"D:P(A;;GA;;;"+sid+")(A;;GA;;;SY)" {
		t.Fatal("descriptor widened")
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal("descriptor invalid")
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("DACL is not protected")
	}
	owner, _, err := sd.Owner()
	if err != nil || owner.String() != sid {
		t.Fatal("wrong owner")
	}
}

func TestOccupiedAndRetainedNamespaceRefusal(t *testing.T) {
	b := fixtureBridge(t, "echo", 2*time.Second)
	if err := roundtrip(b, []byte{0, 1, 2, 255}); err != nil {
		t.Fatal("first roundtrip failed")
	}
	waitRecords(t, b, 1)
	if other, err := openBridge(b.nonce, b.distribution, helperCommand("echo"), time.Second); err == nil || other != nil {
		t.Fatal("owned first handle was not retained")
	}
	r := b.stop(3 * time.Second)
	if !r.Qualified || !r.EndpointAbsentObserved || r.SDKKernelCloseErrorsChecked {
		t.Fatal("normal ownership lifecycle was not proven")
	}
}

func TestConcurrentBinaryStreamsExceedBuffers(t *testing.T) {
	b := fixtureBridge(t, "echo", 5*time.Second)
	var wg sync.WaitGroup
	errorsCh := make(chan error, 2)
	for seed := 0; seed < 2; seed++ {
		payload := make([]byte, 262144)
		for i := range payload {
			payload[i] = byte((i + seed*13) % 256)
		}
		wg.Add(1)
		go func(p []byte) { defer wg.Done(); errorsCh <- roundtrip(b, p) }(payload)
	}
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal("concurrent binary stream failed")
		}
	}
	waitRecords(t, b, 2)
	r := b.stop(3 * time.Second)
	if !r.Qualified || r.Completed != 2 {
		t.Fatal("concurrent cleanup unqualified")
	}
	for _, c := range r.Records {
		if c.InputBytes != 262144 || c.OutputBytes != 262144 || !c.Qualified {
			t.Fatal("stream accounting or closure failed")
		}
	}
}

func TestNonzeroAndStderrOverflowNeverQualify(t *testing.T) {
	for _, mode := range []string{"exit7", "stderr"} {
		t.Run(mode, func(t *testing.T) {
			b := fixtureBridge(t, mode, 3*time.Second)
			if err := roundtrip(b, []byte("bounded fixture")); err != nil {
				t.Fatal("fixture transfer failed")
			}
			waitRecords(t, b, 1)
			r := b.stop(3 * time.Second)
			if r.Qualified || len(r.Records) != 1 || r.Records[0].Qualified {
				t.Fatal("failed relay falsely qualified")
			}
			if mode == "exit7" && r.Records[0].ExitCode != 7 {
				t.Fatal("native exit7 was lost")
			}
			if mode == "stderr" && !r.Records[0].StderrOverflow {
				t.Fatal("stderr overflow was lost")
			}
		})
	}
}

func TestBlockedRelayIsBoundedAndForcedIsFailure(t *testing.T) {
	b := fixtureBridge(t, "blocked", 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := winio.DialPipeContext(ctx, b.path)
	if err != nil {
		t.Fatal("blocked fixture connect failed")
	}
	defer c.Close()
	waitRecords(t, b, 1)
	r := b.stop(3 * time.Second)
	if r.Qualified || len(r.Records) != 1 || !r.Records[0].Forced || !r.Records[0].TimedOut || !r.Records[0].RootWaitObserved {
		t.Fatal("forced termination became acceptance")
	}
}

type faultConn struct{}

func (*faultConn) Read([]byte) (int, error)         { return 0, errors.New("fixture read failure") }
func (*faultConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*faultConn) Close() error                     { return errors.New("fixture close failure") }
func (*faultConn) LocalAddr() net.Addr              { return nil }
func (*faultConn) RemoteAddr() net.Addr             { return nil }
func (*faultConn) SetDeadline(time.Time) error      { return nil }
func (*faultConn) SetReadDeadline(time.Time) error  { return nil }
func (*faultConn) SetWriteDeadline(time.Time) error { return nil }

func TestPostStartReadAndCloseFailuresRemainFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r := runRelay(ctx, 1, &faultConn{}, helperCommand("echo")("unused"))
	if r.Qualified || !r.RootStarted || !r.RootWaitObserved || len(r.Faults) == 0 || r.FilesClosed {
		t.Fatal("post-start failure truth lost")
	}
}

type closeBlockingListener struct{ release, closed chan struct{} }

func (l *closeBlockingListener) Accept() (net.Conn, error) { <-l.closed; return nil, net.ErrClosed }
func (l *closeBlockingListener) Close() error              { <-l.release; close(l.closed); return nil }
func (l *closeBlockingListener) Addr() net.Addr            { return nil }

func TestListenerCloseCannotDefeatAggregateDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &closeBlockingListener{release: make(chan struct{}), closed: make(chan struct{})}
	nonce := freshNonce(t)
	b := &bridge{nonce: nonce, path: "\\\\.\\pipe\\hosted_wsl_" + nonce, listener: l, ctx: ctx, cancel: cancel, active: make(map[int]*relay), acceptDone: make(chan struct{})}
	go func() { <-l.closed; close(b.acceptDone) }()
	start := time.Now()
	r := b.stop(60 * time.Millisecond)
	close(l.release)
	if time.Since(start) > 500*time.Millisecond || r.Qualified || r.ListenerCloseCompleted || r.AcceptLoopFinished {
		t.Fatal("blocked Close defeated the deadline")
	}
}

func TestChildEnvironmentOmitsCredentialAndContextOverrides(t *testing.T) {
	for _, key := range []string{"GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "WSLENV", "PROBE_NONCE"} {
		t.Setenv(key, "fixture-only")
	}
	for _, entry := range minimalWindowsEnvironment() {
		for _, key := range []string{"GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN", "DOCKER_", "WSLENV", "PROBE_NONCE"} {
			if strings.HasPrefix(strings.ToUpper(entry), key+"=") || strings.HasPrefix(entry, "DOCKER_") {
				t.Fatal("unapproved child environment forwarded")
			}
		}
	}
}

func TestAsymmetricEOFPreservesDelayedBinaryTail(t *testing.T) {
	b := fixtureBridge(t, "tail", 5*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := winio.DialPipeContext(ctx, b.path)
	if err != nil {
		t.Fatal("tail connection failed")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	data := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 255}
	if _, err = io.Copy(conn, bytes.NewReader(data)); err != nil {
		t.Fatal("tail request failed")
	}
	got, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(got, append(data, []byte("TAIL")...)) {
		t.Fatal("asymmetric EOF lost the delayed response tail")
	}
	waitRecords(t, b, 1)
	if !b.stop(3 * time.Second).Qualified {
		t.Fatal("asymmetric relay was not clean")
	}
}

func TestMessageHalfClosePreservesDelayedBinaryTail(t *testing.T) {
	b := fixtureBridge(t, "eof-tail", 6*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := winio.DialPipeContext(ctx, b.path)
	if err != nil {
		t.Fatal("half-close connection failed")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	closer, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("message pipe must expose client CloseWrite")
	}
	data := bytes.Repeat([]byte{0, 255, 13, 10, 42}, 65537)
	if _, err = io.Copy(conn, bytes.NewReader(data)); err != nil {
		t.Fatal("half-close binary request failed")
	}
	closed := make(chan error, 1)
	go func() { closed <- closer.CloseWrite() }()
	select {
	case err = <-closed:
		if err != nil {
			t.Fatal("client half-close failed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client half-close exceeded its test deadline")
	}
	got, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(got, append(data, []byte("EOF-TAIL")...)) {
		t.Fatal("half-close lost delayed binary response")
	}
	waitRecords(t, b, 1)
	if !b.stop(3 * time.Second).Qualified {
		t.Fatal("half-close relay was not clean")
	}
}

func TestWSLCommandHasFinitePostEOFDrain(t *testing.T) {
	distribution := "hosted-wsl-0123456789abcdef0123456789abcdef"
	cmd := launchWSL(distribution)
	expected := []string{filepath.Join(os.Getenv("SystemRoot"), "System32", "wsl.exe"), "--distribution", distribution, "--exec", "/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "/usr/bin/socat", "-t", "120", "STDIO", "UNIX-CONNECT:/var/run/docker.sock"}
	if strings.Join(cmd.Args, "|") != strings.Join(expected, "|") {
		t.Fatal("finite post-EOF drain contract missing")
	}
}

type blockedCloseConn struct{ release chan struct{} }

func (c *blockedCloseConn) Read([]byte) (int, error)         { <-c.release; return 0, io.EOF }
func (c *blockedCloseConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *blockedCloseConn) Close() error                     { <-c.release; return nil }
func (c *blockedCloseConn) LocalAddr() net.Addr              { return nil }
func (c *blockedCloseConn) RemoteAddr() net.Addr             { return nil }
func (c *blockedCloseConn) SetDeadline(time.Time) error      { return nil }
func (c *blockedCloseConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blockedCloseConn) SetWriteDeadline(time.Time) error { return nil }

func TestBlockedConnectionCloseStillClosesChildStdin(t *testing.T) {
	conn := &blockedCloseConn{release: make(chan struct{})}
	defer close(conn.release)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	rec := runRelay(ctx, 1, conn, helperCommand("echo")("unused"))
	if rec.Qualified || !rec.RootWaitObserved || rec.ExitCode != 0 || rec.Forced || !rec.FilesClosed || rec.SDKCloseCompleted {
		t.Fatal("blocked SDK Close suppressed independent stdin/stream cleanup or became acceptance")
	}
}

type lateTimerContext struct {
	context.Context
	deadline time.Time
}

func (c lateTimerContext) Deadline() (time.Time, bool) { return c.deadline, true }

func TestCancelledAndExpiredContextsDoNotStartRoots(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, dispose := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer dispose()
	late := lateTimerContext{Context: context.Background(), deadline: time.Now().Add(-time.Second)}
	for _, ctx := range []context.Context{cancelled, expired, late} {
		cmd := helperCommand("echo")("unused")
		r := runRelay(ctx, 1, &faultConn{}, cmd)
		if r.Qualified || r.RootStarted || cmd.Process != nil || !r.Cancelled {
			t.Fatal("nonlive context started a root or qualified")
		}
	}
}

type cancelReplyConn struct {
	reader *bytes.Reader
	cancel context.CancelFunc
}

func (c *cancelReplyConn) Read(p []byte) (int, error)       { return c.reader.Read(p) }
func (c *cancelReplyConn) Write(p []byte) (int, error)      { c.cancel(); return len(p), nil }
func (c *cancelReplyConn) Close() error                     { return nil }
func (c *cancelReplyConn) LocalAddr() net.Addr              { return nil }
func (c *cancelReplyConn) RemoteAddr() net.Addr             { return nil }
func (c *cancelReplyConn) SetDeadline(time.Time) error      { return nil }
func (c *cancelReplyConn) SetReadDeadline(time.Time) error  { return nil }
func (c *cancelReplyConn) SetWriteDeadline(time.Time) error { return nil }

func TestCompletionAndCancellationRaceCannotQualify(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := &cancelReplyConn{reader: bytes.NewReader([]byte("fixture")), cancel: cancel}
	r := runRelay(ctx, 1, conn, helperCommand("echo")("unused"))
	if r.Qualified || !r.Cancelled || r.ContextValidAtCompletion {
		t.Fatal("completion cases hid cancellation")
	}
}
