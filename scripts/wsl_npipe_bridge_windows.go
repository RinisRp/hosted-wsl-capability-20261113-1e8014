package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

var noncePattern = regexp.MustCompile("^[0-9a-f]{32}$")

type relayRecord struct {
	Cancelled, ContextValidAtStart, ContextValidAtCompletion                     bool
	ID, PID, ExitCode                                                            int
	RootStarted, RootWaitObserved, InputFinished, OutputFinished, StderrFinished bool
	SDKCloseCompleted, FilesClosed, Forced, TimedOut, StderrOverflow, Qualified  bool
	StartedBeforeUTC                                                             string
	InputBytes, OutputBytes, StderrBytes                                         int64
	Faults                                                                       []string
}

type bridgeReport struct {
	// Active and Completed count handlers. Unknown* separately retains any
	// unresolved resource accounting after an unsuccessful handler returns.
	UnknownRoots, UnknownPumps, UnknownConnectionCloses                int
	Schema                                                             int
	Nonce, Endpoint, OwnerSID, SDK                                     string
	Accepted, Completed, Active                                        int
	ListenerCloseCompleted, AcceptLoopFinished, EndpointAbsentObserved bool
	SDKKernelCloseErrorsChecked, PayloadLogged, Qualified              bool
	Records                                                            []relayRecord
	Faults                                                             []string
}

type relay struct {
	conn   net.Conn
	cancel context.CancelFunc
}

type bridge struct {
	mu                                         sync.Mutex
	nonce, distribution, path, endpoint, owner string
	listener                                   net.Listener
	acceptDone                                 chan struct{}
	ctx                                        context.Context
	cancel                                     context.CancelFunc
	factory                                    func(string) *exec.Cmd
	active                                     map[int]*relay
	records                                    []relayRecord
	faults                                     []string
	accepted                                   int
	stopping                                   bool
	connectionLimit                            time.Duration
}

func currentOwnerSDDL() (string, string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", "", errors.New("OWNER_TOKEN_REQUIRED")
	}
	sid := u.User.Sid.String()
	return sid, "O:" + sid + "D:P(A;;GA;;;" + sid + ")(A;;GA;;;SY)", nil
}

func openBridge(nonce, distribution string, factory func(string) *exec.Cmd, connectionLimit time.Duration) (*bridge, error) {
	if !noncePattern.MatchString(nonce) || distribution != "hosted-wsl-"+nonce || factory == nil || connectionLimit <= 0 {
		return nil, errors.New("EXACT_OWN_DISTRIBUTION_AND_NONCE_REQUIRED")
	}
	sid, sddl, err := currentOwnerSDDL()
	if err != nil {
		return nil, err
	}
	path := "\\\\.\\pipe\\hosted_wsl_" + nonce
	listener, err := winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: sddl, MessageMode: false, InputBufferSize: 32768, OutputBufferSize: 32768})
	if err != nil {
		return nil, errors.New("FRESH_LOCAL_PIPE_REQUIRED")
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &bridge{nonce: nonce, distribution: distribution, path: path, endpoint: "npipe:////./pipe/hosted_wsl_" + nonce, owner: sid, listener: listener, acceptDone: make(chan struct{}), ctx: ctx, cancel: cancel, factory: factory, active: make(map[int]*relay), connectionLimit: connectionLimit}
	go b.accept()
	return b, nil
}

func (b *bridge) accept() {
	defer close(b.acceptDone)
	for {
		conn, err := b.listener.Accept()
		if err != nil {
			b.mu.Lock()
			if !b.stopping {
				b.faults = append(b.faults, "ACCEPT_FAILED")
			}
			b.mu.Unlock()
			return
		}
		b.mu.Lock()
		if b.stopping || b.accepted >= 128 || len(b.active) >= 32 {
			b.faults = append(b.faults, "CONNECTION_ADMISSION_REFUSED")
			b.mu.Unlock()
			go conn.Close()
			return
		}
		b.accepted++
		id := b.accepted
		ctx, cancel := context.WithTimeout(b.ctx, b.connectionLimit)
		r := &relay{conn: conn, cancel: cancel}
		b.active[id] = r
		b.mu.Unlock()
		go func() {
			record := runRelay(ctx, id, r.conn, b.factory(b.distribution))
			cancel()
			b.mu.Lock()
			b.records = append(b.records, record)
			delete(b.active, id)
			b.mu.Unlock()
		}()
	}
}

type safeFile struct {
	file *os.File
	once sync.Once
	err  error
}

func (f *safeFile) close() error {
	if f == nil || f.file == nil {
		return nil
	}
	f.once.Do(func() { f.err = f.file.Close() })
	return f.err
}

type outcome struct {
	kind            string
	n               int64
	err             error
	afterOwnedClose bool
}
type discardCounter struct {
	n        atomic.Int64
	overflow atomic.Bool
}

func (w *discardCounter) Write(p []byte) (int, error) {
	n := w.n.Add(int64(len(p)))
	if n > 16384 {
		w.overflow.Store(true)
	}
	return len(p), nil
}

func expectedClosingError(err error, closing bool) bool {
	return err == nil || (closing && (errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_OPERATION_ABORTED)))
}

func relayContextState(ctx context.Context) (bool, bool) {
	err := ctx.Err()
	deadline, hasDeadline := ctx.Deadline()
	expired := hasDeadline && !time.Now().Before(deadline)
	return err == nil && !expired, expired || errors.Is(err, context.DeadlineExceeded)
}

func runRelay(ctx context.Context, id int, conn net.Conn, cmd *exec.Cmd) relayRecord {
	rec := relayRecord{ID: id, ExitCode: -1, Faults: []string{}}
	live, expired := relayContextState(ctx)
	if !live {
		rec.Cancelled = true
		rec.TimedOut = expired
		rec.Faults = append(rec.Faults, "CONTEXT_NOT_LIVE_BEFORE_SETUP")
		go conn.Close()
		return rec
	}
	var endpoints []*safeFile
	makePipe := func() (*safeFile, *safeFile, error) {
		r, w, err := os.Pipe()
		if err != nil {
			return nil, nil, err
		}
		rr, ww := &safeFile{file: r}, &safeFile{file: w}
		endpoints = append(endpoints, rr, ww)
		return rr, ww, nil
	}
	inR, inW, err := makePipe()
	if err != nil {
		rec.Faults = append(rec.Faults, "STDIN_PIPE_FAILED")
	}
	var outR, outW, errR, errW *safeFile
	if err == nil {
		outR, outW, err = makePipe()
	}
	if err == nil {
		errR, errW, err = makePipe()
	}
	if err != nil || cmd == nil {
		for _, f := range endpoints {
			_ = f.close()
		}
		_ = conn.Close()
		rec.Faults = append(rec.Faults, "PIPE_SETUP_FAILED")
		return rec
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inR.file, outW.file, errW.file
	live, expired = relayContextState(ctx)
	if !live {
		rec.Cancelled = true
		rec.TimedOut = expired
		rec.Faults = append(rec.Faults, "CONTEXT_NOT_LIVE_BEFORE_START")
		for _, f := range endpoints {
			go f.close()
		}
		go conn.Close()
		return rec
	}
	rec.ContextValidAtStart = true
	if err = cmd.Start(); err != nil {
		for _, f := range endpoints {
			_ = f.close()
		}
		_ = conn.Close()
		rec.Faults = append(rec.Faults, "ROOT_START_FAILED")
		return rec
	}
	rec.RootStarted = true
	rec.PID = cmd.Process.Pid
	rec.StartedBeforeUTC = time.Now().UTC().Format(time.RFC3339Nano)
	// These copies belong only to the child after Start. Keeping a parent writer
	// open would prevent the reader from ever observing EOF.
	for _, f := range []*safeFile{inR, outW, errW} {
		if f.close() != nil {
			rec.Faults = append(rec.Faults, "CHILD_SIDE_CLOSE_FAILED")
		}
	}
	results := make(chan outcome, 4)
	var closing atomic.Bool
	go func() {
		n, e := io.CopyBuffer(inW.file, conn, make([]byte, 32768))
		wasClosing := closing.Load()
		_ = inW.close()
		results <- outcome{"input", n, e, wasClosing}
	}()
	go func() {
		n, e := io.CopyBuffer(conn, outR.file, make([]byte, 32768))
		wasClosing := closing.Load()
		closing.Store(true)
		ce := conn.Close()
		if e == nil {
			e = ce
		}
		results <- outcome{"output", n, e, wasClosing}
	}()
	stderr := &discardCounter{}
	go func() {
		n, e := io.CopyBuffer(stderr, errR.file, make([]byte, 1024))
		results <- outcome{"stderr", n, e, closing.Load()}
	}()
	go func() { e := cmd.Wait(); results <- outcome{"root", 0, e, false} }()
	count := 0
	var cancelOnce sync.Once
	closeDone := make(chan bool, 1)
	filesDone := make(chan bool, 1)
	requestClose := func() {
		cancelOnce.Do(func() {
			closing.Store(true)
			sdkDone := make(chan bool, 1)
			parts := make(chan bool, len(endpoints))
			go func() { sdkDone <- conn.Close() == nil }()
			for _, f := range endpoints {
				go func(f *safeFile) { parts <- f.close() == nil }(f)
			}
			go func() {
				good := true
				for range endpoints {
					if !<-parts {
						good = false
					}
				}
				filesDone <- good
				sdkGood := <-sdkDone
				closeDone <- good && sdkGood
			}()
		})
	}
	var grace <-chan time.Time
	var final <-chan time.Time
	ctxDone := ctx.Done()
	for count < 4 {
		select {
		case o := <-results:
			count++
			switch o.kind {
			case "input":
				rec.InputFinished = true
				rec.InputBytes = o.n
				if !expectedClosingError(o.err, o.afterOwnedClose) {
					rec.Faults = append(rec.Faults, "STDIN_COPY_FAILED")
				}
			case "output":
				rec.OutputFinished = true
				rec.OutputBytes = o.n
				if !expectedClosingError(o.err, o.afterOwnedClose) {
					rec.Faults = append(rec.Faults, "STDOUT_COPY_FAILED")
				}
			case "stderr":
				rec.StderrFinished = true
				rec.StderrBytes = o.n
				if !expectedClosingError(o.err, o.afterOwnedClose) {
					rec.Faults = append(rec.Faults, "STDERR_DRAIN_FAILED")
				}
			case "root":
				if cmd.ProcessState != nil {
					rec.RootWaitObserved = true
					rec.ExitCode = cmd.ProcessState.ExitCode()
				}
				if o.err != nil || rec.ExitCode != 0 {
					rec.Faults = append(rec.Faults, "ROOT_EXIT_NONZERO_OR_UNKNOWN")
				}
			}
		case <-ctxDone:
			rec.Cancelled = true
			rec.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
			rec.Faults = append(rec.Faults, "RELAY_CANCELLED_BEFORE_COMPLETION")
			requestClose()
			ctxDone = nil
			grace = time.After(time.Second)
			final = time.After(10 * time.Second)
		case <-grace:
			grace = nil
			if !rec.RootWaitObserved {
				if e := cmd.Process.Kill(); e == nil {
					rec.Forced = true
				} else if !errors.Is(e, os.ErrProcessDone) {
					rec.Faults = append(rec.Faults, "OWN_ROOT_KILL_FAILED")
				}
			}
		case <-final:
			select {
			case rec.FilesClosed = <-filesDone:
			default:
			}
			rec.Faults = append(rec.Faults, "ROOT_OR_PUMP_TERMINAL_UNKNOWN")
			return rec
		}
	}
	requestClose()
	select {
	case ok := <-closeDone:
		rec.SDKCloseCompleted = true
		rec.FilesClosed = ok
	case <-time.After(2 * time.Second):
		rec.Faults = append(rec.Faults, "CLOSE_COMPLETION_UNKNOWN")
	}
	rec.StderrOverflow = stderr.overflow.Load()
	live, expired = relayContextState(ctx)
	rec.ContextValidAtCompletion = live
	if !live {
		rec.Cancelled = true
		rec.TimedOut = rec.TimedOut || expired
		rec.Faults = append(rec.Faults, "CONTEXT_NOT_LIVE_AT_COMPLETION")
	}
	if rec.StderrOverflow {
		rec.Faults = append(rec.Faults, "STDERR_BOUND_EXCEEDED")
	}
	rec.Qualified = rec.ContextValidAtStart && rec.ContextValidAtCompletion && !rec.Cancelled && rec.RootWaitObserved && rec.ExitCode == 0 && rec.InputFinished && rec.OutputFinished && rec.StderrFinished && rec.SDKCloseCompleted && rec.FilesClosed && !rec.Forced && !rec.TimedOut && len(rec.Faults) == 0
	return rec
}

func namespaceAbsent(path string) bool {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if err == nil {
		_ = windows.CloseHandle(h)
		return false
	}
	return errors.Is(err, windows.ERROR_FILE_NOT_FOUND)
}

func (b *bridge) stop(timeout time.Duration) bridgeReport {
	deadline := time.Now().Add(timeout)
	b.mu.Lock()
	b.stopping = true
	b.mu.Unlock()
	listenerClose := make(chan bool, 1)
	go func() { listenerClose <- b.listener.Close() == nil }()
	closed, acceptFinished, cancelled := false, false, false
	grace := 2 * time.Second
	if timeout < 4*time.Second {
		grace = timeout / 4
	}
	gracefulUntil := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		select {
		case closed = <-listenerClose:
			listenerClose = nil
		default:
		}
		select {
		case <-b.acceptDone:
			acceptFinished = true
		default:
		}
		b.mu.Lock()
		active := len(b.active)
		b.mu.Unlock()
		if closed && acceptFinished && active == 0 {
			break
		}
		if !cancelled && time.Now().After(gracefulUntil) {
			b.cancel()
			cancelled = true
		}
		time.Sleep(10 * time.Millisecond)
	}
	b.mu.Lock()
	report := bridgeReport{Schema: 1, Nonce: b.nonce, Endpoint: b.endpoint, OwnerSID: b.owner, SDK: "github.com/Microsoft/go-winio@v0.6.4", Accepted: b.accepted, Completed: len(b.records), Active: len(b.active), ListenerCloseCompleted: closed, AcceptLoopFinished: acceptFinished, Records: append([]relayRecord{}, b.records...), Faults: append([]string{}, b.faults...)}
	b.mu.Unlock()
	absence := make(chan bool, 1)
	go func() { absence <- namespaceAbsent(b.path) }()
	remaining := time.Until(deadline)
	if remaining > 0 {
		select {
		case report.EndpointAbsentObserved = <-absence:
		case <-time.After(remaining):
		}
	}
	report.Qualified = report.Accepted > 0 && report.Active == 0 && report.Completed == report.Accepted && closed && acceptFinished && report.EndpointAbsentObserved && len(report.Faults) == 0
	for _, r := range report.Records {
		if r.RootStarted && !r.RootWaitObserved {
			report.UnknownRoots++
		}
		if r.RootStarted {
			if !r.InputFinished {
				report.UnknownPumps++
			}
			if !r.OutputFinished {
				report.UnknownPumps++
			}
			if !r.StderrFinished {
				report.UnknownPumps++
			}
		}
		if !r.SDKCloseCompleted {
			report.UnknownConnectionCloses++
		}
		if !r.Qualified {
			report.Qualified = false
		}
	}
	return report
}

func minimalWindowsEnvironment() []string {
	keys := []string{"SystemRoot", "WINDIR", "SystemDrive", "PATH", "PATHEXT", "COMSPEC", "TEMP", "TMP", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "APPDATA", "PROGRAMDATA", "ProgramFiles", "ProgramFiles(x86)", "CommonProgramFiles", "CommonProgramFiles(x86)", "OS", "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "USERNAME", "USERDOMAIN"}
	env := []string{}
	for _, k := range keys {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func launchWSL(distribution string) *exec.Cmd {
	wsl := filepath.Join(os.Getenv("SystemRoot"), "System32", "wsl.exe")
	cmd := exec.Command(wsl, "--distribution", distribution, "--exec", "/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "/usr/bin/socat", "STDIO", "UNIX-CONNECT:/var/run/docker.sock")
	cmd.Env = minimalWindowsEnvironment()
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	return cmd
}

func writeExclusive(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) > 131072 {
		return errors.New("REPORT_BOUND_EXCEEDED")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	if serr != nil {
		return serr
	}
	return cerr
}

func runMain() int {
	nonce := flag.String("nonce", "", "")
	distro := flag.String("distribution", "", "")
	ready := flag.String("ready", "", "")
	stop := flag.String("stop", "", "")
	reportPath := flag.String("report", "", "")
	flag.Parse()
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("GITHUB_REPOSITORY") != "RinisRp/hosted-wsl-capability-20261113-1e8014" || os.Getenv("GITHUB_ACTOR") != "RinisRp" || os.Getenv("GITHUB_REF") != "refs/heads/codex/wsl-npipe-6f3465" || os.Getenv("PROBE_NONCE") != *nonce || !noncePattern.MatchString(*nonce) {
		fmt.Fprintln(os.Stderr, "EXACT_GENERIC_HOSTED_BRIDGE_CONTEXT_REQUIRED")
		return 2
	}
	base := filepath.Dir(*ready)
	expectedBase := filepath.Join(os.Getenv("RUNNER_TEMP"), "hosted-wsl-"+*nonce)
	if !filepath.IsAbs(base) || !strings.EqualFold(filepath.Clean(base), filepath.Clean(expectedBase)) || filepath.Dir(*stop) != base || filepath.Dir(*reportPath) != base || filepath.Base(*ready) != "bridge-ready.json" || filepath.Base(*stop) != "bridge-stop.txt" || filepath.Base(*reportPath) != "bridge-report.json" {
		fmt.Fprintln(os.Stderr, "OWN_NONCE_OUTPUT_PATHS_REQUIRED")
		return 2
	}
	b, err := openBridge(*nonce, *distro, launchWSL, 120*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "BRIDGE_OPEN_FAILED")
		return 3
	}
	if writeExclusive(*ready, map[string]any{"Schema": 1, "Nonce": *nonce, "Endpoint": b.endpoint, "OwnerSID": b.owner, "PID": os.Getpid(), "PayloadLogged": false}) != nil {
		_ = b.stop(15 * time.Second)
		fmt.Fprintln(os.Stderr, "READY_PUBLICATION_FAILED")
		return 3
	}
	deadline := time.Now().Add(10 * time.Minute)
	validStop := false
	for time.Now().Before(deadline) {
		f, err := os.Open(*stop)
		if err == nil {
			data, rerr := io.ReadAll(io.LimitReader(f, 33))
			_ = f.Close()
			validStop = rerr == nil && string(data) == *nonce
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	report := b.stop(15 * time.Second)
	if !validStop {
		report.Faults = append(report.Faults, "VALID_OWNED_STOP_NOT_OBSERVED")
		report.Qualified = false
	}
	if writeExclusive(*reportPath, report) != nil {
		fmt.Fprintln(os.Stderr, "REPORT_PUBLICATION_FAILED")
		return 4
	}
	if !report.Qualified {
		fmt.Fprintln(os.Stderr, "BRIDGE_NOT_QUALIFIED")
		return 4
	}
	return 0
}

func main() { os.Exit(runMain()) }
