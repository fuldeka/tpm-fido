// Package ctlsocket implements a local control API for tpm-fido, exposed
// over a Unix domain socket for use by companion tools (e.g. a tray app)
// that need to list/delete resident credentials or manage the PIN without
// going through the CTAP2/HID transport. This is local IPC, not part of the
// FIDO2 protocol -- there is no browser-facing exposure.
package ctlsocket

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
)

// Request is a single control-socket call: Method plus opaque, method-
// specific Params. One JSON object per line (newline-delimited).
type Request struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response mirrors Request: either Result is set (on success) or Error is
// (on failure), never both.
type Response struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// Handler processes a single decoded request and returns a JSON-encodable
// result or an error. Implemented by the daemon's *server type.
type Handler func(method string, params json.RawMessage) (interface{}, error)

func DefaultPath() (string, error) {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "tpm-fido.sock"), nil
}

// Listen starts serving control-socket requests on path (or the default
// path if empty), dispatching each to handle. Runs until the listener is
// closed or the process exits; intended to be run in its own goroutine.
// The socket is created with 0600 permissions (owner-only) since it grants
// PIN-gated credential management access.
func Listen(path string, handle Handler) error {
	if path == "" {
		var err error
		path, err = DefaultPath()
		if err != nil {
			return err
		}
	}

	// A stale socket file from a previous unclean shutdown will otherwise
	// make bind fail with "address already in use".
	if _, err := os.Stat(path); err == nil {
		os.Remove(path)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir control socket dir: %w", err)
	}

	l, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("listen on control socket: %w", err)
	}

	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return fmt.Errorf("chmod control socket: %w", err)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			return fmt.Errorf("accept control socket connection: %w", err)
		}
		go serveConn(conn, handle)
	}
}

func serveConn(conn net.Conn, handle Handler) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	enc := json.NewEncoder(conn)

	for scanner.Scan() {
		var req Request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			enc.Encode(Response{Error: fmt.Sprintf("invalid request: %s", err)})
			continue
		}

		result, err := handle(req.Method, req.Params)
		if err != nil {
			enc.Encode(Response{Error: err.Error()})
			continue
		}

		resultJSON, err := json.Marshal(result)
		if err != nil {
			enc.Encode(Response{Error: fmt.Sprintf("encode result: %s", err)})
			continue
		}
		enc.Encode(Response{Result: resultJSON})
	}

	if err := scanner.Err(); err != nil {
		log.Printf("control socket connection read err: %s", err)
	}
}

// Call is a client-side helper: dial path (or the default path if empty),
// send one request, decode and return its response.
func Call(path, method string, params interface{}) (*Response, error) {
	if path == "" {
		var err error
		path, err = DefaultPath()
		if err != nil {
			return nil, err
		}
	}

	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil, fmt.Errorf("dial control socket: %w", err)
	}
	defer conn.Close()

	var paramsJSON json.RawMessage
	if params != nil {
		paramsJSON, err = json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("encode params: %w", err)
		}
	}

	req := Request{Method: method, Params: paramsJSON}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	reqBytes = append(reqBytes, '\n')

	if _, err := conn.Write(reqBytes); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("%s", resp.Error)
	}

	return &resp, nil
}
