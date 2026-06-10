// http_test_server is a hermetic HTTP test server used by the e2e test suite.
//
// It supports every feature exercised by e2e/ tests in this repository:
//   - HTTP verbs: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD
//   - JSON, urlencoded, and multipart/form-data request bodies
//   - File download with HTTP Range requests
//   - Server-Sent Events (text/event-stream)
//   - Large streaming responses (>5MB) to exercise the streaming path
//   - Status code echoes, redirects, and configurable delays for abort/timeout
//
// On startup the server binds to 127.0.0.1:0 (OS-assigned port) and prints
// "PORT=<n>" to stdout so the launcher can export E2E_BASE_URL.
//
// Implementation is stdlib only: no third-party Go modules.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	mux := http.NewServeMux()

	// HTTP verb coverage
	mux.HandleFunc("/get", handleGet)
	mux.HandleFunc("/post", handlePost)
	mux.HandleFunc("/put", handlePut)
	mux.HandleFunc("/patch", handlePatch)
	mux.HandleFunc("/delete", handleDelete)
	mux.HandleFunc("/options", handleOptions)
	mux.HandleFunc("/head", handleHead)

	// Content-type coverage
	mux.HandleFunc("/json", handleJSON)
	mux.HandleFunc("/urlencoded", handleURLEncoded)
	mux.HandleFunc("/multipart", handleMultipart)

	// Download & range
	mux.HandleFunc("/download/", handleDownload)
	mux.HandleFunc("/range", handleRange)

	// Streaming
	mux.HandleFunc("/sse", handleSSE)
	mux.HandleFunc("/stream-large", handleStreamLarge)

	// Status / redirect / delay
	mux.HandleFunc("/status/", handleStatus)
	mux.HandleFunc("/redirect/", handleRedirect)
	mux.HandleFunc("/delay/", handleDelay)

	// Health check
	mux.HandleFunc("/", handleIndex)

	addr := "127.0.0.1:0"
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	// Print the bound port on its own line so the launcher can grep it.
	fmt.Printf("PORT=%d\n", port)
	os.Stdout.Sync()

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Fatalf("serve: %v", err)
	}
}

// index: liveness probe + list of routes.
func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"server": "http_test_server",
		"routes": []string{
			"/get", "/post", "/put", "/patch", "/delete", "/options", "/head",
			"/json", "/urlencoded", "/multipart",
			"/download/{bytes}", "/range",
			"/sse", "/stream-large",
			"/status/{code}", "/redirect/{n}", "/delay/{ms}",
		},
	})
}

// --- HTTP verbs -----------------------------------------------------------

func handleGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	echoRequest(w, r, "")
}

func handlePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(r.Body)
	echoRequest(w, r, string(body))
}

func handlePut(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(r.Body)
	echoRequest(w, r, string(body))
}

func handlePatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(r.Body)
	echoRequest(w, r, string(body))
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func handleOptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD")
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusNoContent)
}

func handleHead(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Test-Head", "true")
	w.WriteHeader(http.StatusOK)
	// HEAD must not include a body.
}

// --- Content type coverage ------------------------------------------------

func handleJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":      true,
		"n":       42,
		"message": "hello from test server",
	})
}

func handleURLEncoded(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
		return
	}
	form := map[string][]string{}
	for k, v := range r.PostForm {
		form[k] = v
	}
	// r.Form also contains query string params — include both.
	out := map[string]any{
		"form":  form,
		"query": r.URL.Query(),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func handleMultipart(w http.ResponseWriter, r *http.Request) {
	// 32 MB in memory, the rest spills to disk. 1 MB is plenty for tests.
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		http.Error(w, "bad multipart: "+err.Error(), http.StatusBadRequest)
		return
	}
	fields := map[string][]string{}
	for k, v := range r.MultipartForm.Value {
		fields[k] = v
	}
	files := map[string]any{}
	for fieldName, fhs := range r.MultipartForm.File {
		out := []map[string]any{}
		for _, fh := range fhs {
			f, err := fh.Open()
			if err != nil {
				http.Error(w, "file open: "+err.Error(), http.StatusBadRequest)
				return
			}
			data, _ := io.ReadAll(f)
			_ = f.Close()
			out = append(out, map[string]any{
				"filename":     fh.Filename,
				"content_type": fh.Header.Get("Content-Type"),
				"size":         len(data),
				"data_b64":     base64.StdEncoding.EncodeToString(data),
			})
		}
		files[fieldName] = out
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"fields": fields,
		"files":  files,
	})
}

// --- Download & range -----------------------------------------------------

func handleDownload(w http.ResponseWriter, r *http.Request) {
	nStr := strings.TrimPrefix(r.URL.Path, "/download/")
	n, err := strconv.Atoi(nStr)
	if err != nil || n < 0 {
		http.Error(w, "bad size", http.StatusBadRequest)
		return
	}
	// Cap to 10 MB so a buggy client can't OOM the test runner.
	if n > 10<<20 {
		http.Error(w, "too large", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(n))
	buf := make([]byte, 8192)
	written := 0
	for written < n {
		b := buf
		if remaining := n - written; remaining < len(b) {
			b = buf[:remaining]
		}
		if _, err := rand.Read(b); err != nil {
			return
		}
		if _, err := w.Write(b); err != nil {
			return
		}
		written += len(b)
	}
}

// /range returns 1000 bytes total. Range requests slice into it.
const rangeTotal = 1000

func handleRange(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Type", "application/octet-stream")

	rangeHdr := r.Header.Get("Range")
	if rangeHdr == "" {
		w.Header().Set("Content-Length", strconv.Itoa(rangeTotal))
		// Serve the full body when no Range is given.
		buf := make([]byte, rangeTotal)
		_, _ = rand.Read(buf)
		_, _ = w.Write(buf)
		return
	}

	start, end, ok := parseRange(rangeHdr, rangeTotal)
	if !ok {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", rangeTotal))
		http.Error(w, "range not satisfiable", http.StatusRequestedRangeNotSatisfiable)
		return
	}
	length := end - start + 1
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, rangeTotal))
	w.Header().Set("Content-Length", strconv.Itoa(length))
	w.WriteHeader(http.StatusPartialContent)

	// Stream only the requested slice. Use crypto/rand to fill it (deterministic-enough for tests).
	remaining := length
	offset := start
	buf := make([]byte, 8192)
	for remaining > 0 {
		b := buf
		if remaining < len(b) {
			b = buf[:remaining]
		}
		// Seed the slice with deterministic-ish data so we can verify content.
		for i := range b {
			b[i] = byte((offset + i) % 256)
		}
		if _, err := w.Write(b); err != nil {
			return
		}
		offset += len(b)
		remaining -= len(b)
	}
}

// parseRange handles "bytes=START-END", "bytes=START-", and "bytes=-SUFFIX".
// Returns inclusive end and ok.
func parseRange(h string, total int) (start, end int, ok bool) {
	const prefix = "bytes="
	if !strings.HasPrefix(h, prefix) {
		return 0, 0, false
	}
	spec := strings.TrimPrefix(h, prefix)
	parts := strings.SplitN(spec, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	if parts[0] == "" {
		// Suffix form: "-N" means last N bytes.
		n, err := strconv.Atoi(parts[1])
		if err != nil || n <= 0 || n > total {
			return 0, 0, false
		}
		return total - n, total - 1, true
	}
	s, err := strconv.Atoi(parts[0])
	if err != nil || s < 0 || s >= total {
		return 0, 0, false
	}
	if parts[1] == "" {
		return s, total - 1, true
	}
	e, err := strconv.Atoi(parts[1])
	if err != nil || e < s || e >= total {
		return 0, 0, false
	}
	return s, e, true
}

// --- Streaming ------------------------------------------------------------

func handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	// Emit N events with a small delay so a client can consume them in real time.
	n := 5
	if v := r.URL.Query().Get("n"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 1000 {
			n = parsed
		}
	}
	for i := 0; i < n; i++ {
		fmt.Fprintf(w, "id: %d\n", i+1)
		fmt.Fprintf(w, "event: tick\n")
		fmt.Fprintf(w, "data: {\"n\":%d}\n", i+1)
		fmt.Fprintf(w, "data: line-two\n")
		fmt.Fprintf(w, "\n")
		flusher.Flush()
		// 50ms between events so the client observes multiple chunks.
		time.Sleep(50 * time.Millisecond)
	}
}

// /stream-large returns 6 MB of random bytes — enough to cross the 5 MB
// streaming threshold in HTTP.fetch.
func handleStreamLarge(w http.ResponseWriter, r *http.Request) {
	const n = 6 << 20 // 6 MiB
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(n))
	w.WriteHeader(http.StatusOK)
	// Use math/rand for speed; seeding once at startup is enough.
	buf := make([]byte, 64<<10)
	written := 0
	for written < n {
		b := buf
		if remaining := n - written; remaining < len(b) {
			b = buf[:remaining]
		}
		mrand.Read(b)
		if _, err := w.Write(b); err != nil {
			return
		}
		written += len(b)
	}
}

// --- Status / redirect / delay --------------------------------------------

func handleStatus(w http.ResponseWriter, r *http.Request) {
	codeStr := strings.TrimPrefix(r.URL.Path, "/status/")
	code, err := strconv.Atoi(codeStr)
	if err != nil || code < 100 || code > 599 {
		http.Error(w, "bad status", http.StatusBadRequest)
		return
	}
	http.Error(w, http.StatusText(code), code)
}

func handleRedirect(w http.ResponseWriter, r *http.Request) {
	nStr := strings.TrimPrefix(r.URL.Path, "/redirect/")
	n, err := strconv.Atoi(nStr)
	if err != nil || n < 0 {
		http.Error(w, "bad count", http.StatusBadRequest)
		return
	}
	if n == 0 {
		// Final destination.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "redirects": 0})
		return
	}
	// Hop one step toward /redirect/0.
	http.Redirect(w, r, fmt.Sprintf("/redirect/%d", n-1), http.StatusFound)
}

func handleDelay(w http.ResponseWriter, r *http.Request) {
	msStr := strings.TrimPrefix(r.URL.Path, "/delay/")
	ms, err := strconv.Atoi(msStr)
	if err != nil || ms < 0 || ms > 30_000 {
		http.Error(w, "bad delay", http.StatusBadRequest)
		return
	}
	time.Sleep(time.Duration(ms) * time.Millisecond)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"slept_ms": ms})
}

// --- helpers --------------------------------------------------------------

// echoRequest serializes the request (method, url, query, headers, body) as JSON.
func echoRequest(w http.ResponseWriter, r *http.Request, body string) {
	hdrs := map[string]string{}
	for k, v := range r.Header {
		if len(v) > 0 {
			hdrs[k] = v[0]
		}
	}
	out := map[string]any{
		"method":  r.Method,
		"url":     r.URL.String(),
		"path":    r.URL.Path,
		"query":   r.URL.Query(),
		"headers": hdrs,
	}
	if body != "" {
		out["body"] = body
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// --- end of file ---
