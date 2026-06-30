// Package bridge implements the MCP-over-SSE server that proxies Unipile.
// Each SSE connection gets its own Unipile client bound to the bearer token
// extracted from the Authorization header — this is the per-user routing trick.
package bridge

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/idoption/unipileBridge/internal/mcp"
	"github.com/idoption/unipileBridge/internal/oauth"
	"github.com/idoption/unipileBridge/internal/unipile"
)

// session holds the SSE channel for one connected client.
type session struct {
	ch     chan mcp.Response
	client *unipile.Client
	mu     sync.Mutex // guards client (re-resolved per /messages POST)
}

// Server is the MCP bridge server.
type Server struct {
	baseURL     string
	publicURL   string
	credentials *Store
	tokens      *oauth.Issuer
	mu          sync.RWMutex
	sessions    map[string]*session
}

func NewServer(baseURL, publicURL string, creds *Store, tokens *oauth.Issuer) *Server {
	return &Server{
		baseURL:     baseURL,
		publicURL:   publicURL,
		credentials: creds,
		tokens:      tokens,
		sessions:    make(map[string]*session),
	}
}

// resolveCaller verifies the bridge-issued JWT access token and resolves the
// caller's Unipile credentials. status==0 on success; otherwise the HTTP status
// + JSON body to send.
func (s *Server) resolveCaller(r *http.Request) (apiKey, accountID, userEmail string, status int, errBody string) {
	email, err := s.tokens.VerifyAccess(extractBearer(r))
	if err != nil {
		return "", "", "", http.StatusUnauthorized, `{"error":"unauthorized"}`
	}
	userEmail = email
	accountID = s.credentials.ResolveAccountID(userEmail)
	if accountID == "" {
		// Verified user with no ACCOUNT_MAP entry — hard fail so isolation is never off.
		return "", "", userEmail, http.StatusForbidden, `{"error":"no account mapped for user"}`
	}
	key, err := s.credentials.Resolve(userEmail)
	if err != nil {
		return "", "", userEmail, http.StatusForbidden, `{"error":"no Unipile credential for user"}`
	}
	return key, accountID, userEmail, 0, ""
}

// writeAuthError sends an error; on 401 it advertises the protected-resource
// metadata so an MCP client knows where to start the OAuth flow.
func (s *Server) writeAuthError(w http.ResponseWriter, status int, body string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate",
			`Bearer resource_metadata="`+s.publicURL+`/.well-known/oauth-protected-resource"`)
	}
	http.Error(w, body, status)
}

// HandleProtectedResourceMetadata serves RFC 9728 PRM pointing at this bridge as
// its own authorization server.
func (s *Server) HandleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"resource":              s.publicURL + "/sse",
		"authorization_servers": []string{s.publicURL},
		"scopes_supported":      []string{"mcp"},
	})
}

// ─── SSE endpoint (/sse) ─────────────────────────────────────────────────────
// Dust connects here first. We authenticate, mint a session bound to the
// caller's Unipile client, advertise the /messages endpoint, and stream
// JSON-RPC responses until the client disconnects.

func (s *Server) HandleSSE(w http.ResponseWriter, r *http.Request) {
	apiKey, accountID, userEmail, status, errBody := s.resolveCaller(r)
	if status != 0 {
		s.writeAuthError(w, status, errBody)
		return
	}

	sessionID := uuid.NewString()
	ch := make(chan mcp.Response, 32)

	s.mu.Lock()
	s.sessions[sessionID] = &session{
		ch:     ch,
		client: unipile.NewClient(s.baseURL, apiKey, accountID),
	}
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.sessions, sessionID)
		s.mu.Unlock()
		log.Printf("session %s closed", sessionID)
	}()

	// SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	// Disable Railway/nginx proxy buffering so SSE events flush immediately
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// Tell the MCP client where to POST requests
	messagesURL := fmt.Sprintf("/messages?sessionId=%s", sessionID)
	fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", messagesURL)
	flusher.Flush()

	// Stream responses until client disconnects
	for {
		select {
		case <-r.Context().Done():
			return
		case resp := <-ch:
			b, err := json.Marshal(resp)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", string(b))
			flusher.Flush()
		}
	}
}

// ─── Messages endpoint (/messages) ───────────────────────────────────────────
// Dust POSTs JSON-RPC requests here. We route them and send responses via SSE.

func (s *Server) HandleMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("sessionId")
	s.mu.RLock()
	sess, ok := s.sessions[sessionID]
	s.mu.RUnlock()
	if !ok {
		http.Error(w, "unknown session", http.StatusNotFound)
		return
	}

	var req mcp.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Re-resolve per-user credentials from this request's bearer token and swap
	// the session's Unipile client before dispatch — Dust identifies the user via
	// the per-request bearer token, not the /sse handshake.
	apiKey, accountID, _, status, errBody := s.resolveCaller(r)
	if status != 0 {
		s.writeAuthError(w, status, errBody)
		return
	}
	sess.mu.Lock()
	sess.client = unipile.NewClient(s.baseURL, apiKey, accountID)
	sess.mu.Unlock()

	w.WriteHeader(http.StatusAccepted)

	// Handle the request asynchronously and push response into SSE channel
	go func() {
		resp := s.handleRequest(sess, req)
		sess.ch <- resp
	}()
}

// ─── Streamable HTTP endpoint (POST /sse) ────────────────────────────────────
// Newer MCP clients (Dust's "Streamable HTTP" transport) POST a JSON-RPC
// request directly to /sse and read the single response back inline — either as
// a one-shot SSE event or as plain JSON, depending on the Accept header.

func (s *Server) HandleStreamableHTTP(w http.ResponseWriter, r *http.Request) {
	apiKey, accountID, _, status, errBody := s.resolveCaller(r)
	if status != 0 {
		s.writeAuthError(w, status, errBody)
		return
	}

	var req mcp.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Notifications have no ID — return 202, no body (per MCP spec)
	if req.ID == nil {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusAccepted)
		return
	}

	sess := &session{
		ch:     make(chan mcp.Response, 1),
		client: unipile.NewClient(s.baseURL, apiKey, accountID),
	}

	resp := s.handleRequest(sess, req)

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// ─── JSON-RPC router ─────────────────────────────────────────────────────────

func (s *Server) handleRequest(sess *session, req mcp.Request) mcp.Response {
	switch req.Method {
	case "initialize":
		return mcp.OK(req.ID, mcp.InitializeResult{
			ProtocolVersion: "2024-11-05",
			Capabilities: mcp.Capabilities{
				Tools: &mcp.ToolsCapability{ListChanged: false},
			},
			ServerInfo: mcp.ServerInfo{Name: "unipile-bridge", Version: "1.0.0"},
		})

	case "notifications/initialized":
		// No-op notification from client
		return mcp.Response{}

	case "ping":
		return mcp.OK(req.ID, map[string]any{})

	case "tools/list":
		return mcp.OK(req.ID, mcp.ToolsListResult{Tools: toolCatalog()})

	case "tools/call":
		var params mcp.CallToolParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return mcp.Err(req.ID, -32602, "invalid params: "+err.Error())
		}
		result := dispatch(sess.client, params)
		return mcp.OK(req.ID, result)

	default:
		return mcp.Err(req.ID, -32601, fmt.Sprintf("method not found: %s", req.Method))
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func extractBearer(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
