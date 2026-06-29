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
	credentials *Store
	authToken   string // BRIDGE_AUTH_TOKEN; "" => legacy mode (auth disabled)
	mu          sync.RWMutex
	sessions    map[string]*session
}

func NewServer(baseURL string, creds *Store, authToken string) *Server {
	return &Server{
		baseURL:     baseURL,
		credentials: creds,
		authToken:   authToken,
		sessions:    make(map[string]*session),
	}
}

// ─── SSE endpoint (/sse) ─────────────────────────────────────────────────────
// Dust connects here first. We:
//  1. Extract the bearer token (= user's Unipile API key)
//  2. Mint a session ID
//  3. Send the MCP `endpoint` event pointing to /messages?sessionId=xxx
//  4. Keep the connection alive and stream JSON-RPC responses

func (s *Server) HandleSSE(w http.ResponseWriter, r *http.Request) {
	bearer := extractBearer(r)
	legacy := s.authToken == ""

	// Bridge auth
	if !legacy && bearer != s.authToken {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// Resolve Unipile API key
	userEmail := r.URL.Query().Get("dust_user_email")
	if userEmail == "" {
		userEmail = r.Header.Get("X-Dust-User-Email")
	}
	apiKey, err := s.credentials.Resolve(userEmail, bearer, legacy)
	if err != nil {
		log.Printf("credential lookup failed for %q: %v", userEmail, err)
		http.Error(w, `{"error":"no Unipile credential for user"}`, http.StatusForbidden)
		return
	}

	sessionID := uuid.NewString()
	ch := make(chan mcp.Response, 32)

	accountID := s.credentials.ResolveAccountID(userEmail)

	log.Printf("🔍 GET /sse — email=%q accountID=%q url=%q",
		userEmail, accountID, r.URL.String())

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

	log.Printf("session %s connected (key: %.8s… email=%q accountID=%q)", sessionID, apiKey, userEmail, accountID)

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
	log.Printf("🔍 /messages headers — %v", r.Header)
	log.Printf("🔍 /messages url — %s", r.URL.String())

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

	// Re-resolve per-user credentials from the POST /messages request — Dust
	// sends user context here (header/query), not on the GET /sse handshake.
	postEmail := r.Header.Get("X-Dust-User-Email")
	if postEmail == "" {
		postEmail = r.URL.Query().Get("dust_user_email")
	}
	log.Printf("🔍 /messages — sessionID=%s method=%q postEmail=%q", sessionID, req.Method, postEmail)
	if postEmail != "" {
		bearer := extractBearer(r)
		legacy := s.authToken == ""
		if apiKey, err := s.credentials.Resolve(postEmail, bearer, legacy); err == nil {
			accountID := s.credentials.ResolveAccountID(postEmail)
			sess.mu.Lock()
			sess.client = unipile.NewClient(s.baseURL, apiKey, accountID)
			sess.mu.Unlock()
			log.Printf("🔑 /messages session %s — email=%q accountID=%q", sessionID, postEmail, accountID)
		}
	}

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
	bearer := extractBearer(r)
	legacy := s.authToken == ""

	if !legacy && bearer != s.authToken {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	userEmail := r.URL.Query().Get("dust_user_email")
	if userEmail == "" {
		userEmail = r.Header.Get("X-Dust-User-Email")
	}

	apiKey, err := s.credentials.Resolve(userEmail, bearer, legacy)
	if err != nil {
		http.Error(w, `{"error":"no Unipile credential"}`, http.StatusForbidden)
		return
	}

	accountID := s.credentials.ResolveAccountID(userEmail)

	var req mcp.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	log.Printf("🔍 POST /sse — method=%q email=%q accountID=%q url=%q headers=%v",
		req.Method,
		userEmail,
		accountID,
		r.URL.String(),
		r.Header,
	)

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
	auth := r.Header.Get("Authorization")
	if auth == "" {
		// Also allow ?api_key=... for easier testing in browser
		return r.URL.Query().Get("api_key")
	}
	return strings.TrimPrefix(auth, "Bearer ")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
