package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/idoption/unipileBridge/internal/bridge"
)

func main() {
	// Load .env in local dev (no-op in Railway)
	_ = godotenv.Load()

	// Base URL comes from the env var; fall back to the documented default so
	// the service boots and passes its healthcheck even if the var is unset.
	// Override UNIPILE_BASE_URL if your Unipile account is on a different DSN.
	const defaultBaseURL = "https://api6.unipile.com:13614"
	baseURL := os.Getenv("UNIPILE_BASE_URL")
	if baseURL == "" {
		baseURL = defaultBaseURL
		log.Printf("⚠️  UNIPILE_BASE_URL not set; using default %s — override it if your account uses a different DSN", baseURL)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	authToken := os.Getenv("BRIDGE_AUTH_TOKEN")
	if authToken == "" {
		log.Println("⚠️  WARNING: BRIDGE_AUTH_TOKEN not set — auth DISABLED (legacy mode)")
	}

	userMap := os.Getenv("USER_MAP")
	sharedKey := os.Getenv("UNIPILE_SHARED_KEY")
	creds := bridge.NewStore(userMap, sharedKey)

	mux := http.NewServeMux()
	srv := bridge.NewServer(baseURL, creds, authToken)

	// MCP /sse: GET = legacy SSE transport, POST = Streamable HTTP transport
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			srv.HandleSSE(w, r)
		case http.MethodPost:
			srv.HandleStreamableHTTP(w, r)
		case http.MethodOptions:
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept")
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	// Legacy SSE transport posts JSON-RPC back here (endpoint advertised by HandleSSE)
	mux.HandleFunc("/messages", srv.HandleMessages)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	log.Printf("🚀 Unipile Bridge MCP listening on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}
