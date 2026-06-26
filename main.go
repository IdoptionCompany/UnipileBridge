package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/idoption/unipile-bridge/internal/bridge"
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

	mux := http.NewServeMux()
	srv := bridge.NewServer(baseURL)

	// MCP over SSE — one endpoint for connection, one for messages
	mux.HandleFunc("/sse", srv.HandleSSE)
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
