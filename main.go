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

	baseURL := os.Getenv("UNIPILE_BASE_URL")
	if baseURL == "" {
		log.Fatal("UNIPILE_BASE_URL env var is required (e.g. https://api6.unipile.com:13614)")
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
