package unipile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client is a lightweight Unipile API client bound to one user's API key.
type Client struct {
	baseURL          string
	apiKey           string
	DefaultAccountID string
	httpClient       *http.Client
}

func NewClient(baseURL, apiKey, defaultAccountID string) *Client {
	return &Client{
		baseURL:          baseURL,
		apiKey:           apiKey,
		DefaultAccountID: defaultAccountID,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// do executes an authenticated Unipile API call and returns the parsed JSON body.
func (c *Client) do(method, path string, query url.Values, body any) (json.RawMessage, error) {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, u, reqBody)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-API-KEY", c.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("unipile %d: %s", resp.StatusCode, string(raw))
	}
	return json.RawMessage(raw), nil
}

// ─── Accounts ────────────────────────────────────────────────────────────────

func (c *Client) ListAccounts() (json.RawMessage, error) {
	return c.do("GET", "/api/v1/accounts", nil, nil)
}

// ─── Chats / Messaging ───────────────────────────────────────────────────────

func (c *Client) ListChats(accountID string) (json.RawMessage, error) {
	q := url.Values{}
	if accountID != "" {
		q.Set("account_id", accountID)
	}
	return c.do("GET", "/api/v1/chats", q, nil)
}

func (c *Client) GetChatMessages(chatID string) (json.RawMessage, error) {
	return c.do("GET", "/api/v1/chats/"+chatID+"/messages", nil, nil)
}

func (c *Client) StartChatAndSend(accountID, attendeeID, text string) (json.RawMessage, error) {
	body := map[string]any{
		"account_id":    accountID,
		"attendees_ids": []string{attendeeID},
		"text":          text,
	}
	return c.do("POST", "/api/v1/chats", nil, body)
}

func (c *Client) SendMessageToChat(chatID, text string) (json.RawMessage, error) {
	body := map[string]any{"text": text}
	return c.do("POST", "/api/v1/chats/"+chatID+"/messages", nil, body)
}

// ─── LinkedIn ────────────────────────────────────────────────────────────────

func (c *Client) SearchLinkedIn(accountID, query string) (json.RawMessage, error) {
	q := url.Values{}
	q.Set("account_id", accountID)
	body := map[string]any{
		"api":      "classic",
		"category": "people",
		"keywords": query,
	}
	return c.do("POST", "/api/v1/linkedin/search", q, body)
}

func (c *Client) GetLinkedInProfile(profileURL string) (json.RawMessage, error) {
	q := url.Values{}
	q.Set("linkedin_url", profileURL)
	return c.do("GET", "/api/v1/users/me", q, nil)
}

func (c *Client) GetUserProfile(accountID, identifier string) (json.RawMessage, error) {
	q := url.Values{}
	q.Set("linkedin_sections", "*")
	q.Set("account_id", accountID)
	return c.do("GET", "/api/v1/users/"+identifier, q, nil)
}

func (c *Client) ListConnections(accountID string) (json.RawMessage, error) {
	q := url.Values{}
	q.Set("account_id", accountID)
	body := map[string]any{
		"api":              "classic",
		"category":         "people",
		"network_distance": []int{1},
	}
	return c.do("POST", "/api/v1/linkedin/search", q, body)
}

func (c *Client) SendInvitation(accountID, providerID, message string) (json.RawMessage, error) {
	body := map[string]any{
		"account_id":  accountID,
		"provider_id": providerID,
	}
	if message != "" {
		body["message"] = message
	}
	return c.do("POST", "/api/v1/linkedin/invitations", nil, body)
}

// ─── Email ───────────────────────────────────────────────────────────────────

func (c *Client) ListEmails(accountID, folder string, limit int) (json.RawMessage, error) {
	q := url.Values{}
	if accountID != "" {
		q.Set("account_id", accountID)
	}
	if folder != "" {
		q.Set("folder", folder)
	}
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}
	return c.do("GET", "/api/v1/emails", q, nil)
}

func (c *Client) SendEmail(accountID, to, subject, body string) (json.RawMessage, error) {
	payload := map[string]any{
		"account_id": accountID,
		"to":         []map[string]string{{"identifier": to}},
		"subject":    subject,
		"body":       body,
	}
	return c.do("POST", "/api/v1/emails", nil, payload)
}
