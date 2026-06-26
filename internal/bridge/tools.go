package bridge

import (
	"encoding/json"
	"fmt"

	"github.com/idoption/unipile-bridge/internal/mcp"
	"github.com/idoption/unipile-bridge/internal/unipile"
)

// toolCatalog returns all MCP tool definitions exposed by the bridge.
func toolCatalog() []mcp.Tool {
	return []mcp.Tool{
		// ── Accounts ──────────────────────────────────────────────────────
		{
			Name:        "list_accounts",
			Description: "List all accounts connected in Unipile (LinkedIn, email, etc.)",
			InputSchema: mcp.InputSchema{Type: "object"},
		},

		// ── LinkedIn ──────────────────────────────────────────────────────
		{
			Name:        "search_linkedin_people",
			Description: "Search LinkedIn for people by name or keywords",
			InputSchema: mcp.InputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"query": {Type: "string", Description: "Name or keywords to search for"},
				},
				Required: []string{"query"},
			},
		},
		{
			Name:        "get_linkedin_profile",
			Description: "Get a LinkedIn user profile by their Unipile provider_id (from search results)",
			InputSchema: mcp.InputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"account_id":  {Type: "string", Description: "Your Unipile LinkedIn account ID"},
					"provider_id": {Type: "string", Description: "The LinkedIn user's provider_id from search results"},
				},
				Required: []string{"account_id", "provider_id"},
			},
		},
		{
			Name:        "list_linkedin_connections",
			Description: "List all your LinkedIn 1st-degree connections",
			InputSchema: mcp.InputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"account_id": {Type: "string", Description: "Your Unipile LinkedIn account ID"},
				},
				Required: []string{"account_id"},
			},
		},
		{
			Name:        "send_linkedin_invitation",
			Description: "Send a LinkedIn connection request, optionally with a note",
			InputSchema: mcp.InputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"account_id":  {Type: "string", Description: "Your Unipile LinkedIn account ID"},
					"provider_id": {Type: "string", Description: "LinkedIn provider_id of the person to invite"},
					"message":     {Type: "string", Description: "Optional note to include with the invitation"},
				},
				Required: []string{"account_id", "provider_id"},
			},
		},

		// ── Messaging ─────────────────────────────────────────────────────
		{
			Name:        "list_chats",
			Description: "List all messaging conversations (LinkedIn DMs, email threads, etc.)",
			InputSchema: mcp.InputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"account_id": {Type: "string", Description: "Optional: filter by a specific account ID"},
				},
			},
		},
		{
			Name:        "get_chat_messages",
			Description: "Read all messages in a specific chat/conversation",
			InputSchema: mcp.InputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"chat_id": {Type: "string", Description: "The chat ID to read messages from"},
				},
				Required: []string{"chat_id"},
			},
		},
		{
			Name:        "send_new_message",
			Description: "Start a new conversation and send a first message to a person (LinkedIn DM or other channel)",
			InputSchema: mcp.InputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"account_id":   {Type: "string", Description: "Your Unipile account ID to send from"},
					"attendee_id":  {Type: "string", Description: "Provider ID of the recipient (from search results)"},
					"text":         {Type: "string", Description: "The message to send"},
				},
				Required: []string{"account_id", "attendee_id", "text"},
			},
		},
		{
			Name:        "reply_to_chat",
			Description: "Reply to an existing conversation",
			InputSchema: mcp.InputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"chat_id": {Type: "string", Description: "The chat ID to reply to"},
					"text":    {Type: "string", Description: "Your reply message"},
				},
				Required: []string{"chat_id", "text"},
			},
		},

		// ── Email ─────────────────────────────────────────────────────────
		{
			Name:        "list_emails",
			Description: "List emails from an account, optionally filtering by folder",
			InputSchema: mcp.InputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"account_id": {Type: "string", Description: "Your Unipile email account ID"},
					"folder":     {Type: "string", Description: "Folder name (e.g. INBOX, SENT)"},
					"limit":      {Type: "number", Description: "Max emails to return (default 20)"},
				},
			},
		},
		{
			Name:        "send_email",
			Description: "Send an email from one of your connected email accounts",
			InputSchema: mcp.InputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"account_id": {Type: "string", Description: "Your Unipile email account ID"},
					"to":         {Type: "string", Description: "Recipient email address"},
					"subject":    {Type: "string", Description: "Email subject"},
					"body":       {Type: "string", Description: "Email body (plain text or HTML)"},
				},
				Required: []string{"account_id", "to", "subject", "body"},
			},
		},
	}
}

// dispatch routes a tools/call to the right Unipile method.
func dispatch(client *unipile.Client, params mcp.CallToolParams) mcp.CallToolResult {
	args := params.Arguments

	str := func(key string) string {
		if v, ok := args[key].(string); ok {
			return v
		}
		return ""
	}
	intVal := func(key string) int {
		switch v := args[key].(type) {
		case float64:
			return int(v)
		case int:
			return v
		}
		return 0
	}

	var (
		raw json.RawMessage
		err error
	)

	switch params.Name {
	// Accounts
	case "list_accounts":
		raw, err = client.ListAccounts()

	// LinkedIn
	case "search_linkedin_people":
		raw, err = client.SearchLinkedIn(str("query"))
	case "get_linkedin_profile":
		raw, err = client.GetUserProfile(str("account_id"), str("provider_id"))
	case "list_linkedin_connections":
		raw, err = client.ListConnections(str("account_id"))
	case "send_linkedin_invitation":
		raw, err = client.SendInvitation(str("account_id"), str("provider_id"), str("message"))

	// Messaging
	case "list_chats":
		raw, err = client.ListChats(str("account_id"))
	case "get_chat_messages":
		raw, err = client.GetChatMessages(str("chat_id"))
	case "send_new_message":
		raw, err = client.StartChatAndSend(str("account_id"), str("attendee_id"), str("text"))
	case "reply_to_chat":
		raw, err = client.SendMessageToChat(str("chat_id"), str("text"))

	// Email
	case "list_emails":
		raw, err = client.ListEmails(str("account_id"), str("folder"), intVal("limit"))
	case "send_email":
		raw, err = client.SendEmail(str("account_id"), str("to"), str("subject"), str("body"))

	default:
		return mcp.ErrorResult(fmt.Sprintf("unknown tool: %s", params.Name))
	}

	if err != nil {
		return mcp.ErrorResult(err.Error())
	}

	// Pretty-print the JSON for the LLM
	var pretty []byte
	pretty, err = json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return mcp.TextResult(string(raw))
	}
	return mcp.TextResult(string(pretty))
}
