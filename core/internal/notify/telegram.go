// Package notify implements VANGUARD's outbound real-time alerting.
// v3.0 ships a single channel -- Telegram -- deliberately kept to a thin,
// dependency-free wrapper around the Bot API's HTTPS `sendMessage` call
// (stdlib net/http only, no Telegram SDK), consistent with the project's
// zero-dependency / single-binary philosophy.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// telegramAPIBase is the Bot API endpoint template. Overridable in tests
// via TelegramNotifier.apiBase so unit tests never hit the real Telegram
// network.
const telegramAPIBase = "https://api.telegram.org/bot%s/sendMessage"

// TelegramNotifier pushes short, human-readable alert messages to a single
// Telegram chat via the Bot API. It is intentionally fire-and-forget from
// the caller's perspective: Notify() logs failures but never returns an
// error to callers, because a Telegram outage must never be allowed to
// block or fail the Autopilot ban path it is attached to.
type TelegramNotifier struct {
	botToken string
	chatID   string
	client   *http.Client
	// apiBase lets tests point the notifier at an httptest.Server instead
	// of the real Telegram API. Defaults to telegramAPIBase.
	apiBase string
}

// NewTelegramNotifier constructs a notifier bound to a bot token and chat
// ID. Returns nil if either is empty -- callers should treat a nil
// *TelegramNotifier as "notifications disabled" (all its methods are safe
// to call on a nil receiver and simply no-op).
func NewTelegramNotifier(botToken, chatID string) *TelegramNotifier {
	if botToken == "" || chatID == "" {
		return nil
	}
	return &TelegramNotifier{
		botToken: botToken,
		chatID:   chatID,
		client:   &http.Client{Timeout: 10 * time.Second},
		apiBase:  telegramAPIBase,
	}
}

// Enabled reports whether this notifier will actually attempt delivery.
// Safe to call on a nil receiver.
func (t *TelegramNotifier) Enabled() bool {
	return t != nil && t.botToken != "" && t.chatID != ""
}

type sendMessageRequest struct {
	ChatID    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode"`
}

// Notify sends text to the configured Telegram chat. Safe to call on a nil
// receiver (no-op). Never blocks the caller for more than the configured
// HTTP timeout, and never panics or propagates an error -- failures are
// logged only, per the "alerting must never break Autopilot" design goal.
func (t *TelegramNotifier) Notify(ctx context.Context, text string) {
	if !t.Enabled() {
		return
	}

	body, err := json.Marshal(sendMessageRequest{
		ChatID:    t.chatID,
		Text:      text,
		ParseMode: "Markdown",
	})
	if err != nil {
		log.Printf("[notify] telegram: failed to marshal payload: %v", err)
		return
	}

	url := fmt.Sprintf(t.apiBase, t.botToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Printf("[notify] telegram: failed to build request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		log.Printf("[notify] telegram: request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		log.Printf("[notify] telegram: API returned status %d: %s", resp.StatusCode, string(respBody))
		return
	}
	log.Printf("[notify] telegram: alert delivered")
}

// NotifyBan sends a formatted "Autopilot banned an IP" summary. Kept as a
// distinct helper (rather than making every call site build the string)
// so the message format is defined in exactly one place.
func (t *TelegramNotifier) NotifyBan(ctx context.Context, ip, incidentType, severity string, riskScore int, duration time.Duration, reason string) {
	if !t.Enabled() {
		return
	}
	text := fmt.Sprintf(
		"🚨 *VANGUARD Autopilot: IP Banned*\n\n"+
			"*IP:* `%s`\n"+
			"*Type:* %s\n"+
			"*Severity:* %s\n"+
			"*Risk Score:* %d/100\n"+
			"*Ban Duration:* %s\n"+
			"*Reason:* %s",
		ip, incidentType, severity, riskScore, duration.String(), reason,
	)
	t.Notify(ctx, text)
}

// NotifyPanicMode sends an alert when Panic Mode (site-wide lockdown) is
// entered or exited, since this is a high-impact, operator-visible event.
func (t *TelegramNotifier) NotifyPanicMode(ctx context.Context, active bool, reason string) {
	if !t.Enabled() {
		return
	}
	icon, state := "🟢", "EXITED"
	if active {
		icon, state = "🔴", "ENTERED"
	}
	text := fmt.Sprintf("%s *VANGUARD Panic Mode %s*\n\n*Reason:* %s", icon, state, reason)
	t.Notify(ctx, text)
}
