package worker

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

// NotificationWorker sends alerts to Telegram/Discord
func NotificationWorker(db *sql.DB) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		processNotificationQueue(db)
	}
}

func processNotificationQueue(db *sql.DB) {
	rows, err := db.Query(`
		SELECT id, channel, webhook_url, message 
		FROM notification_queue 
		WHERE sent = 0 
		ORDER BY created_at ASC 
		LIMIT 10
	`)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var channel, webhookURL, message string
		if err := rows.Scan(&id, &channel, &webhookURL, &message); err != nil {
			continue
		}

		var sendErr error
		switch channel {
		case "telegram":
			sendErr = sendTelegram(webhookURL, message)
		case "discord":
			sendErr = sendDiscord(webhookURL, message)
		default:
			sendErr = sendGenericWebhook(webhookURL, message)
		}

		if sendErr == nil {
			db.Exec("UPDATE notification_queue SET sent = 1, sent_at = datetime('now') WHERE id = ?", id)
		} else {
			slog.Warn("Notification send failed", "channel", channel, "error", sendErr)
		}
	}
}

func sendTelegram(botURL, message string) error {
	// botURL format: https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<CHAT_ID>
	// Or we can parse chat_id from URL query params
	payload := map[string]interface{}{
		"text":       message,
		"parse_mode": "Markdown",
	}
	return postJSON(botURL, payload)
}

func sendDiscord(webhookURL, message string) error {
	payload := map[string]interface{}{
		"content": message,
		"username": "SamNet-WG",
	}
	return postJSON(webhookURL, payload)
}

func sendGenericWebhook(url, message string) error {
	payload := map[string]string{"message": message}
	return postJSON(url, payload)
}

func postJSON(url string, payload interface{}) error {
	body, _ := json.Marshal(payload)
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// QueueNotification adds a notification to the queue
func QueueNotification(db *sql.DB, channel, webhookURL, message string) error {
	_, err := db.Exec(`
		INSERT INTO notification_queue (channel, webhook_url, message, created_at) 
		VALUES (?, ?, ?, datetime('now'))
	`, channel, webhookURL, message)
	return err
}
