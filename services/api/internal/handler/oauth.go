package handler

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

// OAuthConfig holds OAuth provider settings
type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
}

var googleOAuth = OAuthConfig{
	AuthURL:     "https://accounts.google.com/o/oauth2/v2/auth",
	TokenURL:    "https://oauth2.googleapis.com/token",
	UserInfoURL: "https://www.googleapis.com/oauth2/v2/userinfo",
}

var githubOAuth = OAuthConfig{
	AuthURL:     "https://github.com/login/oauth/authorize",
	TokenURL:    "https://github.com/login/oauth/access_token",
	UserInfoURL: "https://api.github.com/user",
}

// OAuthRedirect initiates OAuth flow
func OAuthRedirect(db *sql.DB, provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var config OAuthConfig
		switch provider {
		case "google":
			config = googleOAuth
			config.ClientID = os.Getenv("GOOGLE_CLIENT_ID")
			config.RedirectURI = os.Getenv("OAUTH_REDIRECT_BASE") + "/api/v1/oauth/google/callback"
		case "github":
			config = githubOAuth
			config.ClientID = os.Getenv("GITHUB_CLIENT_ID")
			config.RedirectURI = os.Getenv("OAUTH_REDIRECT_BASE") + "/api/v1/oauth/github/callback"
		default:
			http.Error(w, "Unknown provider", http.StatusBadRequest)
			return
		}

		// Generate state for CSRF protection
		state := generateRandomState()

		// Store state in session/cookie for verification
		http.SetCookie(w, &http.Cookie{
			Name:     "oauth_state",
			Value:    state,
			HttpOnly: true,
			Path:     "/",
		})

		authURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=email&state=%s",
			config.AuthURL, config.ClientID, url.QueryEscape(config.RedirectURI), state)

		http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
	}
}

// OAuthCallback handles the OAuth callback
func OAuthCallback(db *sql.DB, provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stateCookie, err := r.Cookie("oauth_state")
		if err != nil || stateCookie.Value != r.URL.Query().Get("state") {
			http.Error(w, "Invalid state", http.StatusUnauthorized)
			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Missing code", http.StatusBadRequest)
			return
		}

		var config OAuthConfig
		switch provider {
		case "google":
			config = googleOAuth
			config.ClientID = os.Getenv("GOOGLE_CLIENT_ID")
			config.ClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
			config.RedirectURI = os.Getenv("OAUTH_REDIRECT_BASE") + "/api/v1/oauth/google/callback"
		case "github":
			config = githubOAuth
			config.ClientID = os.Getenv("GITHUB_CLIENT_ID")
			config.ClientSecret = os.Getenv("GITHUB_CLIENT_SECRET")
			config.RedirectURI = os.Getenv("OAUTH_REDIRECT_BASE") + "/api/v1/oauth/github/callback"
		}

		token, err := exchangeCodeForToken(config, code)
		if err != nil {
			http.Error(w, "Token exchange failed", http.StatusInternalServerError)
			return
		}

		email, err := getUserEmail(config, token, provider)
		if err != nil {
			http.Error(w, "Failed to get user info", http.StatusInternalServerError)
			return
		}

		// Check if user exists or create new one
		var userID int
		err = db.QueryRow("SELECT id FROM users WHERE email = ?", email).Scan(&userID)
		if err == sql.ErrNoRows {
			result, _ := db.Exec("INSERT INTO users (username, email, role, auth_provider) VALUES (?, ?, 'viewer', ?)", email, email, provider)
			id, _ := result.LastInsertId()
			userID = int(id)
		}

		// Create session
		sessionToken := generateRandomState()
		db.Exec("INSERT INTO sessions (user_id, token_hash, created_at, expires_at) VALUES (?, ?, datetime('now'), datetime('now', '+7 days'))", userID, sessionToken)

		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    sessionToken,
			HttpOnly: true,
			Path:     "/",
		})

		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}
}

func generateRandomState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func exchangeCodeForToken(config OAuthConfig, code string) (string, error) {
	data := url.Values{}
	data.Set("client_id", config.ClientID)
	data.Set("client_secret", config.ClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", config.RedirectURI)
	data.Set("grant_type", "authorization_code")

	resp, err := http.PostForm(config.TokenURL, data)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(body, &result)

	if token, ok := result["access_token"].(string); ok {
		return token, nil
	}
	return "", fmt.Errorf("no access token")
}

func getUserEmail(config OAuthConfig, token, provider string) (string, error) {
	req, _ := http.NewRequest("GET", config.UserInfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if provider == "github" {
		req.Header.Set("Accept", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(body, &result)

	if email, ok := result["email"].(string); ok {
		return email, nil
	}
	return "", fmt.Errorf("no email")
}
