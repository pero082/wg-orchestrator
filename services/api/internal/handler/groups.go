package handler

import (
	"database/sql"
	"encoding/json"
	"net/http"
)

// PeerGroup represents a group/tag for organizing peers
type PeerGroup struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Color string `json:"color"`
}

// ListPeerGroups returns all peer groups
func ListPeerGroups(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query("SELECT id, name, color FROM peer_groups ORDER BY name")
		if err != nil {
			http.Error(w, "DB Error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var groups []PeerGroup
		for rows.Next() {
			var g PeerGroup
			rows.Scan(&g.ID, &g.Name, &g.Color)
			groups = append(groups, g)
		}

		json.NewEncoder(w).Encode(groups)
	}
}

// CreatePeerGroup creates a new group
func CreatePeerGroup(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req PeerGroup
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		result, err := db.Exec("INSERT INTO peer_groups (name, color) VALUES (?, ?)", req.Name, req.Color)
		if err != nil {
			http.Error(w, "Failed to create group", http.StatusInternalServerError)
			return
		}

		id, _ := result.LastInsertId()
		req.ID = int(id)
		json.NewEncoder(w).Encode(req)
	}
}

// AssignPeerToGroup assigns a peer to a group
func AssignPeerToGroup(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			PeerID  int `json:"peer_id"`
			GroupID int `json:"group_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		_, err := db.Exec("INSERT OR REPLACE INTO peer_group_members (peer_id, group_id) VALUES (?, ?)", req.PeerID, req.GroupID)
		if err != nil {
			http.Error(w, "Failed to assign", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "assigned"}`))
	}
}

// ListPeersInGroup lists all peers in a specific group
func ListPeersInGroup(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		groupID := r.URL.Query().Get("group_id")
		if groupID == "" {
			http.Error(w, "Missing group_id", http.StatusBadRequest)
			return
		}

		rows, err := db.Query(`
			SELECT p.id, p.name, p.public_key, p.allowed_ips 
			FROM peers p
			JOIN peer_group_members pgm ON p.id = pgm.peer_id
			WHERE pgm.group_id = ?
		`, groupID)
		if err != nil {
			http.Error(w, "DB Error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var peers []Peer
		for rows.Next() {
			var p Peer
			rows.Scan(&p.ID, &p.Name, &p.PublicKey, &p.AllowedIPs)
			peers = append(peers, p)
		}

		json.NewEncoder(w).Encode(peers)
	}
}
