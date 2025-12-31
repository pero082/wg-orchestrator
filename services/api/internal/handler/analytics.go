package handler

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
)

// GeoIPData represents geolocation data for a peer
type GeoIPData struct {
	PeerID    int     `json:"peer_id"`
	PeerName  string  `json:"peer_name"`
	IP        string  `json:"ip"`
	Country   string  `json:"country"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// GetPeerGeoIP returns geolocation data for all connected peers
func GetPeerGeoIP(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query(`
			SELECT p.id, p.name, p.last_endpoint 
			FROM peers p 
			WHERE p.last_endpoint IS NOT NULL AND p.last_endpoint != ''
		`)
		if err != nil {
			http.Error(w, "DB Error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var results []GeoIPData
		for rows.Next() {
			var id int
			var name, endpoint string
			if err := rows.Scan(&id, &name, &endpoint); err != nil {
				continue
			}


			
			ip := endpoint
			if idx := len(endpoint) - 1; idx > 0 {
				for i := len(endpoint) - 1; i >= 0; i-- {
					if endpoint[i] == ':' {
						ip = endpoint[:i]
						break
					}
				}
			}

			// Lookup geo data (using ip-api.com free tier)
			geo := lookupGeoIP(ip)
			geo.PeerID = id
			geo.PeerName = name
			geo.IP = ip
			results = append(results, geo)
		}

		json.NewEncoder(w).Encode(results)
	}
}

func lookupGeoIP(ip string) GeoIPData {
	resp, err := http.Get("http://ip-api.com/json/" + ip)
	if err != nil {
		return GeoIPData{}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var data struct {
		Country string  `json:"country"`
		City    string  `json:"city"`
		Lat     float64 `json:"lat"`
		Lon     float64 `json:"lon"`
	}
	json.Unmarshal(body, &data)

	return GeoIPData{
		Country:   data.Country,
		City:      data.City,
		Latitude:  data.Lat,
		Longitude: data.Lon,
	}
}

// TrafficStats represents traffic data for graphing
type TrafficStats struct {
	PeerID    int    `json:"peer_id"`
	PeerName  string `json:"peer_name"`
	Timestamp string `json:"timestamp"`
	RXBytes   int64  `json:"rx_bytes"`
	TXBytes   int64  `json:"tx_bytes"`
}

// GetTrafficHistory returns historical traffic data for charts
func GetTrafficHistory(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		peerID := r.URL.Query().Get("peer_id")
		
		var rows *sql.Rows
		var err error
		
		if peerID != "" {
			// Use parameterized query to prevent SQL injection
			rows, err = db.Query(`
				SELECT peer_id, timestamp, rx_bytes, tx_bytes 
				FROM traffic_history 
				WHERE timestamp > datetime('now', '-24 hours')
				AND peer_id = ?
				ORDER BY timestamp ASC
			`, peerID)
		} else {
			rows, err = db.Query(`
				SELECT peer_id, timestamp, rx_bytes, tx_bytes 
				FROM traffic_history 
				WHERE timestamp > datetime('now', '-24 hours')
				ORDER BY timestamp ASC
			`)
		}
		
		if err != nil {
			http.Error(w, "DB Error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var stats []TrafficStats
		for rows.Next() {
			var s TrafficStats
			rows.Scan(&s.PeerID, &s.Timestamp, &s.RXBytes, &s.TXBytes)
			stats = append(stats, s)
		}

		json.NewEncoder(w).Encode(stats)
	}
}
