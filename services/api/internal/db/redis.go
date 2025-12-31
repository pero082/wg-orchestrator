package db

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisCache provides caching layer for sessions and rate limiting
type RedisCache struct {
	client *redis.Client
	url    string
}

// NewRedisCache creates a new Redis cache connection
func NewRedisCache(url string) *RedisCache {
	return &RedisCache{url: url}
}

func (r *RedisCache) Connect() error {
	opt, err := redis.ParseURL(r.url)
	if err != nil {
		return fmt.Errorf("invalid redis URL: %w", err)
	}

	r.client = redis.NewClient(opt)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := r.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis ping failed: %w", err)
	}

	return nil
}

func (r *RedisCache) Close() error {
	if r.client != nil {
		return r.client.Close()
	}
	return nil
}

// Ping checks Redis connectivity for health checks
func (r *RedisCache) Ping(ctx context.Context) error {
	if r.client == nil {
		return fmt.Errorf("redis client not initialized")
	}
	return r.client.Ping(ctx).Err()
}

type CachedSession struct {
	UserID    int       `json:"user_id"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (r *RedisCache) SetSession(tokenHash string, session CachedSession) error {
	ctx := context.Background()
	data, _ := json.Marshal(session)
	ttl := time.Until(session.ExpiresAt)
	if ttl < 0 {
		ttl = 1 * time.Hour
	}
	return r.client.Set(ctx, "session:"+tokenHash, data, ttl).Err()
}

func (r *RedisCache) GetSession(tokenHash string) (*CachedSession, error) {
	ctx := context.Background()
	data, err := r.client.Get(ctx, "session:"+tokenHash).Bytes()
	if err == redis.Nil {
		return nil, nil // Cache miss
	}
	if err != nil {
		return nil, err
	}

	var session CachedSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}
	return &session, nil
}

func (r *RedisCache) DeleteSession(tokenHash string) error {
	ctx := context.Background()
	return r.client.Del(ctx, "session:"+tokenHash).Err()
}

type RateLimitEntry struct {
	Count    int       `json:"count"`
	LastSeen time.Time `json:"last_seen"`
}

func (r *RedisCache) IncrementRateLimit(key string, window time.Duration, limit int) (bool, error) {
	ctx := context.Background()
	
	pipe := r.client.Pipeline()
	incr := pipe.Incr(ctx, "ratelimit:"+key)
	pipe.Expire(ctx, "ratelimit:"+key, window)
	
	_, err := pipe.Exec(ctx)
	if err != nil {
		return false, err
	}

	count := incr.Val()
	return count <= int64(limit), nil
}

func (r *RedisCache) GetRateLimitCount(key string) (int, error) {
	ctx := context.Background()
	count, err := r.client.Get(ctx, "ratelimit:"+key).Int()
	if err == redis.Nil {
		return 0, nil
	}
	return count, err
}

// Write metrics (for distributed monitoring)
func (r *RedisCache) IncrementWriteCount() error {
	ctx := context.Background()
	pipe := r.client.Pipeline()
	pipe.Incr(ctx, "metrics:writes:total")
	pipe.Incr(ctx, "metrics:writes:window")
	_, err := pipe.Exec(ctx)
	return err
}

func (r *RedisCache) GetWriteMetrics() (WriteMetrics, error) {
	ctx := context.Background()
	
	total, _ := r.client.Get(ctx, "metrics:writes:total").Int64()
	window, _ := r.client.Get(ctx, "metrics:writes:window").Int64()
	peak, _ := r.client.Get(ctx, "metrics:writes:peak").Int64()

	return WriteMetrics{
		TotalWrites:     total,
		WritesPerSecond: float64(window) / 60.0, // Assumes 1-min window
		PeakWrites:      peak,
		LastSample:      time.Now(),
	}, nil
}

func (r *RedisCache) ResetWriteWindow() error {
	ctx := context.Background()
	
	window, _ := r.client.Get(ctx, "metrics:writes:window").Int64()
	peak, _ := r.client.Get(ctx, "metrics:writes:peak").Int64()
	
	if window > peak {
		r.client.Set(ctx, "metrics:writes:peak", window, 0)
	}
	
	return r.client.Set(ctx, "metrics:writes:window", 0, 0).Err()
}

// StartMetricsWindowReset resets window every minute
func (r *RedisCache) StartMetricsWindowReset(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := r.ResetWriteWindow(); err != nil {
					slog.Error("Failed to reset Redis write window", "error", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}
