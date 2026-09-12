package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const stateDirectory = "/var/lib/ssh-login-notify"

type geoCacheEntry struct {
	Expires int64   `json:"expires"`
	Value   geoData `json:"value"`
}

type stateData struct {
	Sent       []int64                  `json:"sent,omitempty"`
	Suppressed int                      `json:"suppressed,omitempty"`
	GeoQueries []int64                  `json:"geo_queries,omitempty"`
	Geo        map[string]geoCacheEntry `json:"geo,omitempty"`
}

func withLockedState(directory string, callback func(*stateData) error) error {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	_ = os.Chmod(directory, 0700)
	lock, err := os.OpenFile(filepath.Join(directory, "state.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)

	statePath := filepath.Join(directory, "state.json")
	state := stateData{Geo: make(map[string]geoCacheEntry)}
	if raw, readErr := os.ReadFile(statePath); readErr == nil && len(raw) <= 2*1024*1024 {
		_ = json.Unmarshal(raw, &state)
	}
	if state.Geo == nil {
		state.Geo = make(map[string]geoCacheEntry)
	}
	if err := callback(&state); err != nil {
		return err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return writePrivateFile(statePath, raw)
}

func allowNotification(directory string, now time.Time, cfg Config) (bool, int, error) {
	allowed := false
	previouslySuppressed := 0
	err := withLockedState(directory, func(state *stateData) error {
		minuteAgo := now.Add(-time.Minute).UnixNano()
		secondAgo := now.Add(-time.Second).UnixNano()
		kept := state.Sent[:0]
		minuteCount, secondCount := 0, 0
		for _, timestamp := range state.Sent {
			if timestamp > minuteAgo {
				kept = append(kept, timestamp)
				minuteCount++
				if timestamp > secondAgo {
					secondCount++
				}
			}
		}
		state.Sent = kept
		if minuteCount >= cfg.MaxPerMinute || secondCount >= cfg.MaxPerSecond {
			state.Suppressed++
			return nil
		}
		allowed = true
		previouslySuppressed = state.Suppressed
		state.Suppressed = 0
		state.Sent = append(state.Sent, now.UnixNano())
		return nil
	})
	return allowed, previouslySuppressed, err
}

func loadCachedGeo(directory, ip string, now time.Time) (geoData, bool, error) {
	var value geoData
	found := false
	err := withLockedState(directory, func(state *stateData) error {
		entry, ok := state.Geo[ip]
		if ok && entry.Expires > now.Unix() {
			value, found = entry.Value, true
		}
		return nil
	})
	return value, found, err
}

var errGeoQuota = errors.New("地理查询达到每日限额")

func reserveGeoQuery(directory string, now time.Time, maximum int) error {
	quotaReached := false
	err := withLockedState(directory, func(state *stateData) error {
		dayAgo := now.Add(-24 * time.Hour).Unix()
		kept := state.GeoQueries[:0]
		for _, timestamp := range state.GeoQueries {
			if timestamp > dayAgo {
				kept = append(kept, timestamp)
			}
		}
		state.GeoQueries = kept
		if len(kept) >= maximum {
			quotaReached = true
			return nil
		}
		state.GeoQueries = append(state.GeoQueries, now.Unix())
		return nil
	})
	if err != nil {
		return err
	}
	if quotaReached {
		return errGeoQuota
	}
	return nil
}

func saveCachedGeo(directory, ip string, value geoData, expires time.Time) error {
	return withLockedState(directory, func(state *stateData) error {
		if len(state.Geo) >= 1024 {
			var oldestKey string
			var oldest int64 = 1<<63 - 1
			for key, entry := range state.Geo {
				if entry.Expires < oldest {
					oldest, oldestKey = entry.Expires, key
				}
			}
			delete(state.Geo, oldestKey)
		}
		state.Geo[ip] = geoCacheEntry{Expires: expires.Unix(), Value: value}
		return nil
	})
}
