package app

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testConfig() Config {
	return defaultConfig("https://open.feishu.cn/open-apis/bot/v2/hook/test", "demo", true)
}

func TestEncryptDecryptConfig(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "host-key")
	configPath := filepath.Join(directory, "config.enc")
	key := []byte("a sufficiently long fake host private key")
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := encryptConfig(testConfig(), keyPath, key)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "open.feishu.cn") || strings.Contains(string(raw), "demo") {
		t.Fatal("encrypted file leaked plaintext")
	}
	if err := os.WriteFile(configPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := decryptConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.WebhookURL != testConfig().WebhookURL || got.SignSecret != "demo" {
		t.Fatalf("unexpected config: %#v", got)
	}
	if err := os.WriteFile(keyPath, []byte("a different and sufficiently long host key"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := decryptConfig(configPath); err == nil {
		t.Fatal("wrong host key unexpectedly decrypted config")
	}
}

func TestPayloadMarkdownAndSignature(t *testing.T) {
	cfg := testConfig()
	now := time.Unix(1599360473, 0).In(time.FixedZone("UTC+8", 8*3600))
	event := loginEvent{Username: "a*lice", RemoteIP: "8.8.8.8", Hostname: "server_1", TTY: "ssh"}
	payload := buildPayload(cfg, event, now, "United States", "Google", 2)
	if payload["msg_type"] != "interactive" {
		t.Fatalf("unexpected message type: %v", payload["msg_type"])
	}
	card := payload["card"].(map[string]any)
	if card["schema"] != "2.0" {
		t.Fatalf("unexpected schema: %v", card["schema"])
	}
	encoded, _ := json.Marshal(payload)
	if !strings.Contains(string(encoded), `a\\*lice`) || !strings.Contains(string(encoded), "此前限速抑制") {
		t.Fatalf("missing escaped markdown fields: %s", encoded)
	}
	mac := hmac.New(sha256.New, []byte("1599360473\ndemo"))
	expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if payload["sign"] != expected {
		t.Fatalf("unexpected signature: %v", payload["sign"])
	}
}

func TestRateLimits(t *testing.T) {
	directory := t.TempDir()
	cfg := testConfig()
	cfg.MaxPerMinute = 3
	cfg.MaxPerSecond = 2
	now := time.Unix(100, 0)
	if allowed, _, err := allowNotification(directory, now, cfg); err != nil || !allowed {
		t.Fatalf("first notification: allowed=%v err=%v", allowed, err)
	}
	if allowed, _, err := allowNotification(directory, now.Add(100*time.Millisecond), cfg); err != nil || !allowed {
		t.Fatalf("second notification: allowed=%v err=%v", allowed, err)
	}
	if allowed, _, _ := allowNotification(directory, now.Add(200*time.Millisecond), cfg); allowed {
		t.Fatal("burst limit did not apply")
	}
	if allowed, suppressed, err := allowNotification(directory, now.Add(2*time.Second), cfg); err != nil || !allowed || suppressed != 1 {
		t.Fatalf("post-burst notification: allowed=%v suppressed=%d err=%v", allowed, suppressed, err)
	}
	if allowed, _, _ := allowNotification(directory, now.Add(3*time.Second), cfg); allowed {
		t.Fatal("minute limit did not apply")
	}
}

func TestPAMEventFilter(t *testing.T) {
	t.Setenv("PAM_SERVICE", "sshd")
	t.Setenv("PAM_TYPE", "open_session")
	t.Setenv("PAM_USER", "alice")
	t.Setenv("PAM_RHOST", "2001:4860:4860::8888")
	event, ok := eventFromEnvironment()
	if !ok || event.Username != "alice" || event.RemoteIP != "2001:4860:4860::8888" {
		t.Fatalf("unexpected event: %#v ok=%v", event, ok)
	}
	t.Setenv("PAM_SERVICE", "cron")
	if _, ok := eventFromEnvironment(); ok {
		t.Fatal("cron event was accepted")
	}
}

func TestPrivateIPs(t *testing.T) {
	for _, value := range []string{
		"127.0.0.1", "10.0.0.1", "100.64.0.1", "192.0.2.1", "198.51.100.1",
		"203.0.113.1", "::1", "fe80::1", "2001:db8::1",
	} {
		if isPublicIP(value) {
			t.Fatalf("private IP considered public: %s", value)
		}
	}
	if !isPublicIP("8.8.8.8") {
		t.Fatal("public IP considered private")
	}
}

func TestPAMMarkers(t *testing.T) {
	begin, end := pamMarkerCounts([]byte("x\n" + beginMarker + "\ny\n" + endMarker + "\n"))
	if begin != 1 || end != 1 {
		t.Fatalf("unexpected markers: %d %d", begin, end)
	}
}

func TestPAMExecDiscovery(t *testing.T) {
	directory := t.TempDir()
	module := filepath.Join(directory, "lib64", "security", "pam_exec.so")
	if err := os.MkdirAll(filepath.Dir(module), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(module, []byte("test module"), 0644); err != nil {
		t.Fatal(err)
	}
	if !pamExecAvailableIn([]string{filepath.Join(directory, "lib64", "security", "pam_exec.so")}) {
		t.Fatal("lib64 PAM module was not discovered")
	}
	if pamExecAvailableIn([]string{filepath.Join(directory, "missing", "pam_exec.so")}) {
		t.Fatal("missing PAM module was reported as present")
	}
}
