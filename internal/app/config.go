package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const configVersion = 1

var defaultHostKeys = []string{
	"/etc/ssh/ssh_host_ed25519_key",
	"/etc/ssh/ssh_host_ecdsa_key",
	"/etc/ssh/ssh_host_rsa_key",
}

type Config struct {
	WebhookURL     string `json:"webhook_url"`
	SignSecret     string `json:"sign_secret,omitempty"`
	GeoEnabled     bool   `json:"geo_enabled"`
	MaxPerMinute   int    `json:"max_per_minute"`
	MaxPerSecond   int    `json:"max_per_second"`
	GeoCacheHours  int    `json:"geo_cache_hours"`
	GeoMaxPerDay   int    `json:"geo_max_per_day"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

type encryptedEnvelope struct {
	Version    int    `json:"version"`
	KeyFile    string `json:"key_file"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func defaultConfig(webhook, secret string, geoEnabled bool) Config {
	return Config{
		WebhookURL:     strings.TrimSpace(webhook),
		SignSecret:     strings.TrimSpace(secret),
		GeoEnabled:     geoEnabled,
		MaxPerMinute:   10,
		MaxPerSecond:   4,
		GeoCacheHours:  24,
		GeoMaxPerDay:   900,
		TimeoutSeconds: 3,
	}
}

func (cfg Config) validate() error {
	parsed, err := url.Parse(cfg.WebhookURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return errors.New("飞书 Webhook 必须是有效的 HTTPS URL")
	}
	host := strings.ToLower(parsed.Hostname())
	if host != "open.feishu.cn" && host != "open.larksuite.com" {
		return errors.New("Webhook 域名必须是 open.feishu.cn 或 open.larksuite.com")
	}
	if !strings.HasPrefix(parsed.Path, "/open-apis/bot/v2/hook/") {
		return errors.New("不是飞书自定义机器人的 Webhook 路径")
	}
	if cfg.MaxPerMinute < 1 || cfg.MaxPerMinute > 100 {
		return errors.New("max_per_minute 必须在 1 到 100 之间")
	}
	if cfg.MaxPerSecond < 1 || cfg.MaxPerSecond > 5 {
		return errors.New("max_per_second 必须在 1 到 5 之间")
	}
	if cfg.GeoCacheHours < 1 || cfg.GeoCacheHours > 168 {
		return errors.New("geo_cache_hours 必须在 1 到 168 之间")
	}
	if cfg.GeoMaxPerDay < 1 || cfg.GeoMaxPerDay > 1000 {
		return errors.New("geo_max_per_day 必须在 1 到 1000 之间")
	}
	if cfg.TimeoutSeconds < 1 || cfg.TimeoutSeconds > 15 {
		return errors.New("timeout_seconds 必须在 1 到 15 之间")
	}
	return nil
}

func selectHostKey(explicit string) (string, []byte, error) {
	paths := defaultHostKeys
	if explicit != "" {
		paths = []string{explicit}
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(path)
		if err == nil && len(data) >= 16 && len(data) <= 1024*1024 {
			absolute, err := filepath.Abs(path)
			if err != nil {
				return "", nil, err
			}
			return absolute, data, nil
		}
	}
	return "", nil, errors.New("找不到可读的 SSH 主机私钥；请以 root 运行或用 --host-key 指定")
}

func deriveKey(hostKey, salt []byte) []byte {
	digest := sha256.New()
	digest.Write([]byte("ssh-login-notify/config/v1\x00"))
	digest.Write(hostKey)
	digest.Write(salt)
	return digest.Sum(nil)
}

func envelopeAAD(version int, keyFile string) []byte {
	return []byte(fmt.Sprintf("ssh-login-notify:%d:%s", version, keyFile))
}

func encryptConfig(cfg Config, keyFile string, hostKey []byte) ([]byte, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(deriveKey(hostKey, salt))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, envelopeAAD(configVersion, keyFile))
	envelope := encryptedEnvelope{
		Version:    configVersion,
		KeyFile:    keyFile,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	return json.Marshal(envelope)
}

func decryptConfig(path string) (Config, error) {
	var cfg Config
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("读取加密配置: %w", err)
	}
	if len(raw) > 64*1024 {
		return cfg, errors.New("配置文件过大")
	}
	var envelope encryptedEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return cfg, errors.New("配置格式无效")
	}
	if envelope.Version != configVersion || envelope.KeyFile == "" {
		return cfg, errors.New("不支持的配置版本")
	}
	info, err := os.Stat(envelope.KeyFile)
	if err != nil || !info.Mode().IsRegular() {
		return cfg, fmt.Errorf("配置绑定的主机密钥不可用: %s", envelope.KeyFile)
	}
	hostKey, err := os.ReadFile(envelope.KeyFile)
	if err != nil {
		return cfg, fmt.Errorf("读取主机密钥: %w", err)
	}
	salt, err := base64.StdEncoding.DecodeString(envelope.Salt)
	if err != nil || len(salt) != 32 {
		return cfg, errors.New("配置 salt 无效")
	}
	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return cfg, errors.New("配置 nonce 无效")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return cfg, errors.New("配置 ciphertext 无效")
	}
	block, err := aes.NewCipher(deriveKey(hostKey, salt))
	if err != nil {
		return cfg, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return cfg, errors.New("配置 nonce 长度无效")
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, envelopeAAD(envelope.Version, envelope.KeyFile))
	if err != nil {
		return cfg, errors.New("配置解密失败：文件损坏或 SSH 主机密钥已变化")
	}
	if err := json.Unmarshal(plaintext, &cfg); err != nil {
		return cfg, errors.New("配置明文无效")
	}
	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func writePrivateFile(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".ssh-login-notify-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
