package app

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"
)

type loginEvent struct {
	Username string
	RemoteIP string
	Hostname string
	TTY      string
}

type geoData struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Country string `json:"country"`
	Region  string `json:"region"`
	City    string `json:"city"`
	Flag    struct {
		Emoji string `json:"emoji"`
	} `json:"flag"`
	Connection struct {
		Org string `json:"org"`
	} `json:"connection"`
}

func eventFromEnvironment() (loginEvent, bool) {
	if os.Getenv("PAM_SERVICE") != "sshd" || os.Getenv("PAM_TYPE") != "open_session" {
		return loginEvent{}, false
	}
	username := strings.TrimSpace(os.Getenv("PAM_USER"))
	remote := strings.TrimSpace(os.Getenv("PAM_RHOST"))
	ip, err := netip.ParseAddr(remote)
	if username == "" || err != nil {
		return loginEvent{}, false
	}
	hostname, _ := os.Hostname()
	return loginEvent{
		Username: username,
		RemoteIP: ip.Unmap().String(),
		Hostname: hostname,
		TTY:      strings.TrimSpace(os.Getenv("PAM_TTY")),
	}, true
}

func isPublicIP(value string) bool {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() ||
		address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range specialUsePrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var specialUsePrefixes = func() []netip.Prefix {
	values := []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
		"100::/64", "2001:db8::/32",
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	return prefixes
}()

func lookupGeo(client *http.Client, cfg Config, event loginEvent, directory string, now time.Time) (string, string) {
	if !cfg.GeoEnabled {
		return "未启用", ""
	}
	if !isPublicIP(event.RemoteIP) {
		return "内网或保留地址", ""
	}
	if cached, found, err := loadCachedGeo(directory, event.RemoteIP, now); err == nil && found {
		return formatGeo(cached)
	}
	if err := reserveGeoQuery(directory, now, cfg.GeoMaxPerDay); err != nil {
		if errors.Is(err, errGeoQuota) {
			return "查询限速", ""
		}
		return "查询失败", ""
	}
	requestURL := "https://ipwho.is/" + event.RemoteIP +
		"?fields=success,message,country,region,city,flag,connection"
	request, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return "查询失败", ""
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "ssh-login-notify/1.0")
	response, err := client.Do(request)
	if err != nil {
		return "查询失败", ""
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "查询失败", ""
	}
	var data geoData
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64*1024))
	if err := decoder.Decode(&data); err != nil || !data.Success {
		return "查询失败", ""
	}
	_ = saveCachedGeo(directory, event.RemoteIP, data, now.Add(time.Duration(cfg.GeoCacheHours)*time.Hour))
	return formatGeo(data)
}

func formatGeo(data geoData) (string, string) {
	parts := make([]string, 0, 3)
	for _, part := range []string{data.Country, data.Region, data.City} {
		if strings.TrimSpace(part) != "" {
			parts = append(parts, strings.TrimSpace(part))
		}
	}
	location := strings.Join(parts, " / ")
	if data.Flag.Emoji != "" {
		location = strings.TrimSpace(data.Flag.Emoji + " " + location)
	}
	if location == "" {
		location = "未知"
	}
	return location, strings.TrimSpace(data.Connection.Org)
}

func escapeMarkdown(value string) string {
	replacer := strings.NewReplacer(
		"\\", "\\\\", "*", "\\*", "_", "\\_", "~", "\\~", "`", "\\`",
		"[", "\\[", "]", "\\]", "<", "&lt;", ">", "&gt;", "\r", " ", "\n", " ",
	)
	return replacer.Replace(value)
}

func buildPayload(cfg Config, event loginEvent, now time.Time, location, organization string, suppressed int) map[string]any {
	fields := [][2]string{
		{"登录时间", now.Format(time.RFC3339)},
		{"服务器", event.Hostname},
		{"用户名", event.Username},
		{"来源 IP", event.RemoteIP},
		{"地理位置", location},
	}
	if organization != "" {
		fields = append(fields, [2]string{"网络组织", organization})
	}
	if event.TTY != "" {
		fields = append(fields, [2]string{"终端", event.TTY})
	}
	if suppressed > 0 {
		fields = append(fields, [2]string{"此前限速抑制", fmt.Sprintf("%d 条", suppressed)})
	}
	lines := make([]string, 0, len(fields))
	for _, field := range fields {
		lines = append(lines, fmt.Sprintf("**%s：** %s", field[0], escapeMarkdown(field[1])))
	}
	payload := map[string]any{
		"msg_type": "interactive",
		"card": map[string]any{
			"schema": "2.0",
			"config": map[string]any{"update_multi": true},
			"body": map[string]any{
				"direction": "vertical",
				"elements": []any{map[string]any{
					"tag": "markdown", "content": strings.Join(lines, "\n"), "text_align": "left",
				}},
			},
			"header": map[string]any{
				"title":    map[string]any{"tag": "plain_text", "content": "SSH 登录成功"},
				"template": "green",
			},
		},
	}
	if cfg.SignSecret != "" {
		timestamp := fmt.Sprintf("%d", now.Unix())
		mac := hmac.New(sha256.New, []byte(timestamp+"\n"+cfg.SignSecret))
		signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		payload["timestamp"] = timestamp
		payload["sign"] = signature
	}
	return payload
}

func sendFeishu(client *http.Client, webhook string, payload map[string]any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, webhook, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("调用飞书失败: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("飞书 HTTP 状态: %s", response.Status)
	}
	var result struct {
		Code          *int   `json:"code"`
		StatusCode    *int   `json:"StatusCode"`
		Message       string `json:"msg"`
		StatusMessage string `json:"StatusMessage"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 64*1024)).Decode(&result); err != nil {
		return fmt.Errorf("解析飞书响应: %w", err)
	}
	code := 0
	if result.Code != nil {
		code = *result.Code
	} else if result.StatusCode != nil {
		code = *result.StatusCode
	}
	if code != 0 {
		message := result.Message
		if message == "" {
			message = result.StatusMessage
		}
		return fmt.Errorf("飞书返回错误 %d: %s", code, message)
	}
	return nil
}

var errNotificationLimited = errors.New("通知被限速")

func processEvent(cfg Config, event loginEvent, directory string, now time.Time, dryRun bool) (map[string]any, error) {
	client := &http.Client{Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second}
	suppressed := 0
	if !dryRun {
		allowed, count, err := allowNotification(directory, now, cfg)
		if err != nil {
			return nil, fmt.Errorf("限速状态: %w", err)
		}
		if !allowed {
			return nil, errNotificationLimited
		}
		suppressed = count
	}
	location, organization := "已跳过", ""
	if !dryRun {
		location, organization = lookupGeo(client, cfg, event, directory, now)
	}
	payload := buildPayload(cfg, event, now, location, organization, suppressed)
	if !dryRun {
		if err := sendFeishu(client, cfg.WebhookURL, payload); err != nil {
			return nil, err
		}
	}
	return payload, nil
}
