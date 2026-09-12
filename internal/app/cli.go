package app

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"
)

var version = "dev"

func usage() {
	fmt.Fprintf(os.Stderr, `SSH 登录飞书通知 %s

用法:
  ssh-login-notify init [--config FILE] [--host-key FILE] [--no-geo] [--force]
  ssh-login-notify test [--config FILE] [--ip IP] [--user USER]
  ssh-login-notify dry-run [--config FILE] [--ip IP] [--user USER]
  ssh-login-notify install [--config FILE]
  ssh-login-notify uninstall [--purge]
  ssh-login-notify version
`, version)
}

func runInit(arguments []string) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	configPath := flags.String("config", "./ssh-login-notify.enc", "加密配置输出路径")
	hostKeyPath := flags.String("host-key", "", "SSH 主机私钥路径（默认自动选择）")
	noGeo := flags.Bool("no-geo", false, "禁用 IP 地理查询")
	force := flags.Bool("force", false, "覆盖已有配置")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if _, err := os.Stat(*configPath); err == nil && !*force {
		return errors.New("配置已存在；如需覆盖请加 --force")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	reader := bufio.NewReader(os.Stdin)
	webhook, err := readHiddenLine("飞书 Webhook（输入不回显）: ", reader)
	if err != nil && webhook == "" {
		return err
	}
	secret, _ := readHiddenLine("飞书签名密钥（未启用可直接回车）: ", reader)
	cfg := defaultConfig(webhook, secret, !*noGeo)
	keyFile, hostKey, err := selectHostKey(*hostKeyPath)
	if err != nil {
		return err
	}
	encrypted, err := encryptConfig(cfg, keyFile, hostKey)
	if err != nil {
		return err
	}
	if err := writePrivateFile(*configPath, encrypted); err != nil {
		return err
	}
	fmt.Printf("已生成机器绑定的加密配置 %s（0600）\n", *configPath)
	return nil
}

func testEvent(ipValue, username string) (loginEvent, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(ipValue))
	if err != nil {
		return loginEvent{}, errors.New("测试 IP 无效")
	}
	hostname, _ := os.Hostname()
	return loginEvent{Username: username, RemoteIP: ip.Unmap().String(), Hostname: hostname, TTY: "test"}, nil
}

func runTest(arguments []string, dryRun bool) error {
	name := "test"
	if dryRun {
		name = "dry-run"
	}
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	configPath := flags.String("config", installedConfig, "加密配置路径")
	statePath := flags.String("state-dir", stateDirectory, "限速和缓存状态目录")
	ipValue := flags.String("ip", "8.8.8.8", "测试来源 IP")
	username := flags.String("user", "test", "测试用户名")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	cfg, err := decryptConfig(*configPath)
	if err != nil {
		return err
	}
	event, err := testEvent(*ipValue, *username)
	if err != nil {
		return err
	}
	directory := *statePath
	if dryRun {
		directory = os.TempDir()
	}
	payload, err := processEvent(cfg, event, directory, time.Now(), dryRun)
	if err != nil {
		return err
	}
	if dryRun {
		encoded, _ := json.MarshalIndent(payload, "", "  ")
		fmt.Println(string(encoded))
	} else {
		fmt.Println("测试消息发送成功")
	}
	return nil
}

func startWorker(event loginEvent) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	command := exec.Command(executable, "_worker", "--config", installedConfig)
	command.Env = []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"PAM_SERVICE=sshd",
		"PAM_TYPE=open_session",
		"PAM_USER=" + event.Username,
		"PAM_RHOST=" + event.RemoteIP,
		"PAM_TTY=" + event.TTY,
	}
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer null.Close()
	command.Stdin, command.Stdout, command.Stderr = null, null, null
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		return err
	}
	return command.Process.Release()
}

func runWorker(arguments []string) error {
	flags := flag.NewFlagSet("_worker", flag.ContinueOnError)
	configPath := flags.String("config", installedConfig, "config")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if writer, err := syslog.New(syslog.LOG_AUTH|syslog.LOG_WARNING, "ssh-login-notify"); err == nil {
		defer writer.Close()
		log.SetOutput(writer)
	}
	event, ok := eventFromEnvironment()
	if !ok {
		return nil
	}
	cfg, err := decryptConfig(*configPath)
	if err != nil {
		return err
	}
	_, err = processEvent(cfg, event, stateDirectory, time.Now(), false)
	if errors.Is(err, errNotificationLimited) {
		log.Printf("通知被限速: user=%s ip=%s", event.Username, event.RemoteIP)
		return nil
	}
	return err
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		event, ok := eventFromEnvironment()
		if !ok {
			usage()
			return nil
		}
		return startWorker(event)
	}
	switch arguments[0] {
	case "init":
		return runInit(arguments[1:])
	case "test":
		return runTest(arguments[1:], false)
	case "dry-run":
		return runTest(arguments[1:], true)
	case "install":
		flags := flag.NewFlagSet("install", flag.ContinueOnError)
		configPath := flags.String("config", "./ssh-login-notify.enc", "加密配置路径")
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		return installSelf(*configPath)
	case "uninstall":
		flags := flag.NewFlagSet("uninstall", flag.ContinueOnError)
		purge := flags.Bool("purge", false, "同时删除配置和状态")
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		return uninstallSelf(*purge)
	case "_worker":
		return runWorker(arguments[1:])
	case "version":
		fmt.Printf("ssh-login-notify %s %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
		return nil
	default:
		usage()
		return fmt.Errorf("未知命令: %s", arguments[0])
	}
}

// Main runs the command and returns its process exit code.
func Main(arguments []string) int {
	if err := run(arguments); err != nil {
		log.Printf("错误: %v", err)
		return 1
	}
	return 0
}
