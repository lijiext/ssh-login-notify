package app

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	installedBinary = "/usr/local/sbin/ssh-login-notify"
	installedConfig = "/etc/ssh-login-notify.enc"
	pamFile         = "/etc/pam.d/sshd"
	beginMarker     = "# BEGIN ssh-login-notify"
	endMarker       = "# END ssh-login-notify"
)

func copyFile(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return err
	}
	directory := filepath.Dir(destination)
	if err := os.MkdirAll(directory, 0755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".ssh-login-notify-install-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := io.Copy(temporary, io.LimitReader(input, info.Size()+1)); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(mode); err != nil {
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
	return os.Rename(temporaryPath, destination)
}

func pamMarkerCounts(data []byte) (int, int) {
	lines := strings.Split(string(data), "\n")
	begin, end := 0, 0
	for _, line := range lines {
		if line == beginMarker {
			begin++
		}
		if line == endMarker {
			end++
		}
	}
	return begin, end
}

var pamExecPatterns = []string{
	"/lib/security/pam_exec.so",
	"/usr/lib/security/pam_exec.so",
	"/lib64/security/pam_exec.so",
	"/usr/lib64/security/pam_exec.so",
	"/lib/*/security/pam_exec.so",
	"/usr/lib/*/security/pam_exec.so",
}

func pamExecAvailableIn(patterns []string) bool {
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(pattern)
		for _, match := range matches {
			if info, err := os.Stat(match); err == nil && info.Mode().IsRegular() {
				return true
			}
		}
	}
	return false
}

func pamExecAvailable() bool {
	return pamExecAvailableIn(pamExecPatterns)
}

func installSelf(configPath string) error {
	if os.Geteuid() != 0 {
		return errors.New("install 必须以 root 运行")
	}
	if _, err := decryptConfig(configPath); err != nil {
		return fmt.Errorf("安装前验证配置: %w", err)
	}
	if !pamExecAvailable() {
		return errors.New("找不到 pam_exec.so；RPM 系请安装 pam，Debian/Ubuntu 请安装 libpam-modules")
	}
	pam, err := os.ReadFile(pamFile)
	if err != nil {
		return fmt.Errorf("读取 %s: %w", pamFile, err)
	}
	begin, end := pamMarkerCounts(pam)
	if begin != end || begin > 1 {
		return errors.New("PAM 标记不完整或重复，拒绝自动修改")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}
	if executable != installedBinary {
		if err := copyFile(executable, installedBinary, 0755); err != nil {
			return fmt.Errorf("安装二进制: %w", err)
		}
	}
	absoluteConfig, _ := filepath.Abs(configPath)
	if absoluteConfig != installedConfig {
		if err := copyFile(configPath, installedConfig, 0600); err != nil {
			return fmt.Errorf("安装配置: %w", err)
		}
	} else if err := os.Chmod(installedConfig, 0600); err != nil {
		return err
	}
	if err := os.MkdirAll(stateDirectory, 0700); err != nil {
		return err
	}
	_ = os.Chmod(stateDirectory, 0700)

	if begin == 0 {
		backup := pamFile + ".ssh-login-notify.bak." + time.Now().Format("20060102150405")
		if err := copyFile(pamFile, backup, 0600); err != nil {
			return fmt.Errorf("备份 PAM: %w", err)
		}
		updated := bytes.TrimRight(pam, "\n")
		updated = append(updated, []byte("\n"+beginMarker+"\n")...)
		updated = append(updated, []byte("session optional pam_exec.so quiet type=open_session "+installedBinary+"\n")...)
		updated = append(updated, []byte(endMarker+"\n")...)
		if err := writeFileWithMode(pamFile, updated, 0644); err != nil {
			return fmt.Errorf("更新 PAM: %w", err)
		}
		fmt.Printf("PAM 备份: %s\n", backup)
	}
	if sshd, err := exec.LookPath("sshd"); err == nil {
		if output, commandErr := exec.Command(sshd, "-T").Output(); commandErr == nil &&
			!bytes.Contains(bytes.ToLower(output), []byte("usepam yes")) {
			fmt.Fprintln(os.Stderr, "警告：sshd 的 UsePAM 不是 yes")
		}
	}
	fmt.Printf("已安装 %s 和加密配置 %s\n", installedBinary, installedConfig)
	return nil
}

func writeFileWithMode(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".ssh-login-notify-edit-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
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

func uninstallSelf(purge bool) error {
	if os.Geteuid() != 0 {
		return errors.New("uninstall 必须以 root 运行")
	}
	pam, err := os.ReadFile(pamFile)
	if err != nil {
		return err
	}
	begin, end := pamMarkerCounts(pam)
	if begin != end || begin > 1 {
		return errors.New("PAM 标记不完整或重复，拒绝自动修改")
	}
	if begin == 1 {
		lines := strings.Split(string(pam), "\n")
		kept := make([]string, 0, len(lines))
		skipping := false
		for _, line := range lines {
			if line == beginMarker {
				skipping = true
				continue
			}
			if line == endMarker && skipping {
				skipping = false
				continue
			}
			if !skipping {
				kept = append(kept, line)
			}
		}
		backup := pamFile + ".ssh-login-notify.bak." + time.Now().Format("20060102150405")
		if err := copyFile(pamFile, backup, 0600); err != nil {
			return err
		}
		if err := writeFileWithMode(pamFile, []byte(strings.Join(kept, "\n")), 0644); err != nil {
			return err
		}
		fmt.Printf("PAM 备份: %s\n", backup)
	}
	if err := os.Remove(installedBinary); err != nil && !os.IsNotExist(err) {
		return err
	}
	if purge {
		for _, path := range []string{
			installedConfig,
			filepath.Join(stateDirectory, "state.json"),
			filepath.Join(stateDirectory, "state.lock"),
		} {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		_ = os.Remove(stateDirectory)
	}
	fmt.Println("卸载完成")
	return nil
}
