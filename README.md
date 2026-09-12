# ssh-login-notify

[![CI](https://github.com/lijiext/ssh-login-notify/actions/workflows/ci.yml/badge.svg)](https://github.com/lijiext/ssh-login-notify/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/lijiext/ssh-login-notify)](https://github.com/lijiext/ssh-login-notify/releases)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

SSH 登录成功事件的飞书通知程序。Go 静态二进制连接 PAM、IP 地理服务和飞书自定义机器人。

## 功能

| 项目 | 内容 |
| --- | --- |
| 事件源 | `sshd` 的 PAM `open_session` |
| 消息格式 | 飞书卡片 2.0 Markdown |
| 消息字段 | 时间、主机、用户、来源 IP、位置、网络组织、终端 |
| 配置保护 | AES-256-GCM、SSH 主机私钥绑定、`0600` 权限 |
| 通知限速 | 10 次/分钟、4 次/秒 |
| 地理查询 | HTTPS、24 小时缓存、900 次/24 小时 |
| 失败策略 | PAM `optional`、后台工作进程、登录放行 |
| 架构 | linux/amd64、linux/arm64、linux/armv7、linux/386 |

## 数据流

```text
sshd -> PAM open_session -> ssh-login-notify -> 后台工作进程
                                              ├─ ipwho.is
                                              └─ Feishu Webhook
```

## 系统要求

- Linux
- OpenSSH `UsePAM yes`
- `pam_exec.so`
- root 权限（配置生成、安装、卸载）

| 系统族 | PAM 软件包 | 模块路径示例 |
| --- | --- | --- |
| Debian、Ubuntu | `libpam-modules` | `/usr/lib/*/security/pam_exec.so` |
| RHEL、Fedora、openEuler、麒麟 | `pam` | `/usr/lib64/security/pam_exec.so` |

模块查询：

```bash
rpm -ql pam | grep '/pam_exec\.so$'
dpkg -L libpam-modules | grep '/pam_exec\.so$'
```

## 安装

### 1. 下载

从 [Releases](https://github.com/lijiext/ssh-login-notify/releases) 选择架构文件，校验 `checksums.txt`。

ARM64 / aarch64 示例：

```bash
tar -xzf ssh-login-notify_1.0.1_linux_aarch64.tar.gz
chmod 0755 ssh-login-notify
```

### 2. 生成配置

配置生成环境：目标 SSH 主机。密钥材料：SSH 主机私钥和随机 salt。

```bash
sudo ./ssh-login-notify init
```

交互输入：

- 飞书 Webhook
- 飞书签名密钥；空行代表未启用签名

输出文件：`ssh-login-notify.enc`。

### 3. 测试

```bash
sudo ./ssh-login-notify test \
  --config ./ssh-login-notify.enc \
  --ip 8.8.8.8 \
  --user test
```

### 4. 安装

```bash
sudo ./ssh-login-notify install --config ./ssh-login-notify.enc
```

安装内容：

| 路径 | 用途 |
| --- | --- |
| `/usr/local/sbin/ssh-login-notify` | 程序 |
| `/etc/ssh-login-notify.enc` | 加密配置 |
| `/var/lib/ssh-login-notify` | 限速状态和位置缓存 |
| `/etc/pam.d/sshd` | PAM 会话钩子 |

保留安装会话。建立新 SSH 会话。检查飞书消息。

## 配置加密

配置格式：JSON 信封。密文字段：Webhook、签名密钥、限速参数、地理查询参数。算法：AES-256-GCM。

密钥派生输入：

- SSH 主机私钥
- 32 字节随机 salt
- 应用上下文字符串

主机私钥轮换流程：

```bash
sudo ./ssh-login-notify init --force
sudo ./ssh-login-notify install --config ./ssh-login-notify.enc
```

安全边界见 [SECURITY.md](SECURITY.md)。

## 命令

```text
ssh-login-notify init [--config FILE] [--host-key FILE] [--no-geo] [--force]
ssh-login-notify test [--config FILE] [--ip IP] [--user USER]
ssh-login-notify dry-run [--config FILE] [--ip IP] [--user USER]
ssh-login-notify install [--config FILE]
ssh-login-notify uninstall [--purge]
ssh-login-notify version
```

请求预览：

```bash
sudo ./ssh-login-notify dry-run \
  --config ./ssh-login-notify.enc \
  --ip 8.8.8.8 \
  --user alice
```

卸载：

```bash
sudo /usr/local/sbin/ssh-login-notify uninstall
```

配置和状态清除：

```bash
sudo /usr/local/sbin/ssh-login-notify uninstall --purge
```

## 构建

```bash
make test
make release VERSION=1.0.1
```

产物目录：`dist/`。

OCI archive：

```bash
make image VERSION=1.0.1
```

容器仓库镜像：

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64,linux/arm/v7 \
  --build-arg VERSION=1.0.1 \
  --tag ghcr.io/lijiext/ssh-login-notify:1.0.1 \
  --push .
```

PAM 钩子位于宿主机。二进制产物用于 SSH 主机部署。容器镜像用于制品分发和命令检查。

## 贡献与许可

- [贡献指南](CONTRIBUTING.md)
- [安全策略](SECURITY.md)
- [变更记录](CHANGELOG.md)
- [MIT License](LICENSE)
