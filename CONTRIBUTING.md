# 贡献指南

## 开发环境

- Go 1.25+
- GNU Make
- Docker Buildx（镜像任务）

## 工作流

1. Fork 仓库。
2. 创建主题分支。
3. 编写代码和测试。
4. 执行检查。
5. 提交 Pull Request。

```bash
gofmt -w cmd internal
go vet ./...
go test -race ./...
make release VERSION=dev
```

## Pull Request 要求

- 单一问题范围
- 测试覆盖
- 文档更新
- 变更记录
- 无密钥、Webhook、主机信息

提交信息采用祈使语气。示例：`fix: detect pam_exec in lib64`。
