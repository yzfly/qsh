# qsh 项目约定（给 AI 编程助手）

qsh：基于 QUIC 的现代远程 shell，「你能 `ssh host`，就能 `qsh host`，而且永不掉线」。目标是成为 Linux 发行版的标准组件。

- 设计契约在 `docs/DESIGN.md`，协议规范在 `docs/protocol.md`，安全模型在 `docs/security.md`。改设计先改文档，再改代码。
- 仓库 `yzfly/qsh`，分支 `main`。提交身份：`git -c user.name="yzfly" -c user.email="zphyix@gmail.com" commit ...`，commit message 不加任何 AI 署名。`gh` 前先 `gh auth switch --user yzfly`。
- 用户需求清单在 `TODO.md`。
- **发布策略（2026-10-06 用户要求）**：仓库暂为私有，0.5.0（M2 完成）之前不打 tag、不发 Release；0.3.0 / 0.4.0 只在 main 上完成和验证。0.5.0 全部测试通过后再改回公开并发布。不要把有 bug 的代码公开发布。
- **测试以本地为主**（私有仓库的 Actions 按分钟计费，macOS 10 倍）：push 只自动跑 Linux 的 CI；macOS、模糊测试、9 个发行版、打包、混沌测试都是手动触发（`gh workflow run …`），只在发版前跑一轮。每个里程碑先在本地跑完 `scripts/local-test.sh`（全量测试 + 真实 sshd 端到端 + 本地混沌测试）。
- 发版：改根 `Cargo.toml` 的 `version` 和 `[workspace.dependencies] qsh-core` 的 version（两处要一致），`cargo xtask gen`（man 页带版本号），CHANGELOG 加 `## [X.Y.Z] - 日期` 一节，CI 全绿后推 `vX.Y.Z` tag。
- 代码和公开文档用英文（面向全球、面向发行版）；TODO.md 和本文件用中文。
- 起点代码：TokenSSH 仓库的 `link/`（`~/yzfly/tokenssh/link`），复用逻辑，不沿用其线协议。

## 工程标准（发行版标准组件）

- `#![forbid(unsafe_code)]`，只有 `qsh-core/src/sys.rs` 允许 unsafe，每处写明理由。
- 依赖要少、要是 Debian / Fedora 已打包的常见 crate；新增依赖先说明理由。`cargo deny check` 必须通过。
- 每个解析器都要有 fuzz 目标；会话层要有属性测试；端到端测试用 fake ssh（见 `crates/qsh-cli/tests/`）。
- 运行时不联网（协议本身除外），`qsh install` 在 cargo feature `self-install` 后面。
- 路径遵循 FHS / XDG，见 DESIGN.md 第 3 节。

## 构建资源（重要）

这台服务器只有 4 核 8G，还跑着别的服务，可用内存常常只有 2G 左右。
- 所有 cargo build / test / clippy 都排队、降优先级：`flock /tmp/heavy.lock nice -n 10 cargo ...`，并加 `-j 2`。
- 开发时用 dev profile，不要在本地跑 release + fat LTO 构建（交给 CI）。
- 2026-09-28 多个 agent 同时构建把机器拖到失联重启过。
- 磁盘也紧（根分区常只剩几 GB，2026-10-06 写满导致链接器 bus error）：构建一律 `CARGO_INCREMENTAL=0`；构建前 `df -h /`，剩余不到 3G 先清 `target/debug/incremental` 和自己 scratchpad 里的 target，别的项目的文件不要动。

## 测试隔离

- 测试用自己的临时目录、自己的端口、自己的 `XDG_RUNTIME_DIR`，绝不碰用户的 `~/.config/qsh`、绝不 kill 不是自己启动的进程。
- 不要用 `pkill -f qsh`（会误杀别人的进程）；按 pid 清理。
