# 用户需求 TODO

用户（语音转写）提的每件事，润色后逐条记在这里，一项一项做完勾掉。

## 2026-10-05

- [ ] 另起项目 qsh：用 Rust 写一个基于 QUIC 的远程 shell CLI，「现代、优雅的 SSH 升级版」，单独开源，别人也能用；TokenSSH 之后改用它（TokenSSH 的 Link 代码先拿来当起点）
- [ ] 目标是成为 Linux 发行版里的标准组件：按最高标准做产品设计和技术架构（docs/DESIGN.md 第 3 节「标准组件门槛」）
- [ ] 在各个 Linux 发行版上支持连接的自主优化（DESIGN.md 第 7 节；`qsh-server doctor` / `tune`，路径记忆、保活学习、端口回退、智能追帧）
- [ ] 把生态做好：协议规范、`qsh-core` 库、发行版打包、安装脚本、文档

## 进度

- [x] M0 设计契约 docs/DESIGN.md、协议规范 docs/protocol.md、安全模型 docs/security.md（2026-10-05）
- [x] M0 工程化：README（中英）、许可证、CI / 发版 / 发行版矩阵流水线、打包文件、安装脚本
- [x] M0 核心：qsh-core + qsh / qsh-server，QUIC / TLS / ssh 管道三路竞速、断线续传、本机测试 63 项全过
- [x] 9 个发行版（Ubuntu 20.04/24.04、Debian 12、Fedora、Rocky 9、Alpine、Arch、openSUSE、Amazon Linux 2023）真实 sshd 端到端全过：直连 QUIC、UDP 被封走 TLS、只剩 ssh 走管道
- [ ] 对抗性审查（2 高 4 中 10 低）修复中：H1 本地用户冒充 daemon、H2 输出溢出后误杀会话、非终端会话不保真（改为管道会话 + 独立 stderr）、会话泄漏、pre-auth DoS 等；同步修协议规范
- [ ] M0 收尾：GitHub CI 全绿（剩 macOS 一个测试、模糊测试抓到的编解码 bug）、9 个发行版端到端通过、对抗性代码审查的问题修完、协议补记实现中的偏差（bootstrap `tty`、KEY_CONFIRM 无状态文件时的行为等），然后公开仓库、发 v0.1.0
