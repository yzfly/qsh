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
- [x] 对抗性审查（2 高 4 中 10 低）全部修完，协议规范同步更新；新增「管道会话」：非终端命令逐字节保真、stderr 分开、stdin 结束送达
- [x] CI 全绿（Linux、macOS、MSRV、cargo deny、4 个模糊测试目标），9 个发行版端到端全过，6 个平台发版构建全过
- [x] 仓库公开（2026-10-06），发布 v0.1.0：https://github.com/yzfly/qsh/releases/tag/v0.1.0 ；一行命令安装实测可用，构建来源证明可验证
- [x] v0.1.1：远端没有 qsh-server 时提示一条现在就能用的安装命令（0.1.0 提示的 `qsh install` 要到 M1 才有）

## 下一步（M1 日常可用）

- [x] v0.2.0（2026-10-06）：`qsh install` 和首次连接提议安装、`qsh attach / ls / kill` + 本地会话凭据、配置文件、网络变化监听（立即迁移 + 探测）、全屏程序底行断线提示；终端会话保留已确认输出作滚动历史（新窗口 attach 能看到最近输出）
- [ ] 小问题：`qsh --help` 里 `[user@]host` 两边的反引号被原样显示
- [ ] `keepalive`、`predict` 配置项还没接上（M2 / M3）
- [ ] `qsh kill --all` 对每个会话各跑一次 ssh（密码用户会被问多次），考虑一次 ssh 批量结束
- [ ] 发行版打包实际跑通（Debian / Fedora / Alpine / Arch 用各自工具构建一次），AUR 先上
- [ ] M2 预研：`qsh-server doctor / tune`（各发行版防火墙、UDP 缓冲、BBR）、路径记忆、保活学习、智能追帧
