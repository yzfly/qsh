# qsh

**基于 QUIC 的远程 shell。你能 `ssh host`，就能 `qsh host`，而且永不掉线。**

[![CI](https://github.com/yzfly/qsh/actions/workflows/ci.yml/badge.svg)](https://github.com/yzfly/qsh/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#许可证)

[English](README.md) | 简体中文

qsh 用你已有的 ssh 登录：同样的主机、`~/.ssh/config`、密钥、agent、`known_hosts`、ProxyJump、
密码和二次验证；登录之后，会话转到 QUIC 上。会话活在服务器上，网络连接只是一根可以替换的管子。
Wi-Fi 切到蜂窝网络、合上笔记本过一夜、坐火车穿过隧道，shell 都还在，错过的输出一个字节都不少。

> **状态：1.0 之前，正在积极开发。** 1.0 之前协议和命令行仍可能变化。当前在做什么，见
> [里程碑](docs/DESIGN.md#8-milestones)。

```console
$ qsh build-box
build-box:~$ cargo build --release      # 合上盖子，换个网络，再打开
   Compiling ...                        # 先补上错过的输出，然后继续
```

## 为什么用 qsh

|                         | ssh  | mosh                          | Eternal Terminal | **qsh** |
| ----------------------- | ---- | ----------------------------- | ---------------- | ------- |
| Wi-Fi ↔ 蜂窝网络，IP 变化 | 断开 | 保持                          | 保持             | 保持（QUIC 连接迁移） |
| 笔记本休眠几个小时        | 断开 | 保持                          | 保持             | 保持，并**补发你错过的输出** |
| 回滚历史（scrollback）    | 有   | **没有**（只同步屏幕）        | 有               | 有，逐字节一致 |
| UDP 被封                  | 可用 | **不可用**                    | 可用（TCP）      | 同时竞速 QUIC、TCP 上的 TLS 和 ssh 管道，哪个通用哪个 |
| 300 ms 链路上打字         | 卡顿 | 预测回显                      | 卡顿             | 预测回显 *（计划中，M3）* |
| 大量输出后按 Ctrl-C       | 慢   | 立即                          | 慢               | 立即：智能追帧 *（计划中，M2）* |
| 端口转发、文件复制        | 有   | 没有                          | 转发             | 走 QUIC 流 *（计划中，M3）* |
| 服务器端准备              | sshd | mosh-server，开放 UDP 60000–61000 | 以 root 运行 etserver | `qsh-server`：不要 root，不要配置；`qsh` 会提议替你安装 |
| 维护状态                  | 活跃 | 最后一次发布在 2022 年        | 缓慢             | 活跃 |

qsh 不做的事：它不替代 sshd，也不替代你的认证方式。每个会话都从一次普通的 ssh 登录开始，
所以 qsh 不会要求你信任任何 ssh 本来不信任的东西。

## 安装

**发布版二进制**（Linux x86_64 / aarch64 / armv7 / riscv64，静态链接；macOS x86_64 / arm64）：

```sh
curl -fsSL https://github.com/yzfly/qsh/releases/latest/download/install.sh | sh
```

脚本会挑选适合你系统的构建，用发布附带的 `SHA256SUMS` 校验，再把 `qsh` 和 `qsh-server`
装进 `~/.local/bin`（root 时装进 `/usr/local/bin`）。选项：`--version 0.1.0`、`--prefix DIR`、
`--server-only`（只装 `qsh-server`，用于服务器）。想先读一遍？它就是
[scripts/install.sh](scripts/install.sh)。

**从源码安装**，需要 Rust 1.85 或更新版本：

```sh
cargo install --locked qsh-cli                          # qsh 和 qsh-server
cargo install --locked qsh-cli --features self-install  # 再加上 `qsh install HOST`
```

**软件包**：每个[发布](https://github.com/yzfly/qsh/releases)都附带 `.deb`、`.rpm` 和 `.apk`。
Debian、Fedora、Alpine、Arch（AUR）和 Homebrew 的原生包正在准备中，打包文件在
[packaging/](packaging/)。

<details>
<summary>校验下载</summary>

每个发布文件都在 `SHA256SUMS` 里有校验和，并有一份构建来源证明（build provenance
attestation），由构建它的 GitHub Actions 运行通过 Sigstore 签名：

```sh
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify qsh-0.1.0-x86_64-unknown-linux-musl.tar.gz --repo yzfly/qsh
```

</details>

## 快速开始

```sh
qsh myserver                    # 登录 shell，和 ssh myserver 一样
qsh -p 2222 alice@10.0.0.5      # ssh 的选项照样可用：-p -l -i -J -F -o -4 -6 -v
qsh myserver -- htop            # 在会话里运行一个命令
```

服务器上只需要 `qsh-server`：不要 root，不用启用守护进程，没有配置文件。用同一个脚本把它装到那台
主机的 `~/.local/bin`：

```sh
ssh myserver 'curl -fsSL https://github.com/yzfly/qsh/releases/latest/download/install.sh | sh -s -- --server-only'
```

也可以交给 qsh：第一次连接一台没有 `qsh-server` 的主机时，qsh 会问一次要不要替你安装，装好后接着连接；
`qsh install myserver` 单独做这件事。qsh 先经 ssh 看清主机的系统，若本机的 `qsh-server` 正是为该系统构建的
就直接拷过去，否则在你这台机器上下载对应的发布包、用发布的 `SHA256SUMS` 校验后再拷过去，所以主机不需要能上网。
不带 `self-install` 特性的构建（发行版软件包）从不下载任何东西，只会给出上面那条命令。

qsh 在服务器上监听 60443–60542 中第一个空闲的 UDP 和 TCP 端口。即使防火墙挡住了它们，qsh
仍然可用：先退到 TCP 上的 TLS，再退到经由 ssh 本身的管道。`qsh doctor myserver`
*（计划中，M2）* 会告诉你哪些传输方式可用、要打开什么才能用上最快的那个。

### 会话比客户端活得久

```sh
qsh myserver              # ……然后输入  ~d  断开（detach），会话继续运行
qsh ls                    # 本机保存的会话，所有主机（不联网）
qsh ls myserver           # myserver 上的会话：编号、名字、状态、类型、创建时间、命令
qsh attach myserver       # 重新接上，离开期间产生的输出一并补上
qsh attach myserver 3f2a  # 指定会话：编号、编号的唯一前缀或名字
qsh kill myserver 3f2a    # 结束一个会话（--all：那台主机上的全部会话）
```

每个会话的凭据保存在 `$XDG_STATE_HOME/qsh/sessions/`（权限 0600），所以 `qsh attach` 直接连服务器，
不经过 ssh，即使笔记本重启过、客户端进程被杀掉也一样；凭据失效时 qsh 会经 ssh 换一份新的。
有多个断开的会话又没指定时，qsh 会问你接哪个（在脚本里则列出它们并报错）；脚本请用 `qsh ls --json`。

断开或掉线的会话保留 6 小时（其中的程序退出后保留 1 小时）。

连接中断超过 3 秒时，qsh 用一行字告诉你：全屏程序（vim、htop）里画在最底行，连接恢复后擦掉并让程序整屏重画；
在 shell 里就是普通的一行输出。qsh 会察觉网络变化（Linux 用 netlink，macOS 用路由套接字），立刻迁移连接。

### 转义键

在一行的开头输入，和 ssh 一样：

| 按键 | 作用 |
| ---- | ---- |
| `~.` | 结束会话 |
| `~d` | 断开（detach），会话在服务器上继续运行 |
| `~s` | 连接状态：传输方式、往返时延、字节数、本次接入时长、各传输方式的尝试结果 |
| `~?` | 列出转义键 |
| `~~` | 输入一个 `~` |

### 退出码

远程程序的退出码；qsh 自身出错时为 255（和 ssh 一样）；主机上没有 `qsh-server`、而 qsh
又不在终端上无法提议安装时为 42，脚本可以据此退回 ssh。

## 工作原理

1. `qsh host` 原样运行你的 ssh，远程命令是 `qsh-server bootstrap`。密码和二次验证提示照常出现。
2. 在服务器上，`qsh-server` 启动（或找到）你这个用户的守护进程，守护进程开一个会话，回复会话
   密钥、监听端口和证书的 SHA-256。随后 ssh 连接关闭。
3. 客户端同时用 QUIC、TCP 上的 TLS 和 ssh 管道连接守护进程（错开启动），留下第一个通过认证的。
   它固定（pin）经 ssh 得知的那张证书，并证明自己持有会话密钥，这个证明绑定在这一条连接上。
4. 两端给终端数据流的每个字节编号。任何中断之后，客户端重新连接（不再需要 ssh），双方从对方
   最后收到的位置开始重发。

详细内容：[docs/DESIGN.md](docs/DESIGN.md)（架构与决策）、
[docs/protocol.md](docs/protocol.md)（qsh/1 线协议，一份别人可以照着实现的规范）、
[docs/security.md](docs/security.md)（威胁模型与认证）。

## 配置

不需要配置。qsh 通过 ssh 本身读取你的 ssh 配置。如果需要 qsh 自己的设置，格式是 TOML：先读
系统的 `/etc/qsh/qsh_config`，再读 `~/.config/qsh/config`，包含 `[defaults]` 和
`[host."pattern"]` 两类表。参考手册是 `man qsh_config`（qsh_config(5)）。

路径遵循 XDG 基础目录规范：配置在 `$XDG_CONFIG_HOME/qsh/`，保存的会话凭据（权限 0600）在
`$XDG_STATE_HOME/qsh/`，套接字在 `$XDG_RUNTIME_DIR/qsh/`。

## 安全

信任锚定在 ssh 上：没有新的密钥要分发，没有新的长期密钥，没有在认证之前接受任何东西的监听器，
也没有任何东西以 root 运行。`qsh-server` 以你的身份运行。安全模型见
[docs/security.md](docs/security.md)；私下报告漏洞见 [SECURITY.md](SECURITY.md)。

## 支持的平台

Ubuntu 20.04+、Debian 11+、Fedora、RHEL / Rocky / Alma 8+、Alpine、Arch、openSUSE 和
Amazon Linux 2023，架构 x86_64、aarch64、armv7 和 riscv64；macOS 可作客户端和服务器。
Windows 客户端以后支持。CI 会在上述每个发行版上端到端地运行 qsh，包括 UDP 被封的情形。

## 嵌入使用

协议、传输和会话层是一个库：[`qsh-core`](crates/qsh-core)，从 1.0 起遵循语义化版本保持 API 稳定。
TokenSSH（一个用手机控制服务器的 App）是它的第一个嵌入方。

## 参与贡献

特别欢迎：问题报告、对协议和安全模型的审阅、打包方面的帮助。见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 许可证

可任选 [Apache License, Version 2.0](LICENSE-APACHE) 或 [MIT 许可证](LICENSE-MIT)。

除非你明确声明，否则你有意提交并纳入 qsh 的任何贡献（按 Apache-2.0 许可证的定义），都按上述
双许可证授权，不附加任何其他条款或条件。
