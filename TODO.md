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
- [x] 发行版打包实际跑通（2026-10-06）：Debian 12/13、Ubuntu 24.04、Fedora、Alpine、Arch、Homebrew 都用各自官方工具从源码构建、lint、安装、跑一次真实会话（.github/workflows/packaging.yml）；详情和正式收录步骤见 packaging/README.md
- [x] v0.2.1（2026-10-06）稳健性：打包时暴露的不稳定测试（daemon 启动等待、重连后 Ctrl-C 可能没送到——疑似真 bug、busybox yes）、rcgen 0.14 / clap_mangen 0.3（之后 Debian / Fedora 不用 vendor 就能构建）、帮助文本反引号
- [x] M2 规范（docs/m2.md）：路径记忆、保活学习、端口回退、智能追帧 SNAPSHOT、zstd、doctor / tune（按发行版）、daemon 无损升级、netem 混沌测试与对比基准
- [ ] 需要用户决定 / 用户账号的对外动作：AUR 账号上传 qsh 包；建 Homebrew tap 仓库 yzfly/homebrew-tap；Debian ITP（维护者身份、邮件）；Fedora 包审核
- [ ] M2 预研：`qsh-server doctor / tune`（各发行版防火墙、UDP 缓冲、BBR）、路径记忆、保活学习、智能追帧

## M2 实现（按 docs/m2.md §13 工作包）

- [x] WP-0 接口：拆分 client（conn / pool / session）、SNAPSHOT / OUTPUT_ZSTD 编解码与 zstd 帧头检查、RESTART、bootstrap extra_ports、M2 配置项、QSH_TRANSCRIPT 测试钩子、服务端输出钩子
- [x] WP-1 客户端：路径记忆、NAT 保活学习、备用端口、后台重探与切到更好的传输
- [x] WP-4 服务端：备用端口、daemon 原地升级不丢会话、socket 缓冲、TLS 上的 BBR
- [x] WP-5 混沌测试与对比基准（CI 手动触发；本地 `scripts/local-test.sh --chaos`）
- [x] WP-2 智能追帧（vt100 画面模型 + SNAPSHOT）与 zstd 压缩（自写有界 zstd 解码器）
- [x] WP-3 `doctor` / `tune`（18 项检查，13 个发行版样本，tune 可逐字节还原）
- [x] 只用发行版自带 crate 构建：Fedora rawhide、Debian testing 通过（CI 必过项）；Debian unstable 卡在上游 synstructure 迁移，等 Rust 团队

## 2026-10-06 用户要求

- [x] 0.5.0 做完之前不公开发布，不要把有 bug 的代码公开：仓库已改回私有（0 star / fork）；0.3.0、0.4.0 只在 main 上完成和验证，不打 tag；0.5.0 全部测试通过后再公开并发版
- [x] 在本地做详尽测试（`scripts/local-test.sh`，34 项，约 5 分钟；能复现修复前的大文件卡住 bug）：`scripts/local-test.sh`（全量测试 + 本地无 root 的真实 sshd 端到端 + sudo 网络命名空间里的本地混沌测试，严格隔离、不动宿主网络）；CI 改为 push 只跑 Linux，其余手动触发、发版前跑一轮
- [x] 清理磁盘：2.9G → 19G 空闲（TokenSSH 38 个干净的旧 agent 工作树、mingjian 的构建产物）
- [x] 0.3.0（未发布，main 47b3763）：管道会话流控死锁修复（大文件双向传输卡住）、UDP 被封后重新接回直接走 TLS
- [ ] 观察：crossborder 下 UDP 中途被封 11.1 s 恢复，离 12 s 上限太近，WP-2 后再看能否更快发现死路
- [ ] 待定：`qsh-server stop` 后已连接的客户端退出码是 1（ssh 断开是 255），发 0.5.0 前统一核对退出码表

## 0.5.0 发布前加固（2026-10-06）

- [ ] 对抗性审查第二轮：网络侧（自写 zstd 解码器、SNAPSHOT 白名单、pacing、handoff 解析）+ 本地/特权侧（原地升级 exec、tune 以 root 运行、install 下载校验、状态文件）
- [ ] 第三方解析器 panic 隔离：release 改为 unwind + catch_unwind，画面模型或编解码出错只关掉这个会话的该功能，不拖垮 daemon
- [ ] 规范按 WP-2 实际实现修正（EL 规则、最小 RTT、路径速率、输入触发不受滞后、alt 屏、ruzstd 事实、快照被拒后的安全回退）
- [ ] 审查问题修完后：本地 `scripts/local-test.sh --chaos`（含 flood_interrupt、compression）、手动跑一轮完整 CI（macOS、长时间模糊测试、9 发行版、打包、混沌），全绿后公开仓库、发 0.5.0
- 本地/特权侧审查结果（待修，panic 隔离完成后统一修）：
  - [ ] H1 升级失败后对同一新程序反复自动重试，每次断开所有连接、新登录失败 → 失败的程序（dev, ino, 版本）记住并跨回退保留，自动升级不再重试，`--force` 仍可用
  - [ ] H3 `tune --root DIR` 混用宿主命令、不检查 root、完全信任 DIR 里的还原记录（可让 root 执行任意命令、写任意文件）→ 改为仅测试用的隐藏选项或禁用命令；还原记录白名单校验、属主/权限检查、O_NOFOLLOW
  - [ ] M1 升级可执行文件按路径检查又按路径执行（TOCTOU）→ 打开一次 fd，fstat 校验，检查父目录，execveat(AT_EMPTY_PATH)
  - [ ] M2 tune 把 0640 的防火墙规则文件抄进 0644 的记录、还原后权限变宽 → 记录 0600，还原原属主和权限
  - [ ] M3 回退在新程序解析参数、建运行时之后才武装 → 恢复参数版本化或放进加密状态，main 一开始就武装
  - [ ] L1 install 的 http 回退、远端 curl 无 --proto =https；DESIGN 承诺的签名还没有 → 只用 https；发版签名（minisign/cosign）进 0.5.0 或写明
  - [ ] L2 root 下命令走继承的 PATH；doctor --tune 用 sudo 跑用户可写的 qsh-server；ssh -t 缺转发关闭选项
  - [ ] L3 服务端文本（错误、doctor 报告、ls）原样进终端 → 统一过滤控制字符，doctor 输出限长
  - [ ] L4 预发布版本号按文本比较 → 按 semver 数字比较
  - [ ] L5 安装提示默认 Yes → 改为默认 No 或要求明确输入
- 网络侧审查结果（修复中）：
  - [ ] H1 未终止的 OSC 让 vt100 内部缓冲无限增长 → daemon OOM（`printf '\e]0;'; yes`）
  - [ ] H2 vt100 对 `CSI 65535 @/L/T` 计数不设上限 → 8 字节耗 1.45 s CPU，且持锁阻塞 tokio 线程 → 计数钳到屏幕大小、模型离开 async 路径和输出缓冲锁
  - [ ] M1 快照做不出时既没快照也没重绘；M2 输入触发的快照堆积；M3 缺口后在途字节算错；投递速率估计无时间下限；快照代价放大；客户端偏移未做溢出检查；PING 应答通道无界
  - [x] 自写 zstd 解码器：170 万次变异无崩溃、无炸弹，与 libzstd 逐字节一致
  - [x] SNAPSHOT 白名单与客户端组装：干净
- 0.5.0 候选（c9fc255）验证结果：本地 35/40、CI 部分失败 → 暂不发布，修复中：
  - [ ] Ctrl-C 刷屏中断未达 S3：CI 上 crossborder p50 0.9 s（目标 0.65）、lossy 2.2 s（0.72）、terrible p95 68 s（病态长尾）
  - [ ] port-fallback：crossborder 下记住的是主端口 TLS，而不是备用端口 QUIC
  - [ ] macOS：tune 假根目录测试里 firewalld 区域文件没写出来
  - [ ] 本地测试流程：忽略 fail2ban 动态集合；/tmp 下的测试目录被升级目录检查拒绝（CI 里通过）；nat ka 本地读不到
  - [ ] 打包：Debian testing / unstable 仓库 crate 构建因新依赖（vt100 0.16、ruzstd）失败 → 发行版构建的特性开关
  - [x] CI 通过：9 个发行版端到端、发版流水线试跑（6 平台 + 签名）、混沌里原地升级（0.0.1 → 0.5.0 同 pid）

## 0.5.0 发布（2026-10-07）

- [x] M2 完成，0.5.0 公开发布：https://github.com/yzfly/qsh/releases/tag/v0.5.0（15 个资产，SHA256SUMS 有 minisign 签名，构建来源证明可验证）；仓库已恢复公开
- [x] 发布关卡：本地 `scripts/local-test.sh --chaos` 40/40（每个网络条件 15 次），CI 全绿（Linux、macOS、MSRV、deny、9 个模糊测试目标、9 个发行版、打包、混沌、发版试跑）
- [x] 新用户实测：一行命令 `--require-signature` 安装，签名验证通过，版本 0.5.0
- [ ] 待用户处理：GitHub 账号 Actions 付款失败或超出支出上限（私有期间额度用完）；仓库公开后 Actions 免费，不影响后续
- [ ] 待用户决定的对外动作：AUR 上传、Homebrew tap、Debian ITP、Fedora 包审核（技术上已就绪：Fedora rawhide 和 Debian testing 均可只用官方仓库 crate 构建）
- [ ] 对比基准（qsh vs ssh vs mosh）写进 README 前，测量方法和措辞先给用户过目
- [ ] CI 上那一次「极差网络下首个提示符没出现」仍未复现，已加 -vv 日志和状态快照，下次出现即可定位
