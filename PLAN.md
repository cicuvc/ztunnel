# PLAN.md — ztunnel 实现计划

通过 Full Cone NAT (CGNAT) TCP 打洞向公网暴露本机 SSH，配合 Vercel
注册中心做端点发现，HMAC 时间窗令牌贯穿注册/发现/接入三层认证。

环境事实（已验证，见 `research/nat-traversal-report.md`）：

- Full Cone，映射端点无关，但公网端口不保留，必须 STUN 发现
- TCP 映射空闲超时 ~5–8s，仅出站流量刷新；hairpin 自连保活有效
- 电信 BRAS 每日 ~02:00 重置，映射全失效且公网 IP 可能变
- STUN 服务器 `stunserver2025.stunprotocol.org:3478` (TCP) 不用 RFC 5389
  §11.2 长度前缀，直接收发裸 STUN 消息

## 1. 架构设计

```
用户侧                     Vercel (Registry + KV)            本机 (Full Cone NAT 后)
─────────────────────────────────────────────────────────────────────────────────────
ssh-nat ──GET /api/endpoint (discover HMAC)──> endpoint.js ──GET──> KV
   │                                                    ▲ SET
   │                                              register.js ←──POST (register HMAC,
   │                                                              20s 心跳)────────┐
   │                                                                              │
   └─TCP ip:port──> "ZTGATE1 <window> <gate HMAC>" ───────────────> nat_sshd ──────┘
        验证通过 → 桥接 127.0.0.1:22，SSH 在同一连接上开始
        验证失败/3s 超时 → 立即断开，零 banner（扫描黑洞）
```

### 统一认证

- 一个 32 字节共享密钥，存于：本机 `~/.config/ztunnel/secret` (0600)、
  Vercel env `ZT_SECRET`、客户端同一路径
- 令牌：`hex(HMAC-SHA256(secret, "{purpose}:{window}"))` 截断前 32 hex 字符，
  `window = floor(unix_time / 30)`，验证容忍 ±1 窗口（≈60s 有效）
- purpose 域分离：`register` / `discover` / `gate`，跨用途重放无效
- Rust 与 Node 实现须用同一组测试向量交叉验证

### 错误恢复（BRAS 重置）

状态机：`ACTIVE → SUSPECT → REPUNCH → ACTIVE`

| 检测器 | 机制 | 延迟 |
|---|---|---|
| Hairpin 健康 | 保活连接走旧映射，重置后立即断裂；连续 3 次失败 → SUSPECT | ~10–30s |
| STUN 周期探测 | 每 60s 从同一本地端口重新打洞，比对 `(ip, port)` | ≤60s |
| 定时强化 | 01:55–02:20 窗口内探测加密到 10s（可配置） | ~10s |

REPUNCH：同一本地端口重新打洞（监听 socket 靠 `SO_REUSEADDR` 不中断）→
**立即**重新注册 → 重建 hairpin → ACTIVE。公网 IP 变化由 STUN 响应自然覆盖。
典型恢复 < 1 分钟。进行中的 SSH 会话不可存活（TCP 无法跨映射），靠客户端重连。

加固：

- STUN 服务器 failover 列表 + 指数退避（5s→5min）；全部不可达时注册
  `{status: "down"}`
- 若检测到 NAT 行为退化（同一本地端口对不同目标映射不同端口），日志报警
  并在注册信息标记 `nat_type_suspect: true`
- systemd user service `Restart=always` 兜底进程崩溃

## 2. 主要模块与文件

Cargo workspace + 一个 Node 子目录：

```
Cargo.toml                 workspace
crates/
  zt-common/               共享库：STUN 客户端、HMAC 时间窗令牌、endpoint 类型
    src/stun.rs            STUN TCP 打洞 + XOR-MAPPED-ADDRESS 解析
    src/token.rs           令牌生成/验证（三个 purpose）
    src/types.rs           EndpointRecord 等 serde 类型
  nat_sshd/                本机守护进程（binary）
    src/main.rs            状态机、线程/任务编排、日志
    src/punch.rs           打洞 + 周期探测（依赖 zt-common::stun）
    src/keepalive.rs       hairpin 自连保活 + 健康信号
    src/gate.rs            accept → 3s 内读首行 → 验 HMAC → 桥接 127.0.0.1:22
    src/register.rs        注册心跳 + 变更立即注册 + STUN failover
  ssh-nat/                 客户端 wrapper（binary）
    src/main.rs            拉 endpoint → 临时 known_hosts → exec ssh
    src/proxy.rs           `ssh-nat gate-proxy` 子命令：发 gate 令牌后 stdio 桥接
                           （作为 ssh ProxyCommand 使用）
vercel/
  api/register.js          POST；验 register HMAC；KV SET，无 TTL（靠 ts 判新鲜度）
  api/endpoint.js          GET；?w=&t= 验 discover HMAC；返回记录 + stale 标志
  api/index.js             状态页：online/stale + 最近心跳时间
  lib/auth.js              HMAC 时间窗验证（与 zt-common::token 对齐）
  lib/auth.test.mjs        Node 侧测试向量
  vercel.json
deploy/
  ztunnel.service          systemd user unit（Restart=always）
README.md                  部署与使用文档
```

依赖选型（Rust）：`tokio`（async 运行时）、`hmac`+`sha2`、`serde`+`serde_json`、
`reqwest`（注册心跳）、`tracing`（日志）、`clap`（ssh-nat CLI）。
Vercel functions 用 Node.js（官方支持运行时；共享逻辑仅 HMAC 验证，体量小）。

## 3. 接口交互

### 3.1 注册中心 HTTP API

`POST /api/register`（nat_sshd → Vercel，每 20s 心跳 + 映射变更时立即）

```
Authorization: Bearer <hex(HMAC(secret, "register:{window}"))[:32]>
Body: { "ip": "...", "port": 12345, "ts": 1722000000,
        "host_pubkey": "ssh-ed25519 AAAA...",
        "status": "active" | "down",
        "nat_type_suspect": false }
→ 200 { "ok": true } | 401 | 400
```

`GET /api/endpoint?w=<window>&t=<hex(HMAC(secret,"discover:{window}"))[:32]>`

```
→ 200 { "ip", "port", "ts", "host_pubkey", "status", "stale": bool }
  stale = (now - ts > 90s)
→ 401 HMAC 无效 | 404 从未注册
```

KV schema：key `zt:endpoint`，value 为上述 JSON（无 TTL，靠 ts 判定）。

### 3.2 Gate 协议（ssh-nat ↔ nat_sshd，TCP 明文首行）

- 客户端连接后首行发送：`ZTGATE1 <window> <hex(HMAC(secret,"gate:{window}"))[:32]>\r\n`
- 服务端 3s 内未收到合法行 → 关闭连接，不回任何字节
- 验证容忍 ±1 窗口；通过 → 立即桥接 `127.0.0.1:22`，后续字节直通（SSH 握手开始）
- 同一源 IP 连续 5 次失败 → 内存封禁 1h

### 3.3 客户端使用

```bash
ssh-nat user@mybox [ssh args...]        # 自动完成发现 + gate + host key 校验
scp/sftp/rsync 经由 ssh-nat --print-ssh 输出底层 ssh 命令串复用
```

ssh-nat 内部流程：

1. 计算 discover HMAC → GET endpoint；`stale` 或 `status=down` 时警告，
   `-f` 才继续
2. 写临时 known_hosts：`mybox ssh-ed25519 <host_pubkey>`
3. `exec ssh -o ProxyCommand="ssh-nat gate-proxy <ip> <port>" \
   -o HostKeyAlias=mybox -o UserKnownHostsFile=<tmp> \
   -o StrictHostKeyChecking=yes -p <port> user@<ip> [args]`
4. gate 连接被拒时自动重新拉取 endpoint 重试一次（竞态覆盖）

### 3.4 配置/密钥分发

- 密钥生成：`openssl rand -hex 32`
- 本机/客户端：`~/.config/ztunnel/secret`（0600）；可选配置文件
  `~/.config/ztunnel/config.toml`（registry URL、本地端口默认 2222、
  STUN 服务器列表、强化窗口）
- Vercel：`ZT_SECRET`（`vercel env add`）；`KV_REST_API_URL` /
  `KV_REST_API_TOKEN`（KV 集成自动注入）

## 4. 实现阶段与完成 criteria

### Phase 1 — Rust 核心与打洞守护进程骨架

范围：`zt-common`（stun、token）+ `nat_sshd` 的 punch/listen/hairpin/relay
（无 gate、无注册）。

- [ ] STUN 打洞能发现公网映射（真实服务器实测）
- [ ] 同端口监听 + hairpin 保活，外部机器可连入并中继到本地 echo 服务
- [ ] 保活 30 分钟映射不失效（对照 research 报告的 hairpin 结果）
- [ ] token 模块单元测试通过

### Phase 2 — Vercel 注册中心

范围：`vercel/` 全部 + `nat_sshd::register`。

- [ ] KV 创建，functions 部署到生产
- [ ] Node/Rust HMAC 测试向量交叉一致
- [ ] curl 伪造 register/discover 请求：合法通过、过期/错 purpose 401
- [ ] nat_sshd 心跳注册，`GET /api/endpoint` 返回实时端点；停掉 daemon
      90s 后 `stale: true`

### Phase 3 — Gate 与客户端

范围：`nat_sshd::gate` + `ssh-nat` + `ssh-nat gate-proxy`。

- [ ] 无令牌/错令牌/过期令牌连接被静默断开（nc 测试，无任何回包）
- [ ] 正确令牌后完成真实 ssh 登录；连续 5 次错令牌触发 IP 封禁
- [ ] `ssh-nat user@host` 一键登录；host key 被篡改时连接被拒绝
- [ ] scp 经 ssh-nat 传输文件成功

### Phase 4 — 恢复、加固与交付

范围：状态机完整化、STUN failover、systemd unit、README。

- [ ] 模拟映射失效（kill hairpin + 阻断旧映射）：60s 内自动重打洞并更新
      注册，客户端重连成功
- [ ] 01:55–02:20 强化窗口生效（日志可见探测加密）
- [ ] systemd 启动后无人值守运行 24h，跨 BRAS 重置自动恢复
- [ ] README 覆盖：KV 创建、env 配置、密钥分发、sshd 加固 checklist
      （`PasswordAuthentication no` 等，由用户手动执行）

## 5. 测试计划

### 单元测试（`cargo test`）

- `token.rs`：固定密钥 + 固定时间的黄金测试向量（同时被
  `vercel/lib/auth.test.mjs` 消费，保证跨语言一致）；±1 窗口边界；
  purpose 混淆拒绝；截断长度
- `stun.rs`：XOR-MAPPED-ADDRESS 解析（用 research 中抓包的真实响应字节做
  fixture）；畸形/截断响应返回错误而非 panic
- `types.rs`：endpoint JSON 序列化/反序列化 round-trip

### 集成测试

- 本地端到端：启动 nat_sshd（注册指向 mock registry）→ 本机经 hairpin
  自连走完整 gate + ssh 链路
- Gate 行为矩阵：正确/错误/过期/无令牌/超时各 case 的连接结果断言
- 注册心跳：mock registry 断言 20s 间隔与变更立即注册
- 恢复：注入"探测结果变化"→ 断言状态机迁移与新注册请求

### 实测验收（手动，需外部机器）

- 外部主机 `nc <public_ip> <port>`：无令牌零回包；`ssh-nat` 登录成功
- 30 分钟保活期间多次连接
- BRAS 重置（或等待凌晨实测 / 重启光猫模拟）后 1 分钟内端点自动更新、
  重连成功

### 安全 checklist

- [ ] 密钥不出现在日志（tracing 输出审查）
- [ ] `secret` 文件权限 0600 校验，不合规时拒绝启动
- [ ] Vercel env 不含明文密钥以外的敏感信息；KV token 最小权限
- [ ] gate 无错误信息泄漏（不区分"无令牌"与"错令牌"的响应）
