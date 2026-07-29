# GAP — 实现检查差距清单

检查日期：2026-07-30
状态：构建通过；Rust 22 测试、JS 11 golden 测试全过（跨语言 token 一致）。

## 严重（功能性）

### GAP-1 缺少 BRAS 重置恢复（状态机未实现）

AGENTS.md 约定的 `ACTIVE → SUSPECT → REPUNCH` 状态机没有实现。
`crates/nat_sshd/src/main.rs` 只在启动时 punch 一次；keepalive 失败后
无限重试（`keepalive.rs`），没有任何组件触发重新 punch + 重新注册。
凌晨 ~02:00 BRAS reset 后服务会永久不可用（systemd Restart=always
救不了，因为进程本身不会退出）。

修复方向：keepalive 连续失败 N 次 / STUN 重探测 mapping 变化 → 进入
SUSPECT → 重新 punch → 立即重新注册。

### GAP-2 注册表用内存存储，未用 Vercel KV

架构决定存储用 Vercel KV (Upstash Redis)，但 `vercel/api/index.js:7`
用模块级变量 `_endpoint`。Serverless 冷启动 / 多实例下 POST 和 GET
可能落在不同实例，endpoint 记录会丢。`deno/main.ts` 同样问题。

另：`deno/` 与 `vercel/` 是两份重复注册表实现，需确定部署目标
（Vercel Functions + KV，还是 Deno Deploy + Deno KV），删掉另一份。

### GAP-3 hairpin keepalive 触发 gate 自我封禁

keepalive 连接自己的公网地址、发 `\x00` 后立即断开
（`keepalive.rs:36-39`）。gate 视为认证失败并计数
（`gate.rs:120-127`），且失败计数**永不衰减**。约 100 秒后
（5 次 × 20s）自己的公网 IP 被 ban 1 小时，日志刷屏，ban 表被自身
流量永久触发。功能上 keepalive 仍有效（出站 SYN 刷新 mapping），
但属设计缺陷。

修复方向：keepalive 发送专用标记行（如 `ZTKEEPALIVE1\n`），gate
识别后静默关闭且不计入失败；同时失败计数应随时间衰减/成功时清零。

## 中等

### GAP-4 SSH 会话空闲 30 秒即断开

`crates/ssh-nat/src/proxy.rs:17` 设了 30s 读超时，`:34` 对任何
`Err(_)` 直接 break。SSH 空闲 30 秒代理线程退出，连接被切。
修复方向：读方向不设超时（阻塞读），或区分 `TimedOut` 后 continue。

### GAP-5 STUN 解析健壮性

- `crates/zt-common/src/stun.rs:135` 单次 `read()` 可能只读到部分
  响应，应循环读至 header + msg_len 完整。
- `stun.rs:69` magic 校验用 `&&`：msg_type 为 0x0101 时 magic 错误
  也能通过。应为严格校验。
- 未校验响应 transaction ID 与请求一致。

### GAP-6 gate 验 token 未用时间偏移

`RegistryClient::sync_time` 算出的 `time_offset` 只用于 register；
`Gate::new`（`main.rs:58`）用本机时钟验证 gate token。主机时钟与
registry 偏差 > ~60s 时合法客户端会被拒。
修复方向：把 offset 传入 Gate，验证时用调整后窗口。

### GAP-7 状态页无认证泄露 endpoint

`GET /api` 无参数时返回 HTML，公开显示 endpoint IP:port
（`vercel/api/index.js:112`）。任何访客可见。建议隐藏 endpoint
或要求 discover token。

## 轻微

### GAP-8 死代码 / 未使用项

- `crates/nat_sshd/src/relay.rs` 的 `spawn_relay` 从未调用
  （gate 内联了同样的 copy_bidirectional 逻辑）——删除或改用。
- `RegisterError::NoUrl` / `NoSecret` 变体从未构造。

### GAP-9 客户端临时 known_hosts 堆积

`crates/ssh-nat/src/main.rs:139` 每次运行创建
`/tmp/ssh_nat_known_hosts_<pid>` 且不清理。建议用完删除或复用
固定路径 + 0600 权限。
