# GAP — 实现检查差距清单

首次检查：2026-07-30；复查：2026-07-30（第二轮）。
构建通过；Rust 23 测试、JS 11 golden 测试全过（跨语言 token 一致）。

## 已修复 ✓

- ~~GAP-2~~ 注册表持久化：改用 Edge Config（`vercel/api/index.js` edgeSet/edgeGet），
  冷启动可恢复；状态页不再泄露 endpoint（GAP-7 一并解决）。
  注：与架构决定的 Vercel KV 不同，但功能等价，接受。`deno/` 重复实现仍待清理。
- ~~GAP-3~~ keepalive 改发 `ZTKEEPALIVE1\n` 标记，gate 识别后静默关闭、不计失败；
  认证成功后清除失败计数；keepalive 间隔 20s → 3s（低于 5–8s NAT 超时，更稳）。
- ~~GAP-4~~ proxy 读方向超时已移除，SSH 空闲不再断线。
- ~~GAP-5~~ STUN：magic 严格校验、transaction ID 校验、循环读至响应完整。
- ~~GAP-9~~ known_hosts 改固定路径 + 0600 权限。

## 未修复

### GAP-1 [严重] 缺少 BRAS 重置恢复（状态机未实现）

AGENTS.md 约定的 `ACTIVE → SUSPECT → REPUNCH` 状态机仍没有实现。
`crates/nat_sshd/src/main.rs` 只在启动时 punch 一次；keepalive 失败后
无限重试且无人上报，没有组件触发重新 punch + 重新注册。
凌晨 ~02:00 BRAS reset 后服务会永久不可用。

修复方向：keepalive 连续失败 N 次（或注册循环收到 stale/失败信号）→
SUSPECT → STUN 重探测确认 mapping 变化 → 重新 punch → 立即重新注册；
listener 用 SO_REUSEADDR 可在同一 local port 存活。

### GAP-6 [严重] gate 时间偏移未生效 + token 重放洞

两层问题：

1. `Gate.time_offset`（`gate.rs:20`）存了但从未读取（编译警告证实），
   GAP-6 原修复未生效。
2. 更深：`token::verify` 是对**客户端自报的 window** ±1 验证。window
   由请求方控制，攻击者抓到任一 gate/discover token 后可携带原 window
   **永久重放**，±1 容差形同虚设。registry discover（`w` 参数）同样。
   register 无此问题（服务端用 `currentWindow()`）。

修复方向：验证方自己计算 `adjusted_window(time_offset)`，先检查
`|client_window - server_window| <= 1`，再做 HMAC 比对。registry
discover 同理（服务端 `currentWindow()` 与 `w` 比对）。

## 新引入的问题

### GAP-10 [中] edgeSet 未 await，serverless 下可能丢失写入

`vercel/api/index.js:104` 在 POST 响应前 fire-and-forget 调用
`edgeSet(...)`。Vercel Functions 在响应发出后可能冻结实例，未完成的
fetch 可能被丢弃，导致冷启动恢复失败。应 `await edgeSet(...)`
（或用 `waitUntil`）。

### GAP-11 [轻] discovery 重复 + 未使用变量

`ssh-nat/src/main.rs` 的 cmd_ssh 做了完整 discovery，但 `ip` 未使用
（只取 port 用于 `-p` 参数和 host_pubkey）；`proxy.rs::run` 又重新做
一次 discovery。每次连接两次 registry 请求。可精简为：main 只做一次
并把 ip/port 传给 gate-proxy 子命令（恢复原签名），或 main 不取 ip。
编译警告：`proxy.rs` `hostname` 参数未使用、`main.rs` `ip` 未使用。

## 轻微（未处理）

- GAP-8 `relay.rs` 死代码、`RegisterError::NoUrl/NoSecret` 未构造、
  zt-common `std::io::Read` unused import（编译警告仍在）。
- `deno/` 与 `vercel/` 双份注册表实现，需确定唯一部署目标并删除另一份。
