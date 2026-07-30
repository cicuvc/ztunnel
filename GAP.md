# GAP — 实现检查差距清单

首次检查：2026-07-30；第三轮复查：2026-07-30。
构建通过；Rust 23 测试、JS 11 golden 测试全过（跨语言 token 一致）。

## 已修复 ✓

- ~~GAP-2~~ 注册表持久化：Edge Config（edgeSet/edgeGet），冷启动可恢复；
  状态页不再泄露 endpoint（~~GAP-7~~ 一并解决）。
- ~~GAP-3~~ keepalive 改发 `ZTKEEPALIVE1` 标记，gate 静默关闭不计失败；
  成功清除计数；持久连接 + 周期写（出站流量刷新 mapping）。
- ~~GAP-4~~ proxy 读超时已移除。
- ~~GAP-5~~ STUN：magic 严格校验、tx id 校验、循环读完整。
- ~~GAP-6~~ gate 和 registry discover 改用服务端 window 校验
  （`verify_synced` / `verifySync`），重放洞关闭；gate 使用 time_offset。
- ~~GAP-9~~ known_hosts 固定路径 + 0600。
- ~~GAP-10~~ `edgeSet` 已 await。

## 未修复 / 新发现

### GAP-1a [严重] repunch 在 Linux 上必然失败（已实测）

`main.rs:143` repunch 在旧 listener 仍活动时调 `punch_and_listen`，
其内部 `bind(0.0.0.0:LOCAL_PORT)` 会 `EADDRINUSE`——SO_REUSEADDR
不允许在存在活跃 listener 时重复绑定同端口（已用 Python 在本机实测
确认）。repunch 每次都会走 "re-punch failed" 分支，BRAS 恢复失效。

修复方向：listener 与 STUN punch socket 都加 `set_reuseport(true)`
（Linux 要求所有相关 socket 都设置；repunch 中新建的第二个 listener
立即 drop，仅有极小的入站竞争窗口）；或 repunch 前先 drop 旧
listener（有服务空窗）。

### GAP-1b [严重] register_loop 用旧 endpoint 覆盖注册表

`main.rs:82` spawn 前把 `record.clone()` 交给 register_loop；repunch
更新的只是 main 的 `record` 并立即注册一次，但 ≤20s 后 register_loop
会把**旧的（已死的）endpoint** 写回注册表，且每 20s 持续覆盖，
BRAS 恢复白做。

修复方向：共享 record（`Arc<Mutex<EndpointRecord>>` 或
tokio watch channel），或 repunch 后重启 register_loop。

### GAP-12 [轻] keepalive reinforce 间隔在 spawn 时一次性求值

`main.rs:70,185` `in_reinforce_window()` 只在 spawn keepalive 时评估；
02:00 BRAS 窗口前启动的 keepalive 全程维持 3s 间隔，不会切到 1s。
（SUSPECT 阈值在 main 循环中是实时求值的，影响有限。）
修复方向：把 reinforce 判断移入 keepalive 循环内。

### GAP-13 [轻] 新增逻辑无测试

verify_synced、repunch 状态机、keepalive 信号路径均无测试，
测试总数仍是 23。建议至少补 verify_synced 的窗口新鲜度用例
（与 JS verifySync 对拍）。

## 轻微（历史遗留，未处理）

- GAP-8 `relay.rs` 死代码、`RegisterError::NoUrl/NoSecret` 未构造、
  zt-common `std::io::Read` unused import、`proxy.rs` `hostname`
  参数未使用（编译警告仍在）。
- GAP-11 ssh-nat discovery 重复（main 与 proxy 各做一次，`ip` 未用）。
- `deno/` 与 `vercel/` 双份注册表实现，需确定唯一部署目标。
