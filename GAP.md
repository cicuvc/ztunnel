# GAP — 实现检查差距清单

首次检查：2026-07-30；最终复查：2026-07-30（第五轮）。
构建 0 警告；Rust 29 测试、JS 11 golden 测试全过（跨语言 token 一致）。

## 已修复 ✓

- ~~GAP-1~~ BRAS 重置恢复：keepalive 信号驱动 SUSPECT → repunch → 立即
  重注册 + watch 同步 register_loop；reinforce 窗口（UTC 17:55–18:20）
  阈值 1、间隔 1s。
  - ~~GAP-1a~~ repunch 绑定冲突：先 drop 旧 listener 再 punch。
  - ~~GAP-1b~~ register_loop 改用 watch channel 共享 record。
  - 后续修复：listener 双重 punch 失败的 unwrap panic → accept 分支加
    守卫 + 独立重试分支 5s 退避（commit 9190674）。
- ~~GAP-2~~ 注册表持久化：Edge Config，冷启动可恢复；~~GAP-10~~ edgeSet
  已 await；~~GAP-7~~ 状态页不再泄露 endpoint。
- ~~GAP-3~~ keepalive 发 `ZTKEEPALIVE1` 标记，gate 不计失败、成功清零。
- ~~GAP-4~~ proxy 读超时移除。
- ~~GAP-5~~ STUN：magic 严格校验、tx id 校验、循环读完整。
- ~~GAP-6~~ gate / registry discover 用服务端 window 校验
  （verify_synced / verifySync），重放洞关闭。
- ~~GAP-9~~ known_hosts 固定路径 + 0600。
- ~~GAP-12~~ reinforce 间隔在 keepalive 循环内实时求值。
- ~~GAP-13~~ 新增测试（29 个）。
- keepalive 持久连接 vs gate 读单行即关的不匹配：gate 现循环读至 EOF。

## 轻微遗留（不阻塞，可选清理）

- GAP-8 已清零：`relay.rs` 已删除，`RegisterError` 无用变体、unused
  import 等编译警告全部处理（commit 7cd29a4，构建 0 警告）。
- GAP-11 ssh-nat discovery 重复（main 与 proxy 各一次），可精简。
- `deno/` 与 `vercel/` 双份注册表实现，需确定唯一部署目标后删一份。

## 待实测验证（代码无法覆盖）

- repunch 后 NAT 是否把新 mapping 的入站流量路由到新 listener
  （依赖 SO_REUSEADDR 语义，需真实 BRAS reset 或模拟验证）。
- Edge Config 写入的生效延迟对 20s 心跳节奏是否足够。
