# WEB_PLAN — 扩展打洞机制暴露本地 HTTPS Web 服务

状态：**已实现**（2026-07-30）。构建 0 警告，Rust 34 测试、JS 11 测试全过。

## 实现清单

- `vercel/api/index.js`：service 分键（`zt:endpoint:<service>`）+
  公开端点 `/api?cmd=web-config`（需 env `WEB_DOMAIN`）+ CORS
- `vercel/public/index.html`、`vercel/public/sw.js`：落地页 + SW
  （`/?bootstrap=1` 为引导逃生口；token 20s 主动刷新；502 时丢弃缓存配置）
- `crates/nat_sshd/src/gate.rs`：ban 逻辑抽为共享 `BanList`
- `crates/nat_sshd/src/gate_http.rs`：header gate（缓冲至 `\r\n\r\n`
  ≤16KB/3s，OPTIONS 直接应答，X-ZT-Gate 验证后剥头透传）+ 5 单测。
  **daemon 终结 TLS**（rustls，ALPN 限 http/1.1）：gate 头在 TLS 加密
  流内，TCP 层无法窥视，因此本地 app 改为 plain HTTP（TARGET）。
  非 TLS 探测（含 keepalive 的 ZTKEEPALIVE1）在握手阶段静默丢弃，
  不计 ban——TLS 服务对扫描器完全隐身。
- `crates/nat_sshd/src/ddns.rs`：CF A 记录更新（env：WEB_DOMAIN /
  CF_ZONE_ID / CF_RECORD_ID / CF_TOKEN(_FILE)）
- `crates/nat_sshd/src/main.rs`：SERVICE / GATE_MODE env 参数化，
  punch/repunch 时触发 DDNS（仅 IP 变化时）
- `crates/zt-common/src/types.rs`：EndpointRecord.service（默认 ssh）
- `deploy/ztunnel.nat-webd.service`：web 实例 systemd unit 模板

## 部署待办（用户侧）

1. Vercel 项目 env 加 `WEB_DOMAIN=test.cicuvc.top`，重新部署
2. 本地起 plain HTTP app（默认 TARGET=127.0.0.1:8080），无需 TLS/CORS
   （CORS 预检由 daemon 应答，但 app 响应仍需 `Access-Control-Allow-Origin: *`）
3. 确认 certbot 证书路径（默认 /etc/letsencrypt/live/$WEB_DOMAIN/），
   daemon 进程需有读权限（certbot privkey 默认 0600 root —— 用
   `setfacl` 或 deploy hook 复制授权）
4. CF 控制台拿 zone/record ID 填入 `deploy/ztunnel.nat-webd.service`，
   cf token 放 `~/.config/ztunnel/cf_token`（`Key: <token>` 格式）
5. `systemctl --user enable --now ztunnel.nat-webd`

## 已知限制

- SW 转发 `credentials: 'omit'`：后端 cookie 会话不可用；
  需要会话的 app 后续再扩展（ACA-Credentials + 非 * ACAO）
- 后端 302 跳绝对 URL（含后端域名）会把用户带离落地页域；app 应发相对跳转
- gate token 公开可得，仅防扫描器，非访问控制

---

# 原方案

目标：复用现有 STUN 打洞 + registry 体系，把本地 HTTPS web 服务器开放到
公网。落地页（Vercel 静态页 + Service Worker）拦截同源 fetch 并重写到
打洞后端，数据路径浏览器直连 NAT 主机（不经 Vercel 中转）。
research 参考：`cf_worker_sw.js`（CF Worker 版落地页）、`nat_backend.py`
（HTTPS 后端 + DNS 更新）。

## 已确认的决策

- DNS 留 Cloudflare（cf_auth.txt token），repunch 时自动更新 A 记录
- Web 端口加 **header gate**：SW 注入 `X-ZT-Gate: <window> <token>` 头，
  daemon 验证后剥头透传；直连探测静默丢弃
- gate token 由 registry 公开签发（`/api/web-config`），仅作扫描器隐身，
  非访问控制；真正认证由 web 应用自己负责
- 多服务 = nat_sshd 第二实例 + 参数化（SERVICE / GATE_MODE 环境变量）
- ~~TLS 由本地 web 服务器终结~~ **修正（2026-07-30 实测后）**：daemon
  终结 TLS——gate 头在 TLS 加密流内，TCP 层不可见；本地 app 只需
  plain HTTP。certbot 证书路径用 TLS_CERT/TLS_KEY 配置

## 技术约束（必须遵守）

- SW 注入自定义头触发 CORS 预检，浏览器预检 OPTIONS **不带**自定义头
  → daemon 必须自己应答 OPTIONS（204 + CORS 头），不透传
- HTTP/2 无法注入头 → header gate 模式下本地服务器 ALPN 限 `http/1.1`
- 本地 web 服务器响应需带 `Access-Control-Allow-Origin: *`（跨域）
- OPTIONS 应答带 `Access-Control-Max-Age: 86400` 让预检结果缓存

## 实施内容

### 1. Registry（vercel/）

- POST /api register：body 加 `service` 字段（默认 `ssh`，向后兼容），
  Edge Config key 改为 `zt:endpoint:<service>`
- 新增公开端点 `GET /api/web-config`（无认证）：
  `{ url, window, gate }`，服务端用 ZT_SECRET 现场签发当前 window 的
  gate token；web 服务未注册时 404
- 落地页静态文件：`vercel/public/index.html` + `vercel/public/sw.js`
  （移植 research/cf_worker_sw.js，`/_config` → `/api/web-config`）
- sw.js：install/activate 拉 web-config；fetch 拦截同源（排除 /sw.js、
  /api/*）重写到 backend 并注入 X-ZT-Gate 头；每 25s 或 502 时刷新
  web-config

### 2. nat_sshd 参数化

- 新 env：`SERVICE`（默认 ssh）、`GATE_MODE=line|header`（默认 line）
- `gate_http.rs`（header 模式）：
  1. 3s 内缓冲到 `\r\n\r\n`（上限 16KB）
  2. OPTIONS → 直接回 204 + CORS 头（ACAO:*, ACAM, ACAH:*, Max-Age）
  3. 找 `X-ZT-Gate: <w> <token>`（大小写不敏感）→ verify_synced 验证
     → 剥掉该头行，剩余字节原样写 target，进入 copy_bidirectional
  4. 失败 → 静默丢弃 + ban 计数（复用 gate.rs 逻辑）
- `ddns.rs`：punch 成功 / repunch mapping 变化时，若配置 WEB_DOMAIN +
  CF_ZONE_ID + CF_RECORD_ID，用 cf_auth.txt token 更新 A 记录（TTL 60）
  为当前公网 IP；SSH 实例不配置则跳过
- EndpointRecord 加 `service` 字段

### 3. 部署

- `nat-webd.service`（第二个 systemd user unit）：
  `SERVICE=web GATE_MODE=header LOCAL_PORT=8443 TARGET=127.0.0.1:8443`
  + WEB_DOMAIN/CF_* 变量
- 本地 HTTPS 服务器跑 8443（certbot 证书已有），加 CORS 头 +
  ALPN http/1.1 —— 用户侧，文档说明
- 落地页先用 Vercel 分配域，自定义域后续加

### 4. 实施顺序

1. registry：service 字段 + /api/web-config
2. nat_sshd：参数化 + gate_http.rs + ddns.rs + 单测
3. sw.js + index.html 移植
4. 实测：8443 HTTPS → 落地页 → SW 转发；repunch 后 A 记录 +
   web-config 更新 → SW 自动切换

### 不做

- 不迁 DNS、daemon 不终结 TLS、不做单 daemon 多 target、不上 KV
- OPTIONS 由 daemon 应答，不透传（浏览器硬约束）
