# Full-Cone NAT TCP 穿透实验报告

## 实验环境

| 项目 | 详情 |
|------|------|
| NAT 类型 | Full Cone (完全锥形) |
| 公网 IPv4 | `120.37.185.53` |
| ISP | 中国电信 CHINANET (AS4134) |
| 内网地址 | `192.168.1.6` |
| STUN 服务器 | `stunserver2025.stunprotocol.org:3478` (TCP) |
| 外部测试机 | `82.156.246.57` (通过 SSH) |

## 核心发现

### 1. 端点无关映射 (Endpoint-Independent Mapping)

同一本地端口发起的多次 TCP 连接到不同目标，始终映射到**同一个公网端口**：

```
local:50000 -> STUN 连接1 -> public:6589
local:50000 -> STUN 连接2 -> public:6589  (相同!)
local:50000 -> STUN 连接3 -> public:6589  (相同!)
```

NAT 将 `(内网IP, 本地端口)` 映射到 `(公网IP, 公网端口)`，与远程目标无关。

> **注意：** NAT 不保留源端口号 (local port ≠ public port)，必须通过 STUN 发现真实的公网端口。

### 2. TCP 打洞后监听可行

STUN 打洞连接关闭后，可立即在同一端口上使用 `SO_REUSEADDR` 启动监听：

```python
s = socket()
s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
s.bind(('0.0.0.0', local_port))
s.listen(5)
```

外部主机可以连接到 `public_ip:public_port`，连接会被正确转发到内网监听端口。

**关键前提：** 打洞后必须在 NAT 映射超时前启动监听。该 NAT 的映射空闲超时约为 **5-8 秒**。

### 3. 外部主机直连验证

使用外部主机 `36.112.122.131`（与公网 IP 不同）成功通过 NAT 映射建立双向 TCP 通信：

```
外部主机: nc 120.37.185.53 6927
→ NAT 转发: 120.37.185.53:6927 → 192.168.1.6:50056
→ 本地中继: 127.0.0.1:19999 (echo server)
→ 响应返回: 127.0.0.1:19999 → 50056 → NAT → 外部主机
→ 外部主机收到: "NAT traversal works!"
```

这证明了 **任意外部主机均可通过该映射连接**，即完整的 Full Cone 行为。

### 4. Hairpin NAT 支持

从内部发起连接到自身公网 IP:端口可以正常工作：

```
内网机器 (192.168.1.6:44416) → 连接 120.37.185.53:7556
→ NAT 识别目标为自己的映射 → 转发回 192.168.1.6:50100
→ 内部监听端口收到连接，对端显示为 120.37.185.53:7557
```

### 5. 映射存活时间对比

#### 真实空闲超时

通过单次探针法（避免探针本身的回包刷新计时器）测得：

| 关闭方式 | t=3s | t=5s | t=8s |
|----------|------|------|------|
| FIN close | ALIVE | ALIVE | DEAD |
| RST close (SO_LINGER=0) | ALIVE | ALIVE | DEAD |

**结论：NAT TCP 映射空闲超时约为 5-8 秒。FIN 和 RST 关闭无差别。**

> 早前测得的 20-30s 是探针间隔测试的假象——每次探针连接时内网回包（SYN-ACK）作为出站流量刷新了计时器。

#### 保活方式对比

| 保活方式 | 存活时间 | 说明 |
|----------|---------|------|
| **无保活** | **~5-8s** | 无任何出站流量时 NAT 映射自然超时 |
| **Hairpin 保活** | **>300s (5分钟+)** | 内部回环的 hairpin 连接产生出站流量，持续刷新计时器 |

#### 快速销毁映射

测试了以下方法尝试**主动加速**映射销毁：

| 方法 | 结果 | 说明 |
|------|------|------|
| RST 关闭打洞连接 | ~5-8s | 与 FIN 无差别 |
| 外部连接 + 内部 RST 响应 | ~5-8s | 无加速效果 |
| 关闭监听端口（让内核回 RST） | ~5-8s | 无加速效果 |

**结论：无法快于 NAT 内置的空闲超时（~5-8s）销毁映射。** NAT 是独立设备，映射计时器只受出站流量刷新；无出站流量时只能等待自然过期。事实上 5-8s 已经够快，无需额外手段。

## Hairpin 保活机制

### 原理

```
1. STUN 打洞:
   local:PORT --TCP--> STUN server
   → 获得映射: PUBLIC_IP:PUBLIC_PORT

2. 启动监听:
   LISTEN on local:PORT (SO_REUSEADDR)

3. 建立 Hairpin 自连接:
   local:random_port --TCP--> PUBLIC_IP:PUBLIC_PORT
   → NAT 识别为目标映射，转发回 local:PORT
   → 内部建立双向 TCP 连接

4. 断开 STUN 连接:
   映射不再依赖 STUN

5. 心跳保活:
   通过 hairpin 连接定期发送 \x00 字节
   → NAT 检测到映射有活跃流量 → 持续刷新计时器

6. 外部连接:
   任意主机 --TCP--> PUBLIC_IP:PUBLIC_PORT → 正常转发！
```

### 与周期性重打洞对比

| 方案 | 优点 | 缺点 |
|------|------|------|
| **周期性 STUN 重打洞** | 不依赖 hairpin | 刷新时监听中断 (~0.1s)；依赖 STUN 服务器 |
| **Hairpin 保活** | 监听不中断；无外部依赖 | 需要 NAT 支持 hairpin |

## 实用工具

### nat_port_map.py — 公网端口映射

```bash
# 暴露本地 SSH (22) 到公网
python3 nat_port_map.py 2222 127.0.0.1:22

# 暴露本地 HTTP 服务
python3 nat_port_map.py 8080 127.0.0.1:80
```

**工作流程：**
1. 连接 STUN 服务器发现公网映射
2. 在同一本地端口启动 TCP 监听
3. 建立 hairpin 自连接进行保活
4. 将所有到达的 TCP 连接转发到目标服务

### STUN TCP 协议要点

```python
# 无需 TCP 帧头前缀，直接发送原始 STUN 消息
# 该特定服务器不支持 RFC 5389 Section 11.2 的 2 字节长度前缀

request = struct.pack('!HHI', 0x0001, 0, 0x2112A442) + os.urandom(12)
s.sendall(request)

# 读取响应 (20 字节头 + body)
header = s.recv(20)
msg_type, msg_length, magic = struct.unpack('!HHI', header[:8])
body = s.recv(msg_length)

# 解析 XOR-MAPPED-ADDRESS (type=0x0020)
x_port = body[pos+2:pos+4]
x_addr = body[pos+4:pos+8]
real_port = x_port ^ 0x2112
real_ip   = x_addr ^ 0x2112A442
```

## 限制与注意事项

1. **端口不保留：** 公网端口由 NAT 分配，与本地端口不同，必须通过 STUN 发现
2. **映射超时：** 无出站流量时约 5-8 秒过期，需 hairpin 保活或周期性重打洞维持（**注意：入站连接不刷新计时器，只有出站流量才行**）
3. **依赖 Hairpin：** 保活方案要求 NAT 支持 hairpin（自连接回环），并非所有 NAT 都支持
4. **TIME_WAIT 处理：** 打洞连接关闭后，需 `SO_REUSEADDR` 才能在 Linux 上立即重用端口
5. **STUN 服务器依赖：** 初始打洞依赖公共 STUN 服务器的可用性
6. **无法快速销毁：** 映射只能等自然超时，无法通过 RST 或其他手段从外部主动销毁

## 测试脚本

| 文件 | 用途 |
|------|------|
| `nat_test.py` | 基础 NAT 行为测试 (STUN, 监听, hairpin) |
| `external_test.py` | 外部主机连通性验证 |
| `lifetime_test.py` | 映射存活时间对比 (baseline vs hairpin) |
| `hairpin_longevity.py` | Hairpin 保活长期稳定性测试 |
| `rst_test.py` / `rst_test2.py` | RST vs FIN 关闭对比，映射空闲超时精确测量 |
| `rst_destroy_test.py` | 主动销毁映射可行性测试 |
| `nat_port_map.py` | 完整的公网端口映射工具 |
