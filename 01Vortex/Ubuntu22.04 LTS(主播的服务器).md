# 端口自定义
## 出网端口2000-2099
### 系统(2000-2019)
- 2000 ssh
- 2001 bt
- 2003 vnc
- 2004 vpn

### Web(2020-2059)
- 2020 source
- 2021 busuanzi
- 2022 ddns



### DockerWeb(2060-2099)
- 2060 twikoo
- 2061 grafana
- 2062 cloudreve


## 本地端口2100-2199
### 系统(2100-2119)
- 2100 redis
- 2101 
- 2102 vpn
- 2103 ddns
- 2104 open

### 普通应用(2120-2149)
- 2121 busuanzi

### Docker应用(2160-2199)
- 2160 twikoo
- 2161 grafana
- 2162 cloudreve



# 常用命令
# SSH远程连接
## SSH 服务端管理（在服务器上）

### 1. 安装 OpenSSH 服务端
```bash
sudo apt update
sudo apt install openssh-server
```

### 2. 启动/停止/重启 SSH 服务
```bash
sudo systemctl start ssh
sudo systemctl stop ssh
sudo systemctl restart ssh
sudo systemctl status ssh
```

### 3. 设置开机自启
```bash
sudo systemctl enable ssh
```

### 4. 配置 SSH（主要配置文件）
```bash
sudo nano /etc/ssh/sshd_config
```
常用配置项：
- `Port 22` → 修改端口（如 `Port 2222`）
- `PermitRootLogin no` → 禁止 root 登录（推荐）
- `PasswordAuthentication yes/no` → 是否允许密码登录
- `PubkeyAuthentication yes` → 允许公钥认证
- `AllowUsers user1 user2` → 仅允许指定用户登录

> 修改后需重启服务：
```bash
sudo systemctl restart ssh
```

### 5. 查看 SSH 服务监听端口
```bash
ss -tulnp | grep ssh
# 或
sudo netstat -tulnp | grep :22
```

---

## SSH 客户端常用命令
>**推荐使用`MobaXterm`**
### 1. 基本连接
```bash
ssh username@remote_host
# 示例：
ssh user@192.168.1.100
ssh ubuntu@example.com
```

### 2. 指定端口（默认端口为 22）
```bash
ssh -p 端口号 username@remote_host
# 示例：
ssh -p 2222 user@192.168.1.100
```

### 3. 使用私钥登录（推荐更安全的方式）
```bash
ssh -i /path/to/private_key username@remote_host
# 示例：
ssh -i ~/.ssh/id_rsa user@192.168.1.100
```

### 4. 执行远程命令（不进入交互式 shell）
```bash
ssh user@host 'command'
# 示例：
ssh user@192.168.1.100 'ls -l /home'
```

### 5. 启用 X11 转发（图形界面应用）
```bash
ssh -X user@host
```

### 6. 后台保持连接（配合 `tmux` 或 `screen` 更佳）
```bash
ssh -f -N -L 本地端口:目标主机:目标端口 user@gateway
# 示例：本地 8080 转发到远程内网 192.168.1.50:80
ssh -f -N -L 8080:192.168.1.50:80 user@gateway
```

---


## 密钥管理（免密登录）

### 1. 生成 SSH 密钥对（本地执行）
```bash
ssh-keygen -t ed25519
# 默认保存在 ~/.ssh/id_ed25519（私钥）和 ~/.ssh/id_ed25519.pub（公钥）
```
>Ed25519是一种高效的椭圆曲线签名算法

### 2. 将公钥上传到远程服务器
将本地的 SSH 公钥（`id_ed25519.pub`）安全地复制到远程主机的 `~/.ssh/authorized_keys` 文件中
```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@remote_host
```
>一键安全配置免密登录

### 3. 设置正确权限（重要！）
在远程服务器上执行：
```bash
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

---

## 常见问题

- **连接被拒绝**：检查 SSH 服务是否运行、防火墙是否放行端口（如 `ufw allow 22`）
- **权限太开放**：私钥文件权限应为 `600`（`chmod 600 ~/.ssh/id_rsa`）
- **日志查看**：
  ```bash
  sudo journalctl -u ssh
  # 或
  sudo tail -f /var/log/auth.log
  ```
>如需进一步优化安全性，可考虑：
- 禁用密码登录，仅用密钥
- 更改默认端口
- 使用 Fail2ban 防暴力破解
- 限制登录用户/IP
- 禁用根用户的直接登录


# VNC访问图形桌面
**VNC over SSH 隧道** 是一种安全地远程访问图形桌面的方式。它通过 SSH 隧道加密 VNC（Virtual Network Computing）流量，防止明文传输带来的安全风险
>VNC 默认**不加密**，密码和画面可能被窃听。
   SSH 隧道提供**端到端加密**，即使 VNC 服务本身不安全，也能保障通信安全。
   可绕过防火墙限制（只需开放 SSH 端口，如 22）。

**基本原理:**
本地机器（Client） ↔ **SSH 隧道（加密）** ↔ 远程服务器（VNC Server）
- 你在本地连接 `localhost:5901`
- SSH 将该连接**安全转发**到远程服务器的 `localhost:5901`（即 VNC 服务）
- VNC 服务只监听本地（127.0.0.1），不对外暴露，更安全

## 远程服务器已安装并运行 VNC 服务

例如使用 `tigervnc-standalone-server`：

```bash
# 安装 TigerVNC
sudo apt update
sudo apt install tigervnc-standalone-server
```

```
# 设置 VNC 密码（会生成 ~/.vnc/passwd）
vncpasswd
```


- 创建 VNC 启动配置
```
vim ~/.vnc/xstartup
```

``` shell
#!/bin/bash
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
exec startxfce4
```
>`startxfce4` 是 XFCE 的标准启动命令，兼容性极佳。
>> GNOME 在 VNC 下容易因 Wayland、会话管理、依赖缺失等问题失败，XFCE 是远程桌面的黄金标准。

 ==XFCE 只是“安装在系统里”，默认不会启动或替换主桌面 GNOME。只有当你通过 VNC 启动桌面时，才由 `~/.vnc/xstartup` 决定用哪个桌面环境。==

- 赋予执行权限
```
chmod +x ~/.vnc/xstartup
```

- 启动 VNC（仅监听本地，提高安全性）
```
vncserver -localhost -rfbport 5901 -geometry 1366x768 -depth 16
```

>**仅绑定到 `127.0.0.1`（localhost）**；
   **监听 TCP 端口 `5901`**(可自定义)；
   提供分辨率为 `1366x768` 的虚拟桌面(提高流畅度)；
   使用 16 位色深以平衡画质与性能；


## 使用MobaXterm连接(推荐)
- #### 添加本地端口转发
```
Local port: 5901 
Remote server: localhost 
Remote port: 5901
```
>这样就把服务器的 5901 端口通过 SSH 隧道映射到本地的 5901。

- #### 使用 MobaXterm 内置 VNC 客户端连接
1. SSH 连接成功后，在 MobaXterm 左侧边栏找到 “VNC” 图标（或顶部菜单 Tools → VNC Viewer）
2. 在 VNC 连接地址输入：
```
localhost:5901
```
3. 点击连接，输入之前设置的 VNC 密码
## 使用命令行连接
### 在本地后台运行 SSH 隧道

在你的**本地电脑**（Linux/macOS/WSL）执行：

```bash
ssh -fN -L 2000:localhost:5901 user@remote_host
```

- `-f`：后台运行
- `-N`：不执行远程命令（仅端口转发）
- `-L [本地端口]:[目标主机]:[目标端口]`(将本地 `2000` 端口 → 转发到远程服务器的 `localhost:5901`)

> 注意：首次连接需手动确认指纹，或加 `-o StrictHostKeyChecking=no`（不推荐生产环境）


---

### 用 VNC 客户端连接本地端口

打开 VNC Viewer（如 MobaXterm 等），连接：

```
localhost:5901
```

或

```
127.0.0.1:1   （有些客户端用 display number，:1 表示 5901）
```

输入你在 `vncpasswd` 中设置的密码即可登录。

---

## 设置 VNC 服务开机自启

创建 systemd 服务文件：
```
sudo vim /etc/systemd/system/vncserver@.service
```

内容：
```shell
[Unit] 
Description=Remote desktop service (VNC) 
After=syslog.target network.target 

[Service] 
Type=simple User=你的用户名 WorkingDirectory=/home/你的用户名 ExecStartPre=/bin/sh -c '/usr/bin/vncserver -kill %i > /dev/null 2>&1 || :' ExecStart=/usr/bin/vncserver %i -geometry 1920x1080 -depth 16 ExecStop=/usr/bin/vncserver -kill %i

[Install] 
WantedBy=multi-user.target
```

启用服务：
```shell
sudo systemctl daemon-reload 
sudo systemctl enable vncserver@:1.service 
sudo systemctl start vncserver@:1
```


## 其他
### 安全建议

1. **VNC 服务务必加 `-localhost`**，禁止外网直连。
2. **禁用 VNC 的默认用户/弱密码**，使用强密码。
3. **SSH 使用密钥登录**，禁用密码（`PasswordAuthentication no`）。
4. 考虑用 `systemd` 管理 VNC 服务，开机自启（可选）。

### VNC 卡顿主要原因

|原因|说明|
|---|---|
|1. 色彩深度太高|`-depth 24` → 改为 `-depth 16` 可大幅减少数据量|
|2. 分辨率太高|`1920x1080` 对带宽要求高 → 可适当降低|
|3. 未启用压缩|TigerVNC 支持图像压缩，需手动开启|
|4. 桌面特效未关闭|XFCE/GNOME 的动画、阴影、透明效果加重负担|
|5. 网络延迟/带宽不足|尤其跨公网、WiFi、公司网络等|
|6. 服务器性能不足|CPU/内存占用高，渲染慢|

# WireGuard VPN
## 简介
WireGuard 是一种现代、高性能、轻量级的虚拟私有网络（VPN）协议，旨在提供比传统 VPN（如 IPsec 或 OpenVPN）更简单、更安全、更快速的网络隧道解决方案。
### 主要特点：

1. **简洁性**  
    WireGuard 的代码库非常小（约4000行 C 代码），远少于 IPsec（数十万行）或 OpenVPN（数万行）。这使得它更容易审计、维护和减少潜在的安全漏洞。
    
2. **安全性**  
    使用经过广泛审查的现代加密算法，包括：
    
    - **Curve25519** 用于密钥交换
    - **ChaCha20** 用于对称加密
    - **Poly1305** 用于数据认证
    - **BLAKE2s** 用于哈希
    - **HKDF** 用于密钥派生  
        所有这些都属于“加密敏捷性”之外的“加密固定”设计，避免了复杂配置带来的安全风险。
3. **高性能**  
    WireGuard 在内核层面实现（Linux 原生支持），延迟低、吞吐量高，特别适合移动设备和资源受限的环境。
    
4. **连接保持**  
    WireGuard 使用“漫游”机制：即使客户端 IP 地址发生变化（比如从 Wi-Fi 切换到蜂窝网络），连接也能自动保持，无需重新握手。
    
5. **配置简单**  
    配置文件通常只有几行，使用类似 SSH 的公钥/私钥认证方式，无需复杂的证书体系。
    

### 基本工作原理：

- 每个对等端（peer）拥有一对公私钥。
- 通过配置文件指定允许的 IP 范围、公钥、端点地址（endpoint）等。
- 数据通过 UDP 传输，默认端口为 51820。
- 通信双方通过公钥验证身份，并建立加密隧道。

#### 🌐 拓扑结构总览

```
+------------------+       (公网 Internet)        +----------------------------+
|                  |  UDP 51820 (加密 WireGuard) |                            |
|   远程客户端     | <--------------------------> |      WireGuard 服务器      |
| (你的电脑/手机)  |                             | (UbuntuServer, 公网可达)   |
|                  |                             |                            |
| 虚拟IP: 10.8.8.2 |                             | 虚拟IP: 10.8.8.1           |
|                  |                             | 物理IP: 192.168.1.141      |
+------------------+                             +----------------------------+
                                                         |
                                                         | (局域网 LAN)
                                                         | eno2 接口
                                                         v
                                          +------------------------------+
                                          |      局域网目标服务设备      |
                                          |  IP: 192.168.1.120           |
                                          |  服务端口: 如 9870、80、22 等 |
                                          +------------------------------+
```

---


### 其他
#### 应用场景：

- 远程办公安全接入公司内网
- 保护公共 Wi-Fi 上的通信
- 跨地域服务器之间的安全互联
- 移动设备安全连接

#### 支持平台：

- Linux（内核 5.6+ 原生集成）
- Windows、macOS、iOS、Android（官方或社区客户端）
- 路由器（如 OpenWrt）
- 云平台（AWS、Azure 等）

#### 与传统 VPN 对比：

|特性|WireGuard|OpenVPN|IPsec|
|---|---|---|---|
|代码复杂度|极低|高|非常高|
|加密算法|现代、固定|可配置、较旧|可配置、复杂|
|性能|高|中等|中等至高|
|配置难度|简单|中等|复杂|
|移动支持|优秀|一般|一般|

---

WireGuard 于 2020 年正式合并进 Linux 内核主线，现已成为许多企业和个人首选的 VPN 解决方案。因其简洁、安全、高效，被广泛认为是下一代 VPN 协议的标准。

## 安装并配置
### 1.安装 WireGuard

```bash
sudo apt update && sudo apt install wireguard resolvconf
```

---

### 2. 生成密钥对

```bash
cd /etc/wireguard
umask 077
wg genkey | tee privatekey | wg pubkey > publickey
```

>需要修改wireguard文件夹的权限才能进,生成的公私钥均位于/wireguard下
---

### 3. 服务器配置 /etc/wireguard/wg0.conf

```
[Interface]
Address = 10.8.8.1/24   #服务端虚拟网卡ip
PrivateKey =            #服务器私钥
ListenPort = 51820      
    
#允许转发到局域网 
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey =    #客户端公钥
AllowedIPs = 10.8.8.2/32 #只填客户端虚拟ip
```

---

### 4. 端口与转发

- 放行 51820/==udp ==端口

```bash
  sudo ufw allow 51820/udp
```
    
- 启用 IPv4转发并永久生效

 ```bash
  echo 'net.ipv4.ip_forward = 1' | sudo tee -a /etc/sysctl.conf
  sudo sysctl -p /etc/sysctl.conf
```


---

### 5. 启动 WireGuard

```bash
sudo wg-quick up wg0
```

### 6.WireGuard常用命令

#### 1. 启动/停止 WireGuard 接口（临时）

```bash
# 启动 wg0
sudo wg-quick up wg0

# 停止 wg0
sudo wg-quick down wg0
```

> 配置文件路径：`/etc/wireguard/wg0.conf`


#### 2. 查看接口状态

```bash
# 查看所有 WireGuard 接口状态（推荐）
sudo wg show

# 查看特定接口
sudo wg show wg0

# 查看网络接口（确认 wg0 是否存在）
ip a show wg0
```


#### 3. 启用开机自启 + 立即启动

```bash
sudo systemctl enable --now wg-quick@wg0.service
```

#### 4. 停止并禁用开机自启

```bash
sudo systemctl disable --now wg-quick@wg0.service
```

#### 5. 查看服务状态

```bash
systemctl status wg-quick@wg0.service
```

#### 6. 查看服务日志

```bash
journalctl -u wg-quick@wg0.service -f
```


#### 7. 生成密钥对（服务端 & 客户端都需要）

```bash
# 生成私钥
wg genkey > privatekey

# 由私钥生成公钥
wg pubkey < privatekey > publickey

# 一行生成（推荐）
umask 077 && wg genkey | tee privatekey | wg pubkey > publickey
```

> 🔐 **权限建议**：私钥文件权限应为 `600`（`chmod 600 privatekey`）

---

#### 8. 配置文件路径规范

- 接口名 `wg0` → 配置文件：`/etc/wireguard/wg0.conf`
- 文件权限必须为 `600`：

```bash
   sudo chmod 600 /etc/wireguard/wg0.conf
   ```


#### 9. 查看路由是否生效

```bash
# 检查到目标 IP 的路由路径
ip route get 10.8.8.1
ip route get 192.168.1.120
```

#### 10. 手动添加/删除路由（调试用）

```bash
# 添加路由（通常不需要，wg-quick 自动处理）
sudo ip route add 192.168.1.120/32 dev wg0

# 删除路由
sudo ip route del 192.168.1.120/32 dev wg0
```

---

#### 11. 抓包调试（确认流量是否加密）

```bash
# 抓公网接口（看加密流量）
sudo tcpdump -i eth0 udp port 51820 -n

# 抓 wg0 接口（看明文流量）
sudo tcpdump -i wg0 -n
```

---


#### 12. 启用 IP 转发（必须！）

```bash
# 临时生效
sudo sysctl net.ipv4.ip_forward=1

# 永久生效
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

#### 13. 防火墙规则（以 iptables 为例）

```bash
# 允许转发
sudo iptables -A FORWARD -i wg0 -j ACCEPT
sudo iptables -A FORWARD -o wg0 -j ACCEPT

# NAT（让客户端访问内网）
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# 保存规则（Ubuntu/Debian）
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

> 💡 替代方案：使用 `nftables` 或 `ufw`（需额外配置）。


#### 14. 查看当前连接的 Peer（是否有握手）

```bash
sudo wg show wg0 latest-handshakes
```

#### 15. 重新加载配置（无需重启）

```bash
# 先 down 再 up（最可靠）
sudo wg-quick down wg0 && sudo wg-quick up wg0

# 或使用 wg 命令动态更新（高级用法）
sudo wg set wg0 peer <pubkey> allowed-ips "10.8.8.2/32"
```

#### 16. 测试连通性

```bash
# ping 服务端虚拟 IP
ping 10.8.8.1

# 访问内网服务
curl http://192.168.1.120:9870
```

---

#### 常见问题排查

| 问题                                           | 检查点                                     |     |
| -------------------------------------------- | --------------------------------------- | --- |
| 无法连接                                         | `Endpoint` 是否正确？防火墙是否放行 UDP 51820？      |     |
| 能连但无法访问内网                                    | 服务端是否开启 `ip_forward`？iptables 是否配置 NAT？ |     |
| `RTNETLINK answers: Operation not permitted` | 配置文件权限是否为 `600`？是否用 `sudo`？             |     |
| 客户端无流量                                       | `AllowedIPs` 是否包含目标网段？路由是否生效？           |     |
| 192.168.1.120有服务却不可用                         | 查看ip是在eth0还是eno2                        |     |





### 7.设置开机自启(可选)
```bash
sudo systemctl enable wg-quick@wg0.service
```
>关闭 sudo systemctl disable wg-quick@wg0.service
#### 关于systemd 服务
在设置了 `systemctl enable wg-quick@wg0.service` 之后，**推荐始终通过 systemd 服务来管理 WireGuard 接口的启停**，而不是直接使用 `wg-quick up/down`。

---
#####  **推荐做法：统一使用 systemd 服务管理**

```bash
# 启动
sudo systemctl start wg-quick@wg0.service

# 停止
sudo systemctl stop wg-quick@wg0.service

# 重启
sudo systemctl restart wg-quick@wg0.service

# 查看状态
sudo systemctl status wg-quick@wg0.service
```

---

##### 为什么推荐用服务而不是 `wg-quick`？

|原因|说明|
|---|---|
|**1. 状态一致性**|如果你用 `wg-quick up` 启动，但 systemd 认为服务是“未启动”的，会导致状态混乱。例如：`systemctl status` 显示未运行，但实际上接口已存在。|
|**2. 依赖管理**|systemd 可以正确处理网络、防火墙、路由等依赖（通过 `After=network.target` 等），而 `wg-quick` 是裸命令，可能在网络未就绪时失败。|
|**3. 日志集成**|服务的日志可通过 `journalctl -u wg-quick@wg0` 查看，便于排错；而 `wg-quick` 的输出是临时的。|
|**4. 自动恢复**|可配置 `Restart=` 策略（虽然默认没有），在异常退出时尝试恢复（需自定义 service 文件）。|
|**5. 权限与环境统一**|systemd 以标准方式运行，避免手动执行时环境变量、路径或权限差异导致的问题。|

---

#####  混用的风险示例

假设你已经启用了服务：

```bash
sudo systemctl enable wg-quick@wg0.service
```

然后你手动执行：

```bash
sudo wg-quick down wg0
```

此时：

- 接口被删除了；
- 但 systemd 仍然认为服务是“active (exited)”或“failed”；
- 如果你再执行 `systemctl start wg-quick@wg0`，可能会报错（比如“RTNETLINK answers: File exists”），因为某些路由或规则残留。

反之亦然：用 `wg-quick up` 启动后，再用 `systemctl stop` 去停，可能无法完全清理资源。

---

##### 特殊情况：调试时可用 `wg-quick`

在**调试配置文件**阶段，可以临时用 `wg-quick up/down` 快速测试：

```bash
sudo wg-quick up wg0      # 测试配置是否有效
sudo wg-quick down wg0    # 快速关闭
```

但一旦配置确认无误，**正式使用时应切换到 systemd 管理**，并避免混用。

---

##### 最佳实践总结

|场景|推荐命令|
|---|---|
|首次测试配置|`wg-quick up wg0` / `down`|
|正式部署、日常启停|`systemctl start/stop/status wg-quick@wg0.service`|
|设置开机自启|`systemctl enable wg-quick@wg0.service`|
|禁用自启 + 停止|`systemctl disable --now wg-quick@wg0.service`|



---

### 8. 客户端配置
- 下载[Wireguard](https://www.wireguard.com/)

- 左下角新建隧道,配置文件为:
```bash
[Interface]
PrivateKey = dihwiajdijsiojdiojwij= #软件自动生成的
Address = 10.8.8.2/24

[Peer]
PublicKey =              #服务端公钥
AllowedIPs = 10.8.8.1/32, 192.168.1.0/24  #/24为网段,/32为单ip
Endpoint =               #公网ip:51820或者域名:51820
PersistentKeepalive = 25
```

配置项：

```ini
AllowedIPs = 10.8.8.1/32, 192.168.1.0/24
```

这是 WireGuard 客户端配置中的关键字段，**决定了哪些目标 IP 流量会通过这个 WireGuard 隧道发送给对应的 Peer（服务端）**。

---

###  关于AllowedIPs

在 WireGuard 中，`AllowedIPs` 有两个功能（对客户端而言主要是第一个）：

1. **路由规则（Routing Policy）**  
    → 系统会自动添加路由：**所有匹配 `AllowedIPs` 的目标地址，都通过 `wg0` 接口发送给该 Peer**。  
    → 相当于执行了：

```bash
   ip route add 10.8.8.1/32 dev wg0    ip route add 192.168.1.120/32 dev wg0
```

2. **访问控制（Access Control）**  
    → 服务端只会接受来自该 Peer、且源 IP 在 `AllowedIPs` 范围内的数据包（反向验证）。  
    → 但在客户端配置中，这个作用较弱，主要是用于路由。
    

---

####  举个实际例子

假设你的 WireGuard 服务端部署在一台具有公网 IP 的 Linux 服务器上，这台服务器同时处于公司内网 `192.168.1.0/24`，其中有一台数据库服务器 IP 是 `192.168.1.120`。

你在家里用客户端连接 WireGuard：

- 当你 `ping 10.8.8.1` → 流量走隧道 → 到达服务端虚拟接口（用于测试连通性）。
- 当你 `ssh user@192.168.1.120` → 流量走隧道 → 服务端收到后，转发给内网的 `192.168.1.120`。
- 当你访问 `8.8.8.8`（Google DNS）→ **不会走隧道**！因为 `8.8.8.8` 不在 `AllowedIPs` 列表中，流量走你本地的默认网关。

> 这种配置叫做 **“分流”（Split Tunneling）**：只加密访问特定资源的流量，其他流量直连，兼顾安全与速度。

---

####  常见问题

##### Q：如果想让**所有流量都走 VPN**（全隧道），怎么写？

```ini
AllowedIPs = 0.0.0.0/0, ::/0
```

> 这会把 IPv4 和 IPv6 的所有流量都导入隧道（类似传统“全局代理”）。

##### Q：可以写整个子网吗？

可以！比如：

```ini
AllowedIPs = 192.168.1.0/24
```

→ 表示访问整个 `192.168.1.x` 网段都走隧道。

##### Q：顺序重要吗？

不重要。WireGuard 会合并所有条目，按最长前缀匹配路由。

---

####  总结

你的配置：

```ini
AllowedIPs = 10.8.8.1/32, 192.168.1.120/32
```

表示：

- 客户端**仅当访问 `10.8.8.1`（服务端虚拟 IP）或 `192.168.1.120`（内网某设备）时**，才通过 WireGuard 隧道发送数据；
- 其他所有互联网流量（如浏览网页、看视频）**仍走本地网络，不经过 VPN**；
- 这是一种**安全、高效、精准的访问控制策略**，非常适合远程访问特定内网资源。

> 💡 提示：确保服务端已开启 IP 转发（`net.ipv4.ip_forward=1`）并配置好防火墙（如 `iptables` 或 `nftables`），否则 `192.168.1.120` 可能无法被访问到。

