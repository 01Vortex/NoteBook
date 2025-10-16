# 端口自定义
## 出网端口2000-2099
### 系统(2000-2019)
- 2000 ssh
- 2001 bt
- 2003 vnc

### Web(2020-2059)
- 2020 source
- 2021 busuanzi



### DockerWeb(2060-2099)
- 2060 twikoo
- 2061 grafana
- 2062 cloudreve


## 本地端口2100-2199
### 系统(2100-2119)
- 2100 redis

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
