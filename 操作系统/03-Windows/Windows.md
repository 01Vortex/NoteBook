

> Windows 是微软公司开发的图形化操作系统，是全球使用最广泛的桌面操作系统
> 本笔记涵盖 Windows 系统管理、命令行操作、安全配置等完整内容
> 基于 Windows 10/11 及 Windows Server 2019/2022，更新日期：2025年12月

---

## 目录

1. [Windows 系统概述](#1-windows-系统概述)
2. [系统安装与配置](#2-系统安装与配置)
3. [用户与权限管理](#3-用户与权限管理)
4. [文件系统与磁盘管理](#4-文件系统与磁盘管理)
5. [CMD 命令行基础](#5-cmd-命令行基础)
6. [PowerShell 基础](#6-powershell-基础)
7. [PowerShell 进阶](#7-powershell-进阶)
8. [网络配置与管理](#8-网络配置与管理)
9. [服务与进程管理](#9-服务与进程管理)
10. [注册表管理](#10-注册表管理)
11. [组策略管理](#11-组策略管理)
12. [Active Directory 基础](#12-active-directory-基础)
13. [Windows 安全配置](#13-windows-安全配置)
14. [系统监控与日志](#14-系统监控与日志)
15. [故障排除与修复](#15-故障排除与修复)
16. [常见错误与解决方案](#16-常见错误与解决方案)
17. [最佳实践与技巧](#17-最佳实践与技巧)

---

## 1. Windows 系统概述

### 1.1 Windows 发展历史

Windows 操作系统自 1985 年首次发布以来，经历了多个重要版本的演进。了解这些版本对于系统管理和兼容性问题的解决非常有帮助。

```
┌─────────────────────────────────────────────────────────────────┐
│                    Windows 版本演进                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   桌面版本                                                      │
│   ├── Windows 1.0 (1985) - 首个图形界面                        │
│   ├── Windows 3.1 (1992) - 广泛普及                            │
│   ├── Windows 95 (1995) - 革命性更新                           │
│   ├── Windows 98/ME (1998-2000)                                │
│   ├── Windows XP (2001) - 经典版本                             │
│   ├── Windows Vista (2007)                                     │
│   ├── Windows 7 (2009) - 广受好评                              │
│   ├── Windows 8/8.1 (2012-2013)                                │
│   ├── Windows 10 (2015) - 持续更新模式                         │
│   └── Windows 11 (2021) - 最新版本                             │
│                                                                 │
│   服务器版本                                                    │
│   ├── Windows NT 3.1-4.0 (1993-1996)                           │
│   ├── Windows 2000 Server                                      │
│   ├── Windows Server 2003/2003 R2                              │
│   ├── Windows Server 2008/2008 R2                              │
│   ├── Windows Server 2012/2012 R2                              │
│   ├── Windows Server 2016                                      │
│   ├── Windows Server 2019                                      │
│   └── Windows Server 2022 - 最新版本                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Windows 版本对比

| 版本 | 内核版本 | 支持状态 | 主要特性 |
|------|----------|----------|----------|
| Windows 7 | NT 6.1 | 已停止支持 | Aero 界面、任务栏改进 |
| Windows 8.1 | NT 6.3 | 已停止支持 | Metro 界面、应用商店 |
| Windows 10 | NT 10.0 | 支持中 | Cortana、虚拟桌面、WSL |
| Windows 11 | NT 10.0 | 支持中 | 新界面、Android 应用、TPM 2.0 |
| Server 2016 | NT 10.0 | 支持中 | Nano Server、容器支持 |
| Server 2019 | NT 10.0 | 支持中 | 混合云、安全增强 |
| Server 2022 | NT 10.0 | 支持中 | 安全核心、Azure 集成 |

### 1.3 Windows 架构

```
┌─────────────────────────────────────────────────────────────────┐
│                    Windows 系统架构                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   用户模式 (User Mode)                                          │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  应用程序  │  系统进程  │  服务进程  │  环境子系统     │   │
│   │  (Apps)   │ (System)  │ (Services)│  (Subsystems)   │   │
│   └─────────────────────────────────────────────────────────┘   │
│                            ↓                                    │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │              Windows API (Win32/Win64)                  │   │
│   └─────────────────────────────────────────────────────────┘   │
│                            ↓                                    │
│   ─────────────────────────────────────────────────────────────  │
│                                                                 │
│   内核模式 (Kernel Mode)                                        │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  执行体 (Executive)                                     │   │
│   │  ├── I/O 管理器    ├── 对象管理器   ├── 安全引用监视器 │   │
│   │  ├── 进程管理器    ├── 内存管理器   ├── 缓存管理器     │   │
│   │  └── 即插即用管理器                                     │   │
│   └─────────────────────────────────────────────────────────┘   │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  内核 (Kernel) + 硬件抽象层 (HAL)                       │   │
│   └─────────────────────────────────────────────────────────┘   │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  设备驱动程序 (Device Drivers)                          │   │
│   └─────────────────────────────────────────────────────────┘   │
│                            ↓                                    │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                    硬件 (Hardware)                       │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 1.4 重要系统目录

```
C:\
├── Windows\                    # Windows 系统目录
│   ├── System32\              # 64位系统文件和工具
│   │   ├── config\            # 注册表文件
│   │   ├── drivers\           # 驱动程序
│   │   └── *.exe, *.dll       # 系统程序和库
│   ├── SysWOW64\              # 32位兼容系统文件
│   ├── Temp\                  # 系统临时文件
│   ├── Logs\                  # 系统日志
│   └── WinSxS\                # 组件存储
├── Program Files\              # 64位程序安装目录
├── Program Files (x86)\        # 32位程序安装目录
├── Users\                      # 用户目录
│   ├── Default\               # 默认用户配置
│   ├── Public\                # 公共文件夹
│   └── <用户名>\              # 用户个人目录
│       ├── Desktop\           # 桌面
│       ├── Documents\         # 文档
│       ├── Downloads\         # 下载
│       ├── AppData\           # 应用程序数据
│       │   ├── Local\         # 本地数据
│       │   ├── LocalLow\      # 低权限本地数据
│       │   └── Roaming\       # 漫游数据
│       └── NTUSER.DAT         # 用户注册表
├── ProgramData\                # 程序共享数据（隐藏）
└── Recovery\                   # 恢复分区
```

---

## 2. 系统安装与配置

### 2.1 系统要求

#### Windows 11 最低要求

| 组件 | 最低要求 |
|------|----------|
| 处理器 | 1 GHz，2核，64位 |
| 内存 | 4 GB |
| 存储 | 64 GB |
| 固件 | UEFI，支持安全启动 |
| TPM | 版本 2.0 |
| 显卡 | DirectX 12，WDDM 2.0 |
| 显示器 | 720p，9英寸以上 |

#### Windows Server 2022 最低要求

| 组件 | 最低要求 | 推荐配置 |
|------|----------|----------|
| 处理器 | 1.4 GHz，64位 | 2 GHz+ |
| 内存 | 512 MB (Core) / 2 GB (GUI) | 16 GB+ |
| 存储 | 32 GB | 100 GB+ |
| 网络 | 千兆网卡 | 万兆网卡 |

### 2.2 安装方式

```powershell
# 1. 全新安装
# 从 USB 或 DVD 启动，按照向导安装

# 2. 升级安装
# 在现有系统中运行安装程序

# 3. 无人值守安装
# 使用应答文件 (unattend.xml)

# 4. 网络安装 (WDS)
# Windows 部署服务

# 5. 映像部署
# 使用 DISM 或 MDT
```

### 2.3 初始配置

```powershell
# 设置计算机名
Rename-Computer -NewName "PC-001" -Restart

# 设置时区
Set-TimeZone -Id "China Standard Time"

# 启用远程桌面
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# 配置 Windows 更新
# 设置 -> 更新和安全 -> Windows 更新

# 激活 Windows
slmgr /ipk <产品密钥>
slmgr /ato

# 查看激活状态
slmgr /xpr
slmgr /dli
```

### 2.4 系统信息查看

```powershell
# 查看系统信息
systeminfo

# 查看 Windows 版本
winver

# 查看详细版本信息
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer

# 查看系统架构
[Environment]::Is64BitOperatingSystem

# 查看安装日期
(Get-CimInstance Win32_OperatingSystem).InstallDate

# 查看最后启动时间
(Get-CimInstance Win32_OperatingSystem).LastBootUpTime

# 查看系统运行时间
(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
```

---

## 3. 用户与权限管理

### 3.1 用户账户类型

```
┌─────────────────────────────────────────────────────────────────┐
│                    Windows 用户账户类型                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   本地账户                                                      │
│   ├── Administrator - 内置管理员账户（默认禁用）               │
│   ├── Guest - 来宾账户（默认禁用）                             │
│   ├── DefaultAccount - 系统管理账户                            │
│   └── 自定义用户账户                                           │
│                                                                 │
│   Microsoft 账户                                                │
│   └── 与 Microsoft 服务关联的在线账户                          │
│                                                                 │
│   域账户 (Active Directory)                                     │
│   ├── Domain Admins - 域管理员                                 │
│   ├── Domain Users - 域用户                                    │
│   └── 其他域账户                                               │
│                                                                 │
│   服务账户                                                      │
│   ├── SYSTEM (NT AUTHORITY\SYSTEM) - 最高权限                  │
│   ├── LOCAL SERVICE - 本地服务                                 │
│   ├── NETWORK SERVICE - 网络服务                               │
│   └── 托管服务账户 (MSA/gMSA)                                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 用户管理命令

```powershell
# ==================== CMD 命令 ====================

# 查看所有用户
net user

# 查看用户详细信息
net user username

# 创建用户
net user username password /add

# 创建用户（更多选项）
net user username password /add /fullname:"Full Name" /comment:"Description" /passwordchg:no

# 删除用户
net user username /delete

# 修改密码
net user username newpassword

# 禁用用户
net user username /active:no

# 启用用户
net user username /active:yes

# 设置密码永不过期
net user username /expires:never

# ==================== PowerShell 命令 ====================

# 查看所有本地用户
Get-LocalUser

# 查看用户详细信息
Get-LocalUser -Name "username" | Format-List *

# 创建用户
$Password = Read-Host -AsSecureString "Enter Password"
New-LocalUser -Name "username" -Password $Password -FullName "Full Name" -Description "Description"

# 删除用户
Remove-LocalUser -Name "username"

# 修改密码
$Password = Read-Host -AsSecureString "Enter New Password"
Set-LocalUser -Name "username" -Password $Password

# 禁用用户
Disable-LocalUser -Name "username"

# 启用用户
Enable-LocalUser -Name "username"

# 设置密码永不过期
Set-LocalUser -Name "username" -PasswordNeverExpires $true
```

### 3.3 组管理

```powershell
# ==================== CMD 命令 ====================

# 查看所有组
net localgroup

# 查看组成员
net localgroup "Administrators"

# 创建组
net localgroup "GroupName" /add

# 删除组
net localgroup "GroupName" /delete

# 添加用户到组
net localgroup "Administrators" username /add

# 从组中移除用户
net localgroup "Administrators" username /delete

# ==================== PowerShell 命令 ====================

# 查看所有本地组
Get-LocalGroup

# 查看组成员
Get-LocalGroupMember -Group "Administrators"

# 创建组
New-LocalGroup -Name "GroupName" -Description "Description"

# 删除组
Remove-LocalGroup -Name "GroupName"

# 添加用户到组
Add-LocalGroupMember -Group "Administrators" -Member "username"

# 从组中移除用户
Remove-LocalGroupMember -Group "Administrators" -Member "username"
```

### 3.4 内置组说明

| 组名 | 说明 | 权限级别 |
|------|------|----------|
| Administrators | 管理员组 | 完全控制 |
| Users | 普通用户组 | 基本权限 |
| Guests | 来宾组 | 最低权限 |
| Power Users | 高级用户组 | 介于管理员和用户之间 |
| Remote Desktop Users | 远程桌面用户 | 可远程登录 |
| Backup Operators | 备份操作员 | 可备份和还原文件 |
| Network Configuration Operators | 网络配置操作员 | 可配置网络 |
| Performance Monitor Users | 性能监视器用户 | 可监视性能 |
| Event Log Readers | 事件日志读取者 | 可读取事件日志 |
| Cryptographic Operators | 加密操作员 | 可执行加密操作 |

### 3.5 用户权限与特权

```powershell
# 查看当前用户权限
whoami /priv

# 查看当前用户所属组
whoami /groups

# 查看当前用户所有信息
whoami /all

# 查看用户 SID
whoami /user

# 使用 PowerShell 查看权限
[Security.Principal.WindowsIdentity]::GetCurrent().Groups | 
    ForEach-Object { $_.Translate([Security.Principal.NTAccount]) }
```

### 3.6 UAC 用户账户控制

```powershell
# 查看 UAC 状态
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | 
    Select-Object EnableLUA, ConsentPromptBehaviorAdmin, ConsentPromptBehaviorUser

# 禁用 UAC（不推荐）
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0

# 启用 UAC
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1

# 以管理员身份运行程序
Start-Process powershell -Verb RunAs

# 以管理员身份运行命令
Start-Process cmd -ArgumentList "/c command" -Verb RunAs
```

---

## 4. 文件系统与磁盘管理

### 4.1 文件系统类型

| 文件系统 | 最大文件大小 | 最大卷大小 | 特性 |
|----------|--------------|------------|------|
| FAT32 | 4 GB | 2 TB | 兼容性好，无安全特性 |
| exFAT | 16 EB | 128 PB | 适合闪存设备 |
| NTFS | 16 EB | 256 TB | 安全、压缩、加密、配额 |
| ReFS | 16 EB | 1 YB | 数据完整性、自动修复 |

### 4.2 磁盘管理命令

```powershell
# ==================== diskpart 命令 ====================

# 启动 diskpart
diskpart

# 列出磁盘
list disk

# 选择磁盘
select disk 0

# 列出分区
list partition

# 选择分区
select partition 1

# 列出卷
list volume

# 选择卷
select volume 1

# 创建主分区
create partition primary size=10240

# 格式化
format fs=ntfs label="Data" quick

# 分配盘符
assign letter=D

# 删除分区
delete partition

# 清除磁盘
clean

# 转换为 GPT
convert gpt

# 转换为 MBR
convert mbr

# ==================== PowerShell 命令 ====================

# 查看磁盘
Get-Disk

# 查看分区
Get-Partition

# 查看卷
Get-Volume

# 初始化磁盘
Initialize-Disk -Number 1 -PartitionStyle GPT

# 创建分区
New-Partition -DiskNumber 1 -UseMaximumSize -AssignDriveLetter

# 格式化卷
Format-Volume -DriveLetter D -FileSystem NTFS -NewFileSystemLabel "Data"

# 调整分区大小
Resize-Partition -DriveLetter C -Size 100GB

# 删除分区
Remove-Partition -DriveLetter D

# 查看磁盘空间
Get-PSDrive -PSProvider FileSystem
```

### 4.3 文件和目录操作

```powershell
# ==================== CMD 命令 ====================

# 切换目录
cd /d D:\folder
cd ..
cd \

# 列出目录内容
dir
dir /a          # 显示所有文件（包括隐藏）
dir /s          # 递归显示
dir /b          # 简洁格式
dir /o:n        # 按名称排序

# 创建目录
mkdir folder
md folder\subfolder

# 删除目录
rmdir folder
rd /s /q folder  # 递归删除

# 复制文件
copy source.txt dest.txt
copy *.txt D:\backup\

# 复制目录
xcopy source dest /e /i /h
robocopy source dest /e /mir

# 移动文件
move source.txt D:\folder\

# 删除文件
del file.txt
del /f /q *.tmp  # 强制删除

# 重命名
ren oldname.txt newname.txt

# 查看文件内容
type file.txt
more file.txt

# 查找文件
dir /s /b *.txt
where /r C:\ filename.exe

# 文件属性
attrib file.txt
attrib +h +s file.txt  # 设置隐藏和系统属性
attrib -h -s file.txt  # 移除属性

# ==================== PowerShell 命令 ====================

# 切换目录
Set-Location D:\folder
cd D:\folder

# 列出目录内容
Get-ChildItem
Get-ChildItem -Force          # 包括隐藏文件
Get-ChildItem -Recurse        # 递归
Get-ChildItem -Filter *.txt   # 过滤

# 创建目录
New-Item -ItemType Directory -Path "folder"
mkdir folder

# 删除目录
Remove-Item -Path "folder" -Recurse -Force

# 复制文件/目录
Copy-Item -Path "source.txt" -Destination "dest.txt"
Copy-Item -Path "source" -Destination "dest" -Recurse

# 移动文件/目录
Move-Item -Path "source.txt" -Destination "D:\folder\"

# 删除文件
Remove-Item -Path "file.txt"
Remove-Item -Path "*.tmp" -Force

# 重命名
Rename-Item -Path "oldname.txt" -NewName "newname.txt"

# 查看文件内容
Get-Content file.txt
Get-Content file.txt -Tail 10  # 最后10行
Get-Content file.txt -Wait     # 实时监控

# 查找文件
Get-ChildItem -Path C:\ -Filter "*.txt" -Recurse -ErrorAction SilentlyContinue

# 文件属性
Get-ItemProperty file.txt
Set-ItemProperty file.txt -Name Attributes -Value "Hidden,System"
```

### 4.4 文件权限管理

```powershell
# 查看文件权限
icacls file.txt
Get-Acl file.txt | Format-List

# 设置文件权限
icacls file.txt /grant username:F        # 完全控制
icacls file.txt /grant username:R        # 只读
icacls file.txt /grant username:M        # 修改
icacls file.txt /deny username:W         # 拒绝写入
icacls file.txt /remove username         # 移除权限

# 递归设置权限
icacls folder /grant username:F /t

# 重置权限
icacls file.txt /reset

# 获取所有权
takeown /f file.txt
takeown /f folder /r /d y

# PowerShell 设置权限
$acl = Get-Acl "file.txt"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("username", "FullControl", "Allow")
$acl.SetAccessRule($rule)
Set-Acl "file.txt" $acl
```

### 4.5 磁盘配额

```powershell
# 启用磁盘配额
fsutil quota enforce D:

# 设置默认配额
fsutil quota defaults D: 1073741824 2147483648  # 警告1GB，限制2GB

# 设置用户配额
fsutil quota modify D: 1073741824 2147483648 username

# 查看配额
fsutil quota query D:

# 禁用配额
fsutil quota disable D:
```

---

## 5. CMD 命令行基础

### 5.1 CMD 基础操作

```cmd
:: 清屏
cls

:: 查看帮助
help
command /?

:: 命令历史
doskey /history
按 F7 查看历史

:: 设置命令别名
doskey ls=dir /b
doskey ll=dir

:: 环境变量
echo %PATH%
echo %USERNAME%
echo %COMPUTERNAME%
echo %USERPROFILE%
echo %TEMP%

:: 设置环境变量（当前会话）
set MYVAR=value
echo %MYVAR%

:: 设置永久环境变量
setx MYVAR "value"
setx PATH "%PATH%;C:\newpath"

:: 命令重定向
command > output.txt      :: 覆盖
command >> output.txt     :: 追加
command 2> error.txt      :: 错误输出
command > output.txt 2>&1 :: 合并输出

:: 管道
dir | find "txt"
type file.txt | more

:: 命令连接
command1 & command2       :: 顺序执行
command1 && command2      :: 成功后执行
command1 || command2      :: 失败后执行

:: 注释
:: 这是注释
rem 这也是注释
```

### 5.2 常用系统命令

```cmd
:: 系统信息
systeminfo
hostname
ver

:: 日期和时间
date
time
date /t
time /t

:: 关机和重启
shutdown /s /t 0          :: 立即关机
shutdown /r /t 0          :: 立即重启
shutdown /l               :: 注销
shutdown /h               :: 休眠
shutdown /a               :: 取消关机

:: 任务管理
tasklist                  :: 列出进程
tasklist /fi "imagename eq notepad.exe"
taskkill /im notepad.exe  :: 按名称结束
taskkill /pid 1234        :: 按 PID 结束
taskkill /f /im notepad.exe :: 强制结束

:: 服务管理
sc query                  :: 列出服务
sc query servicename      :: 查询服务
sc start servicename      :: 启动服务
sc stop servicename       :: 停止服务
sc config servicename start=auto :: 设置自动启动

:: 网络命令
ipconfig                  :: IP 配置
ipconfig /all             :: 详细信息
ipconfig /release         :: 释放 IP
ipconfig /renew           :: 更新 IP
ipconfig /flushdns        :: 清除 DNS 缓存

ping hostname             :: 测试连通性
tracert hostname          :: 路由追踪
nslookup hostname         :: DNS 查询
netstat -ano              :: 网络连接
netstat -b                :: 显示程序名

:: 用户和组
net user                  :: 用户列表
net localgroup            :: 组列表
net session               :: 会话列表
net share                 :: 共享列表

:: 磁盘操作
chkdsk C: /f              :: 检查磁盘
sfc /scannow              :: 系统文件检查
dism /online /cleanup-image /restorehealth :: 修复系统映像
```

### 5.3 批处理脚本基础

```batch
@echo off
:: 批处理脚本示例

:: 设置变量
set NAME=World
echo Hello, %NAME%!

:: 获取用户输入
set /p INPUT=Enter your name: 
echo Hello, %INPUT%!

:: 条件判断
if "%INPUT%"=="admin" (
    echo Welcome, Administrator!
) else (
    echo Welcome, User!
)

:: 文件存在判断
if exist "file.txt" (
    echo File exists
) else (
    echo File not found
)

:: 循环
for %%i in (1 2 3 4 5) do (
    echo Number: %%i
)

:: 遍历文件
for %%f in (*.txt) do (
    echo File: %%f
)

:: 遍历目录
for /d %%d in (*) do (
    echo Directory: %%d
)

:: 递归遍历
for /r %%f in (*.txt) do (
    echo %%f
)

:: 数字循环
for /l %%i in (1,1,10) do (
    echo %%i
)

:: 函数调用
call :myfunction arg1 arg2
goto :eof

:myfunction
echo Argument 1: %1
echo Argument 2: %2
goto :eof

:: 错误处理
command || (
    echo Command failed!
    exit /b 1
)

:: 延迟
timeout /t 5
ping -n 5 127.0.0.1 > nul

:: 暂停
pause
```

---

## 6. PowerShell 基础

### 6.1 PowerShell 简介

PowerShell 是微软开发的任务自动化和配置管理框架，它比传统的 CMD 更加强大和灵活。PowerShell 基于 .NET 框架，支持面向对象的编程方式。

```
┌─────────────────────────────────────────────────────────────────┐
│                    PowerShell vs CMD                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   CMD                              PowerShell                   │
│   ├── 基于文本                     ├── 基于对象                 │
│   ├── 功能有限                     ├── 功能强大                 │
│   ├── 脚本能力弱                   ├── 完整的脚本语言           │
│   ├── 无法访问 .NET                ├── 完全访问 .NET            │
│   └── 兼容性好                     └── 跨平台支持               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 6.2 PowerShell 版本

```powershell
# 查看 PowerShell 版本
$PSVersionTable

# 主要版本：
# PowerShell 5.1 - Windows 内置版本
# PowerShell 7.x - 跨平台版本（推荐）

# 安装 PowerShell 7
winget install Microsoft.PowerShell

# 或从 GitHub 下载
# https://github.com/PowerShell/PowerShell/releases
```

### 6.3 基础语法

```powershell
# 获取帮助
Get-Help Get-Process
Get-Help Get-Process -Full
Get-Help Get-Process -Examples
Get-Help *process*

# 更新帮助
Update-Help

# 查看命令
Get-Command
Get-Command -Name *process*
Get-Command -Module Microsoft.PowerShell.Management

# 查看别名
Get-Alias
Get-Alias -Name ls
Get-Alias -Definition Get-ChildItem

# 常用别名
# ls, dir -> Get-ChildItem
# cd -> Set-Location
# cp -> Copy-Item
# mv -> Move-Item
# rm -> Remove-Item
# cat -> Get-Content
# echo -> Write-Output
# cls -> Clear-Host

# 变量
$name = "World"
$number = 42
$array = @(1, 2, 3, 4, 5)
$hash = @{Name="John"; Age=30}

# 输出
Write-Host "Hello, $name!" -ForegroundColor Green
Write-Output "This goes to pipeline"
Write-Warning "This is a warning"
Write-Error "This is an error"

# 字符串操作
$str = "Hello, World!"
$str.Length
$str.ToUpper()
$str.ToLower()
$str.Replace("World", "PowerShell")
$str.Split(",")
$str.Substring(0, 5)
$str -match "World"
$str -replace "World", "PowerShell"

# 数组操作
$array = @(1, 2, 3, 4, 5)
$array[0]           # 第一个元素
$array[-1]          # 最后一个元素
$array[1..3]        # 切片
$array += 6         # 添加元素
$array.Count        # 元素数量
$array | ForEach-Object { $_ * 2 }  # 遍历

# 哈希表操作
$hash = @{
    Name = "John"
    Age = 30
    City = "Beijing"
}
$hash["Name"]
$hash.Name
$hash.Keys
$hash.Values
$hash.Add("Country", "China")
$hash.Remove("City")
```

### 6.4 管道和过滤

```powershell
# 管道基础
Get-Process | Where-Object { $_.CPU -gt 10 }
Get-Process | Sort-Object CPU -Descending
Get-Process | Select-Object Name, CPU, Memory
Get-Process | Format-Table Name, CPU, Memory -AutoSize
Get-Process | Export-Csv processes.csv

# Where-Object 过滤
Get-Process | Where-Object { $_.Name -eq "notepad" }
Get-Process | Where-Object { $_.CPU -gt 10 -and $_.Memory -gt 100MB }
Get-Process | Where-Object Name -like "*chrome*"

# Select-Object 选择
Get-Process | Select-Object -First 5
Get-Process | Select-Object -Last 5
Get-Process | Select-Object Name, @{Name="Memory(MB)"; Expression={$_.WorkingSet64/1MB}}

# Sort-Object 排序
Get-Process | Sort-Object CPU -Descending
Get-Process | Sort-Object Name, CPU

# Group-Object 分组
Get-Process | Group-Object ProcessName
Get-Service | Group-Object Status

# Measure-Object 统计
Get-Process | Measure-Object CPU -Sum -Average -Maximum -Minimum
Get-ChildItem | Measure-Object Length -Sum

# ForEach-Object 遍历
1..10 | ForEach-Object { $_ * 2 }
Get-Process | ForEach-Object { Write-Host $_.Name }

# 格式化输出
Get-Process | Format-Table -AutoSize
Get-Process | Format-List
Get-Process | Format-Wide
Get-Process | Out-GridView
```

### 6.5 条件和循环

```powershell
# if 条件
$value = 10
if ($value -gt 5) {
    Write-Host "Greater than 5"
} elseif ($value -eq 5) {
    Write-Host "Equal to 5"
} else {
    Write-Host "Less than 5"
}

# switch 语句
$day = "Monday"
switch ($day) {
    "Monday" { Write-Host "Start of week" }
    "Friday" { Write-Host "End of week" }
    default { Write-Host "Middle of week" }
}

# for 循环
for ($i = 0; $i -lt 10; $i++) {
    Write-Host $i
}

# foreach 循环
$items = @("apple", "banana", "cherry")
foreach ($item in $items) {
    Write-Host $item
}

# while 循环
$count = 0
while ($count -lt 5) {
    Write-Host $count
    $count++
}

# do-while 循环
$count = 0
do {
    Write-Host $count
    $count++
} while ($count -lt 5)

# do-until 循环
$count = 0
do {
    Write-Host $count
    $count++
} until ($count -ge 5)

# 比较运算符
# -eq  等于
# -ne  不等于
# -gt  大于
# -ge  大于等于
# -lt  小于
# -le  小于等于
# -like  通配符匹配
# -notlike  通配符不匹配
# -match  正则匹配
# -notmatch  正则不匹配
# -contains  包含
# -notcontains  不包含
# -in  在集合中
# -notin  不在集合中

# 逻辑运算符
# -and  与
# -or   或
# -not  非
# !     非
```

### 6.6 函数

```powershell
# 基础函数
function Say-Hello {
    Write-Host "Hello, World!"
}
Say-Hello

# 带参数的函数
function Say-Hello {
    param (
        [string]$Name = "World"
    )
    Write-Host "Hello, $Name!"
}
Say-Hello -Name "PowerShell"

# 高级函数
function Get-Square {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [int]$Number
    )
    
    process {
        return $Number * $Number
    }
}
5 | Get-Square
Get-Square -Number 5

# 带验证的参数
function Set-Age {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateRange(0, 150)]
        [int]$Age
    )
    Write-Host "Age is $Age"
}

# 返回值
function Add-Numbers {
    param ([int]$a, [int]$b)
    return $a + $b
}
$result = Add-Numbers -a 5 -b 3
```

---

## 7. PowerShell 进阶

### 7.1 错误处理

```powershell
# try-catch-finally
try {
    $result = 1 / 0
} catch {
    Write-Host "Error: $_"
    Write-Host "Error Type: $($_.Exception.GetType().Name)"
} finally {
    Write-Host "Cleanup code here"
}

# 错误操作首选项
$ErrorActionPreference = "Stop"      # 遇错停止
$ErrorActionPreference = "Continue"  # 继续执行（默认）
$ErrorActionPreference = "SilentlyContinue"  # 静默继续

# 命令级别错误处理
Get-Item "nonexistent" -ErrorAction SilentlyContinue
Get-Item "nonexistent" -ErrorAction Stop

# 检查上一个命令是否成功
if ($?) {
    Write-Host "Last command succeeded"
} else {
    Write-Host "Last command failed"
}

# 查看错误记录
$Error[0]           # 最近的错误
$Error.Clear()      # 清除错误
```

### 7.2 远程管理

```powershell
# 启用 PowerShell 远程
Enable-PSRemoting -Force

# 检查 WinRM 服务
Get-Service WinRM
Start-Service WinRM

# 添加信任主机
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.1.100"
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*"  # 信任所有（不推荐）

# 远程执行命令
Invoke-Command -ComputerName Server01 -ScriptBlock { Get-Process }

# 使用凭据
$cred = Get-Credential
Invoke-Command -ComputerName Server01 -Credential $cred -ScriptBlock { Get-Process }

# 远程会话
$session = New-PSSession -ComputerName Server01 -Credential $cred
Enter-PSSession $session
Exit-PSSession
Remove-PSSession $session

# 复制文件到远程
Copy-Item -Path "C:\local\file.txt" -Destination "C:\remote\" -ToSession $session

# 从远程复制文件
Copy-Item -Path "C:\remote\file.txt" -Destination "C:\local\" -FromSession $session
```

### 7.3 模块管理

```powershell
# 查看已安装模块
Get-Module -ListAvailable

# 查看已加载模块
Get-Module

# 导入模块
Import-Module ModuleName

# 安装模块（从 PowerShell Gallery）
Install-Module -Name ModuleName

# 更新模块
Update-Module -Name ModuleName

# 卸载模块
Uninstall-Module -Name ModuleName

# 查找模块
Find-Module -Name *Azure*

# 常用模块
# PSReadLine - 命令行增强
# Pester - 测试框架
# PSScriptAnalyzer - 代码分析
# Az - Azure 管理
# ActiveDirectory - AD 管理
# SqlServer - SQL Server 管理
```

### 7.4 脚本执行策略

```powershell
# 查看执行策略
Get-ExecutionPolicy
Get-ExecutionPolicy -List

# 设置执行策略
Set-ExecutionPolicy Restricted      # 禁止所有脚本
Set-ExecutionPolicy AllSigned       # 只允许签名脚本
Set-ExecutionPolicy RemoteSigned    # 本地脚本可执行，远程需签名
Set-ExecutionPolicy Unrestricted    # 允许所有脚本
Set-ExecutionPolicy Bypass          # 绑过所有限制

# 为当前用户设置
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

# 临时绑过
powershell -ExecutionPolicy Bypass -File script.ps1
```

### 7.5 计划任务

```powershell
# 查看计划任务
Get-ScheduledTask
Get-ScheduledTask -TaskName "TaskName"

# 创建计划任务
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\script.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At 9am
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
Register-ScheduledTask -TaskName "MyTask" -Action $action -Trigger $trigger -Principal $principal

# 触发器类型
New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)
New-ScheduledTaskTrigger -Daily -At 9am
New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 9am
New-ScheduledTaskTrigger -AtStartup
New-ScheduledTaskTrigger -AtLogOn

# 启动/停止任务
Start-ScheduledTask -TaskName "MyTask"
Stop-ScheduledTask -TaskName "MyTask"

# 禁用/启用任务
Disable-ScheduledTask -TaskName "MyTask"
Enable-ScheduledTask -TaskName "MyTask"

# 删除任务
Unregister-ScheduledTask -TaskName "MyTask" -Confirm:$false
```

### 7.6 WMI/CIM 查询

```powershell
# 使用 CIM（推荐）
Get-CimInstance -ClassName Win32_OperatingSystem
Get-CimInstance -ClassName Win32_ComputerSystem
Get-CimInstance -ClassName Win32_Processor
Get-CimInstance -ClassName Win32_PhysicalMemory
Get-CimInstance -ClassName Win32_DiskDrive
Get-CimInstance -ClassName Win32_NetworkAdapter
Get-CimInstance -ClassName Win32_Service
Get-CimInstance -ClassName Win32_Process

# 使用 WMI（旧方式）
Get-WmiObject -Class Win32_OperatingSystem

# 查询示例
Get-CimInstance -ClassName Win32_Process | Where-Object { $_.Name -eq "notepad.exe" }
Get-CimInstance -ClassName Win32_Service | Where-Object { $_.State -eq "Running" }

# 远程查询
Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName Server01

# 常用 WMI 类
# Win32_OperatingSystem - 操作系统信息
# Win32_ComputerSystem - 计算机信息
# Win32_Processor - CPU 信息
# Win32_PhysicalMemory - 内存信息
# Win32_DiskDrive - 磁盘信息
# Win32_LogicalDisk - 逻辑磁盘
# Win32_NetworkAdapter - 网卡信息
# Win32_NetworkAdapterConfiguration - 网络配置
# Win32_Service - 服务信息
# Win32_Process - 进程信息
# Win32_Product - 已安装软件
# Win32_UserAccount - 用户账户
```

---

## 8. 网络配置与管理

### 8.1 网络配置命令

```powershell
# ==================== CMD 命令 ====================

# 查看 IP 配置
ipconfig
ipconfig /all

# 释放和更新 IP
ipconfig /release
ipconfig /renew

# 清除 DNS 缓存
ipconfig /flushdns

# 显示 DNS 缓存
ipconfig /displaydns

# 注册 DNS
ipconfig /registerdns

# ==================== PowerShell 命令 ====================

# 查看网络适配器
Get-NetAdapter
Get-NetAdapter | Where-Object Status -eq "Up"

# 查看 IP 配置
Get-NetIPConfiguration
Get-NetIPAddress

# 设置静态 IP
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.1.100 -PrefixLength 24 -DefaultGateway 192.168.1.1

# 设置 DHCP
Set-NetIPInterface -InterfaceAlias "Ethernet" -Dhcp Enabled

# 设置 DNS
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 8.8.8.8,8.8.4.4

# 清除 DNS 缓存
Clear-DnsClientCache

# 查看 DNS 缓存
Get-DnsClientCache

# 禁用/启用网卡
Disable-NetAdapter -Name "Ethernet"
Enable-NetAdapter -Name "Ethernet"

# 重命名网卡
Rename-NetAdapter -Name "Ethernet" -NewName "LAN"
```

### 8.2 网络诊断

```powershell
# Ping 测试
ping hostname
ping -t hostname          # 持续 ping
ping -n 10 hostname       # 指定次数
Test-Connection hostname
Test-Connection hostname -Count 5

# 路由追踪
tracert hostname
Test-NetConnection hostname -TraceRoute

# DNS 查询
nslookup hostname
Resolve-DnsName hostname
Resolve-DnsName hostname -Type MX

# 端口测试
Test-NetConnection hostname -Port 80
Test-NetConnection hostname -Port 443 -InformationLevel Detailed

# 网络连接
netstat -ano
netstat -b               # 显示程序名
Get-NetTCPConnection
Get-NetTCPConnection -State Established
Get-NetTCPConnection -LocalPort 80

# 路由表
route print
Get-NetRoute

# ARP 表
arp -a
Get-NetNeighbor

# 网络统计
netstat -s
Get-NetAdapterStatistics
```

### 8.3 防火墙管理

```powershell
# ==================== netsh 命令 ====================

# 查看防火墙状态
netsh advfirewall show allprofiles

# 开启/关闭防火墙
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles state off

# 添加入站规则
netsh advfirewall firewall add rule name="Allow HTTP" dir=in action=allow protocol=tcp localport=80

# 添加出站规则
netsh advfirewall firewall add rule name="Block Telnet" dir=out action=block protocol=tcp remoteport=23

# 删除规则
netsh advfirewall firewall delete rule name="Allow HTTP"

# 查看规则
netsh advfirewall firewall show rule name=all

# ==================== PowerShell 命令 ====================

# 查看防火墙配置
Get-NetFirewallProfile
Get-NetFirewallProfile -Name Domain,Public,Private

# 启用/禁用防火墙
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# 查看防火墙规则
Get-NetFirewallRule
Get-NetFirewallRule -Enabled True
Get-NetFirewallRule -Direction Inbound

# 创建入站规则
New-NetFirewallRule -DisplayName "Allow HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow

# 创建出站规则
New-NetFirewallRule -DisplayName "Block Telnet" -Direction Outbound -Protocol TCP -RemotePort 23 -Action Block

# 删除规则
Remove-NetFirewallRule -DisplayName "Allow HTTP"

# 启用/禁用规则
Enable-NetFirewallRule -DisplayName "Allow HTTP"
Disable-NetFirewallRule -DisplayName "Allow HTTP"

# 允许程序通过防火墙
New-NetFirewallRule -DisplayName "Allow MyApp" -Direction Inbound -Program "C:\MyApp\app.exe" -Action Allow
```

### 8.4 网络共享

```powershell
# ==================== CMD 命令 ====================

# 查看共享
net share

# 创建共享
net share ShareName=C:\Folder /grant:Everyone,Full

# 删除共享
net share ShareName /delete

# 连接网络驱动器
net use Z: \\Server\Share
net use Z: \\Server\Share /user:domain\username password

# 断开网络驱动器
net use Z: /delete

# 查看连接
net use

# ==================== PowerShell 命令 ====================

# 查看 SMB 共享
Get-SmbShare

# 创建共享
New-SmbShare -Name "ShareName" -Path "C:\Folder" -FullAccess "Everyone"

# 删除共享
Remove-SmbShare -Name "ShareName" -Force

# 设置共享权限
Grant-SmbShareAccess -Name "ShareName" -AccountName "Domain\User" -AccessRight Full
Revoke-SmbShareAccess -Name "ShareName" -AccountName "Domain\User"

# 映射网络驱动器
New-PSDrive -Name "Z" -PSProvider FileSystem -Root "\\Server\Share" -Persist

# 断开网络驱动器
Remove-PSDrive -Name "Z"

# 查看 SMB 连接
Get-SmbConnection
Get-SmbSession
```

### 8.5 远程桌面配置

```powershell
# 启用远程桌面
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0

# 允许防火墙规则
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# 设置网络级别身份验证
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 1

# 添加用户到远程桌面用户组
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "username"

# 查看远程桌面端口
Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "PortNumber"

# 修改远程桌面端口
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "PortNumber" -Value 3390

# 连接远程桌面
mstsc /v:hostname
mstsc /v:hostname:3390
```

---

## 9. 服务与进程管理

### 9.1 服务管理

```powershell
# ==================== CMD 命令 ====================

# 查看所有服务
sc query
sc query state= all

# 查看特定服务
sc query servicename
sc qc servicename        # 查看配置

# 启动/停止服务
sc start servicename
sc stop servicename

# 暂停/恢复服务
sc pause servicename
sc continue servicename

# 设置启动类型
sc config servicename start= auto      # 自动
sc config servicename start= demand    # 手动
sc config servicename start= disabled  # 禁用

# 创建服务
sc create servicename binPath= "C:\path\to\service.exe"

# 删除服务
sc delete servicename

# ==================== PowerShell 命令 ====================

# 查看所有服务
Get-Service
Get-Service | Where-Object Status -eq "Running"
Get-Service | Where-Object Status -eq "Stopped"

# 查看特定服务
Get-Service -Name "servicename"
Get-Service -DisplayName "*Windows*"

# 启动/停止服务
Start-Service -Name "servicename"
Stop-Service -Name "servicename"
Restart-Service -Name "servicename"

# 暂停/恢复服务
Suspend-Service -Name "servicename"
Resume-Service -Name "servicename"

# 设置启动类型
Set-Service -Name "servicename" -StartupType Automatic
Set-Service -Name "servicename" -StartupType Manual
Set-Service -Name "servicename" -StartupType Disabled

# 创建服务
New-Service -Name "servicename" -BinaryPathName "C:\path\to\service.exe" -DisplayName "Service Display Name" -StartupType Automatic

# 删除服务
Remove-Service -Name "servicename"  # PowerShell 6.0+
# 或使用 sc delete servicename

# 查看服务依赖
Get-Service -Name "servicename" -DependentServices
Get-Service -Name "servicename" -RequiredServices
```

### 9.2 进程管理

```powershell
# ==================== CMD 命令 ====================

# 查看进程
tasklist
tasklist /v              # 详细信息
tasklist /svc            # 显示服务
tasklist /m              # 显示模块

# 按名称过滤
tasklist /fi "imagename eq notepad.exe"
tasklist /fi "status eq running"
tasklist /fi "memusage gt 100000"

# 结束进程
taskkill /im notepad.exe
taskkill /pid 1234
taskkill /f /im notepad.exe  # 强制结束
taskkill /f /t /im cmd.exe   # 结束进程树

# ==================== PowerShell 命令 ====================

# 查看进程
Get-Process
Get-Process -Name "notepad"
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10

# 详细信息
Get-Process -Name "notepad" | Format-List *
Get-Process -Name "notepad" | Select-Object Name, Id, CPU, WorkingSet64

# 结束进程
Stop-Process -Name "notepad"
Stop-Process -Id 1234
Stop-Process -Name "notepad" -Force

# 启动进程
Start-Process notepad
Start-Process notepad -ArgumentList "file.txt"
Start-Process powershell -Verb RunAs  # 以管理员身份运行

# 等待进程结束
Start-Process notepad -Wait
$process = Start-Process notepad -PassThru
$process.WaitForExit()

# 查看进程详细信息
Get-CimInstance Win32_Process | Where-Object Name -eq "notepad.exe"
Get-CimInstance Win32_Process | Select-Object Name, ProcessId, CommandLine
```

### 9.3 启动项管理

```powershell
# 查看启动项
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location

# 注册表启动项位置
# HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
# HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
# HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
# HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

# 查看注册表启动项
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# 添加启动项
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "MyApp" -Value "C:\MyApp\app.exe"

# 删除启动项
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "MyApp"

# 启动文件夹
# C:\Users\<用户名>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
# C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup

# 使用 msconfig 管理启动项
msconfig
```

---

## 10. 注册表管理

### 10.1 注册表结构

```
┌─────────────────────────────────────────────────────────────────┐
│                    Windows 注册表结构                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   HKEY_CLASSES_ROOT (HKCR)                                      │
│   └── 文件关联和 COM 对象注册                                   │
│                                                                 │
│   HKEY_CURRENT_USER (HKCU)                                      │
│   └── 当前用户的配置                                            │
│       ├── Software\     - 用户软件设置                          │
│       ├── Environment\  - 用户环境变量                          │
│       └── Control Panel\ - 控制面板设置                         │
│                                                                 │
│   HKEY_LOCAL_MACHINE (HKLM)                                     │
│   └── 计算机范围的配置                                          │
│       ├── SOFTWARE\     - 软件设置                              │
│       ├── SYSTEM\       - 系统配置                              │
│       ├── HARDWARE\     - 硬件信息                              │
│       └── SECURITY\     - 安全设置                              │
│                                                                 │
│   HKEY_USERS (HKU)                                              │
│   └── 所有用户的配置                                            │
│                                                                 │
│   HKEY_CURRENT_CONFIG (HKCC)                                    │
│   └── 当前硬件配置                                              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 10.2 注册表操作

```powershell
# ==================== CMD 命令 ====================

# 查询注册表
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion
reg query HKCU\Software /s  # 递归查询

# 添加键值
reg add HKCU\Software\MyApp /v Setting1 /t REG_SZ /d "Value1"
reg add HKCU\Software\MyApp /v Setting2 /t REG_DWORD /d 1

# 修改键值
reg add HKCU\Software\MyApp /v Setting1 /t REG_SZ /d "NewValue" /f

# 删除键值
reg delete HKCU\Software\MyApp /v Setting1 /f

# 删除键
reg delete HKCU\Software\MyApp /f

# 导出注册表
reg export HKCU\Software\MyApp backup.reg

# 导入注册表
reg import backup.reg

# ==================== PowerShell 命令 ====================

# 查看注册表
Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"

# 获取特定值
Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion" -Name "ProgramFilesDir"

# 创建键
New-Item -Path "HKCU:\Software\MyApp"

# 设置值
Set-ItemProperty -Path "HKCU:\Software\MyApp" -Name "Setting1" -Value "Value1"
New-ItemProperty -Path "HKCU:\Software\MyApp" -Name "Setting2" -Value 1 -PropertyType DWord

# 删除值
Remove-ItemProperty -Path "HKCU:\Software\MyApp" -Name "Setting1"

# 删除键
Remove-Item -Path "HKCU:\Software\MyApp" -Recurse

# 测试键是否存在
Test-Path -Path "HKCU:\Software\MyApp"

# 注册表值类型
# REG_SZ        - 字符串
# REG_EXPAND_SZ - 可扩展字符串
# REG_MULTI_SZ  - 多字符串
# REG_DWORD     - 32位数字
# REG_QWORD     - 64位数字
# REG_BINARY    - 二进制数据
```

### 10.3 常用注册表位置

```powershell
# 系统信息
HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion

# 启动项
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# 卸载程序
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall

# 环境变量
HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
HKCU:\Environment

# 服务
HKLM:\SYSTEM\CurrentControlSet\Services

# 网络配置
HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters

# 远程桌面
HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server

# Windows 更新
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate

# 防火墙
HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy
```

---

## 11. 组策略管理

### 11.1 组策略概述

组策略（Group Policy）是 Windows 中用于集中管理用户和计算机配置的强大工具。它可以控制从桌面背景到安全设置的几乎所有方面。

```
┌─────────────────────────────────────────────────────────────────┐
│                    组策略类型                                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   本地组策略 (Local Group Policy)                               │
│   ├── 适用于单台计算机                                          │
│   ├── 使用 gpedit.msc 管理                                      │
│   └── 存储在 %SystemRoot%\System32\GroupPolicy                  │
│                                                                 │
│   域组策略 (Domain Group Policy)                                │
│   ├── 适用于 Active Directory 环境                              │
│   ├── 使用 GPMC (gpmc.msc) 管理                                 │
│   └── 存储在域控制器的 SYSVOL 共享                              │
│                                                                 │
│   策略应用顺序 (LSDOU)                                          │
│   1. Local (本地)                                               │
│   2. Site (站点)                                                │
│   3. Domain (域)                                                │
│   4. OU (组织单位)                                              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 11.2 本地组策略编辑器

```powershell
# 打开本地组策略编辑器
gpedit.msc

# 主要配置区域：
# 计算机配置
#   ├── 软件设置
#   ├── Windows 设置
#   │   ├── 脚本（启动/关机）
#   │   └── 安全设置
#   └── 管理模板
#       ├── 控制面板
#       ├── 网络
#       ├── 系统
#       └── Windows 组件

# 用户配置
#   ├── 软件设置
#   ├── Windows 设置
#   │   ├── 脚本（登录/注销）
#   │   └── 安全设置
#   └── 管理模板
#       ├── 控制面板
#       ├── 桌面
#       ├── 开始菜单和任务栏
#       └── 系统
```

### 11.3 常用组策略设置

```powershell
# 使用 PowerShell 管理组策略（需要 GroupPolicy 模块）
Import-Module GroupPolicy

# 查看所有 GPO
Get-GPO -All

# 创建 GPO
New-GPO -Name "Security Settings"

# 链接 GPO 到 OU
New-GPLink -Name "Security Settings" -Target "OU=Computers,DC=domain,DC=com"

# 备份 GPO
Backup-GPO -Name "Security Settings" -Path "C:\GPOBackup"

# 还原 GPO
Restore-GPO -Name "Security Settings" -Path "C:\GPOBackup"

# 生成 GPO 报告
Get-GPOReport -Name "Security Settings" -ReportType HTML -Path "C:\report.html"

# 强制更新组策略
gpupdate /force

# 查看应用的策略
gpresult /r
gpresult /h report.html
```

### 11.4 安全策略配置

```powershell
# 打开本地安全策略
secpol.msc

# 主要安全设置：
# 账户策略
#   ├── 密码策略
#   │   ├── 密码最短长度
#   │   ├── 密码复杂性要求
#   │   └── 密码最长使用期限
#   └── 账户锁定策略
#       ├── 账户锁定阈值
#       └── 账户锁定时间

# 本地策略
#   ├── 审核策略
#   ├── 用户权限分配
#   └── 安全选项

# 使用 secedit 导出/导入安全策略
secedit /export /cfg security.inf
secedit /configure /db security.sdb /cfg security.inf

# 使用 PowerShell 配置安全策略
# 设置密码策略
net accounts /minpwlen:12 /maxpwage:90 /minpwage:1 /uniquepw:5

# 查看账户策略
net accounts
```

---

## 12. Active Directory 基础

### 12.1 AD 概述

Active Directory（活动目录）是 Windows Server 的目录服务，用于集中管理网络中的用户、计算机和其他资源。

```
┌─────────────────────────────────────────────────────────────────┐
│                    Active Directory 结构                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   林 (Forest)                                                   │
│   └── 域树 (Domain Tree)                                        │
│       └── 域 (Domain)                                           │
│           ├── 组织单位 (OU)                                     │
│           │   ├── 用户 (Users)                                  │
│           │   ├── 计算机 (Computers)                            │
│           │   └── 组 (Groups)                                   │
│           └── 容器 (Container)                                  │
│                                                                 │
│   域控制器 (Domain Controller)                                  │
│   ├── 存储 AD 数据库                                            │
│   ├── 处理身份验证                                              │
│   └── 复制 AD 数据                                              │
│                                                                 │
│   全局编录 (Global Catalog)                                     │
│   └── 存储林中所有对象的部分属性                                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 12.2 AD 管理命令

```powershell
# 导入 AD 模块
Import-Module ActiveDirectory

# ==================== 用户管理 ====================

# 查看所有用户
Get-ADUser -Filter *
Get-ADUser -Filter * -Properties *

# 查看特定用户
Get-ADUser -Identity "username"
Get-ADUser -Identity "username" -Properties *

# 搜索用户
Get-ADUser -Filter {Name -like "*john*"}
Get-ADUser -Filter {Enabled -eq $false}

# 创建用户
New-ADUser -Name "John Doe" -SamAccountName "jdoe" -UserPrincipalName "jdoe@domain.com" -Path "OU=Users,DC=domain,DC=com" -AccountPassword (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force) -Enabled $true

# 修改用户
Set-ADUser -Identity "jdoe" -Description "IT Department"
Set-ADUser -Identity "jdoe" -PasswordNeverExpires $true

# 禁用/启用用户
Disable-ADAccount -Identity "jdoe"
Enable-ADAccount -Identity "jdoe"

# 解锁用户
Unlock-ADAccount -Identity "jdoe"

# 重置密码
Set-ADAccountPassword -Identity "jdoe" -Reset -NewPassword (ConvertTo-SecureString "NewP@ssw0rd" -AsPlainText -Force)

# 删除用户
Remove-ADUser -Identity "jdoe"

# ==================== 组管理 ====================

# 查看所有组
Get-ADGroup -Filter *

# 查看组成员
Get-ADGroupMember -Identity "Domain Admins"

# 创建组
New-ADGroup -Name "IT Staff" -GroupScope Global -GroupCategory Security -Path "OU=Groups,DC=domain,DC=com"

# 添加成员到组
Add-ADGroupMember -Identity "IT Staff" -Members "jdoe"

# 从组中移除成员
Remove-ADGroupMember -Identity "IT Staff" -Members "jdoe"

# ==================== 计算机管理 ====================

# 查看所有计算机
Get-ADComputer -Filter *

# 查看特定计算机
Get-ADComputer -Identity "PC001" -Properties *

# 禁用计算机账户
Disable-ADAccount -Identity "PC001$"

# ==================== OU 管理 ====================

# 查看所有 OU
Get-ADOrganizationalUnit -Filter *

# 创建 OU
New-ADOrganizationalUnit -Name "IT Department" -Path "DC=domain,DC=com"

# 移动对象到 OU
Move-ADObject -Identity "CN=John Doe,OU=Users,DC=domain,DC=com" -TargetPath "OU=IT Department,DC=domain,DC=com"
```

### 12.3 域加入与退出

```powershell
# 加入域
Add-Computer -DomainName "domain.com" -Credential (Get-Credential) -Restart

# 退出域
Remove-Computer -UnjoinDomainCredential (Get-Credential) -WorkgroupName "WORKGROUP" -Restart

# 重命名计算机并加入域
Add-Computer -DomainName "domain.com" -NewName "PC001" -Credential (Get-Credential) -Restart

# 查看域信息
Get-ADDomain
Get-ADForest

# 查看域控制器
Get-ADDomainController -Filter *

# 查看 FSMO 角色
Get-ADDomain | Select-Object InfrastructureMaster, RIDMaster, PDCEmulator
Get-ADForest | Select-Object DomainNamingMaster, SchemaMaster
```

---

## 13. Windows 安全配置

### 13.1 Windows Defender

```powershell
# 查看 Defender 状态
Get-MpComputerStatus

# 更新病毒定义
Update-MpSignature

# 快速扫描
Start-MpScan -ScanType QuickScan

# 完整扫描
Start-MpScan -ScanType FullScan

# 自定义扫描
Start-MpScan -ScanType CustomScan -ScanPath "C:\Users"

# 添加排除项
Add-MpPreference -ExclusionPath "C:\MyApp"
Add-MpPreference -ExclusionExtension ".log"
Add-MpPreference -ExclusionProcess "myapp.exe"

# 查看排除项
Get-MpPreference | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess

# 移除排除项
Remove-MpPreference -ExclusionPath "C:\MyApp"

# 启用/禁用实时保护
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableRealtimeMonitoring $true

# 查看威胁历史
Get-MpThreatDetection
Get-MpThreat
```

### 13.2 BitLocker 加密

```powershell
# 查看 BitLocker 状态
Get-BitLockerVolume
manage-bde -status

# 启用 BitLocker
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -RecoveryPasswordProtector

# 使用 TPM 保护
Enable-BitLocker -MountPoint "C:" -TpmProtector

# 使用密码保护
$SecureString = ConvertTo-SecureString "password" -AsPlainText -Force
Enable-BitLocker -MountPoint "D:" -PasswordProtector -Password $SecureString

# 备份恢复密钥到 AD
Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $KeyProtectorId

# 暂停/恢复 BitLocker
Suspend-BitLocker -MountPoint "C:"
Resume-BitLocker -MountPoint "C:"

# 禁用 BitLocker
Disable-BitLocker -MountPoint "C:"

# 解锁驱动器
Unlock-BitLocker -MountPoint "D:" -Password $SecureString
```

### 13.3 Windows 更新

```powershell
# 使用 PSWindowsUpdate 模块
Install-Module PSWindowsUpdate

# 检查更新
Get-WindowsUpdate

# 安装所有更新
Install-WindowsUpdate -AcceptAll -AutoReboot

# 安装特定更新
Install-WindowsUpdate -KBArticleID KB5001234

# 隐藏更新
Hide-WindowsUpdate -KBArticleID KB5001234

# 查看更新历史
Get-WUHistory

# 使用 WSUS
# 配置 WSUS 服务器
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -Value "http://wsus-server:8530"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUStatusServer" -Value "http://wsus-server:8530"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Value 1

# 手动检查更新
wuauclt /detectnow
usoclient StartScan
```

### 13.4 审核策略

```powershell
# 查看审核策略
auditpol /get /category:*

# 设置审核策略
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable

# 常用审核类别
# Account Logon - 账户登录
# Account Management - 账户管理
# Logon/Logoff - 登录/注销
# Object Access - 对象访问
# Policy Change - 策略更改
# Privilege Use - 特权使用
# System - 系统事件

# 备份审核策略
auditpol /backup /file:audit_backup.csv

# 还原审核策略
auditpol /restore /file:audit_backup.csv

# 清除审核策略
auditpol /clear
```

---

## 14. 系统监控与日志

### 14.1 性能监控

```powershell
# 任务管理器
taskmgr

# 资源监视器
resmon

# 性能监视器
perfmon

# 查看 CPU 使用率
Get-Counter '\Processor(_Total)\% Processor Time'

# 查看内存使用
Get-Counter '\Memory\Available MBytes'
Get-Counter '\Memory\% Committed Bytes In Use'

# 查看磁盘使用
Get-Counter '\PhysicalDisk(_Total)\% Disk Time'
Get-Counter '\PhysicalDisk(_Total)\Disk Reads/sec'
Get-Counter '\PhysicalDisk(_Total)\Disk Writes/sec'

# 查看网络使用
Get-Counter '\Network Interface(*)\Bytes Total/sec'

# 持续监控
Get-Counter -Counter '\Processor(_Total)\% Processor Time' -Continuous -SampleInterval 2

# 导出性能数据
Get-Counter -Counter '\Processor(_Total)\% Processor Time' -SampleInterval 5 -MaxSamples 10 | Export-Counter -Path "perf.csv" -FileFormat CSV

# 系统信息
Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory
Get-CimInstance Win32_Processor | Select-Object Name, LoadPercentage
Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, Size, FreeSpace
```

### 14.2 事件日志

```powershell
# 查看事件日志
Get-EventLog -List
Get-EventLog -LogName System -Newest 10
Get-EventLog -LogName Application -Newest 10
Get-EventLog -LogName Security -Newest 10

# 使用 Get-WinEvent（推荐）
Get-WinEvent -ListLog *
Get-WinEvent -LogName System -MaxEvents 10
Get-WinEvent -LogName Security -MaxEvents 10

# 过滤事件
Get-WinEvent -FilterHashtable @{LogName='System'; Level=2}  # 错误
Get-WinEvent -FilterHashtable @{LogName='System'; Level=3}  # 警告
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624}  # 登录成功
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625}  # 登录失败

# 按时间过滤
$StartTime = (Get-Date).AddDays(-1)
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$StartTime}

# 导出事件日志
wevtutil epl System C:\Logs\System.evtx
Get-WinEvent -LogName System | Export-Csv -Path "system_events.csv"

# 清除事件日志
Clear-EventLog -LogName Application
wevtutil cl System

# 常用事件 ID
# 4624 - 登录成功
# 4625 - 登录失败
# 4634 - 注销
# 4648 - 使用显式凭据登录
# 4672 - 特权登录
# 4720 - 创建用户
# 4726 - 删除用户
# 4732 - 添加到组
# 4733 - 从组中移除
# 7045 - 安装服务
```

### 14.3 系统日志位置

```
Windows 日志文件位置：
├── %SystemRoot%\System32\winevt\Logs\
│   ├── Application.evtx      - 应用程序日志
│   ├── Security.evtx         - 安全日志
│   ├── System.evtx           - 系统日志
│   ├── Setup.evtx            - 安装日志
│   └── ForwardedEvents.evtx  - 转发的事件
├── %SystemRoot%\Logs\
│   ├── CBS\                  - 组件服务日志
│   ├── DISM\                 - DISM 日志
│   └── WindowsUpdate\        - Windows 更新日志
└── %SystemRoot%\Debug\
    └── NetSetup.LOG          - 网络设置日志
```

---

## 15. 故障排除与修复

### 15.1 系统文件检查

```powershell
# 系统文件检查器 (SFC)
sfc /scannow                    # 扫描并修复
sfc /verifyonly                 # 仅验证
sfc /scanfile=C:\Windows\System32\file.dll  # 扫描特定文件

# DISM 修复系统映像
DISM /Online /Cleanup-Image /CheckHealth      # 检查健康状态
DISM /Online /Cleanup-Image /ScanHealth       # 扫描健康状态
DISM /Online /Cleanup-Image /RestoreHealth    # 修复系统映像

# 使用 Windows 更新作为源
DISM /Online /Cleanup-Image /RestoreHealth /Source:wim:D:\sources\install.wim:1

# 清理组件存储
DISM /Online /Cleanup-Image /StartComponentCleanup
DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase

# 检查 Windows 映像信息
DISM /Get-ImageInfo /ImageFile:D:\sources\install.wim
```

### 15.2 启动修复

```powershell
# 进入恢复环境
# 1. 设置 -> 更新和安全 -> 恢复 -> 高级启动
# 2. 按住 Shift 点击重启
# 3. 从安装介质启动

# 修复启动记录
bootrec /fixmbr           # 修复主引导记录
bootrec /fixboot          # 修复启动扇区
bootrec /scanos           # 扫描 Windows 安装
bootrec /rebuildbcd       # 重建 BCD

# 修复 BCD
bcdedit /enum             # 查看 BCD 配置
bcdedit /export C:\BCD_Backup  # 备份 BCD
bcdedit /import C:\BCD_Backup  # 还原 BCD

# 重建 BCD
bcdboot C:\Windows /s C: /f ALL

# 修复 EFI 启动
# 在恢复环境中：
diskpart
select disk 0
list vol
select vol 1              # EFI 分区
assign letter=S
exit
bcdboot C:\Windows /s S: /f UEFI

# 安全模式启动
bcdedit /set {default} safeboot minimal      # 最小安全模式
bcdedit /set {default} safeboot network      # 带网络的安全模式
bcdedit /deletevalue {default} safeboot      # 恢复正常启动
```

### 15.3 磁盘检查与修复

```powershell
# 检查磁盘错误
chkdsk C:                 # 只读检查
chkdsk C: /f              # 修复错误
chkdsk C: /r              # 定位坏扇区并恢复
chkdsk C: /x              # 强制卸载卷
chkdsk C: /b              # 重新评估坏簇

# 计划下次启动时检查
chkdsk C: /f /r /x

# 使用 PowerShell
Repair-Volume -DriveLetter C -Scan
Repair-Volume -DriveLetter C -OfflineScanAndFix

# 磁盘碎片整理
defrag C: /O              # 优化
defrag C: /U /V           # 详细输出

# 使用 PowerShell
Optimize-Volume -DriveLetter C -Defrag
Optimize-Volume -DriveLetter C -ReTrim  # SSD 优化
```

### 15.4 网络故障排除

```powershell
# 重置网络
netsh winsock reset
netsh int ip reset
ipconfig /release
ipconfig /renew
ipconfig /flushdns

# 重置 TCP/IP 栈
netsh int tcp reset

# 重置防火墙
netsh advfirewall reset

# 网络诊断
# 检查网络连接
Test-NetConnection
Test-NetConnection google.com
Test-NetConnection google.com -Port 443 -InformationLevel Detailed

# 检查 DNS
Resolve-DnsName google.com
nslookup google.com

# 检查路由
tracert google.com
pathping google.com

# 查看网络配置
Get-NetIPConfiguration
Get-NetAdapter | Format-Table Name, Status, LinkSpeed

# 禁用/启用网卡
Disable-NetAdapter -Name "Ethernet" -Confirm:$false
Enable-NetAdapter -Name "Ethernet"

# 重置网络适配器
Restart-NetAdapter -Name "Ethernet"
```

### 15.5 蓝屏故障分析

```powershell
# 蓝屏转储文件位置
# %SystemRoot%\MEMORY.DMP        - 完整内存转储
# %SystemRoot%\Minidump\         - 小型内存转储

# 配置转储类型
# 系统属性 -> 高级 -> 启动和故障恢复 -> 设置

# 使用 WinDbg 分析
# 1. 安装 Windows SDK 或 WinDbg Preview
# 2. 打开转储文件
# 3. 运行 !analyze -v

# 常见蓝屏错误代码
# IRQL_NOT_LESS_OR_EQUAL (0x0000000A) - 驱动问题
# PAGE_FAULT_IN_NONPAGED_AREA (0x00000050) - 内存问题
# SYSTEM_SERVICE_EXCEPTION (0x0000003B) - 系统服务异常
# KERNEL_DATA_INPAGE_ERROR (0x0000007A) - 磁盘问题
# DRIVER_IRQL_NOT_LESS_OR_EQUAL (0x000000D1) - 驱动问题
# CRITICAL_PROCESS_DIED (0x000000EF) - 关键进程终止

# 查看系统事件日志中的蓝屏记录
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WER-SystemErrorReporting'} | Select-Object -First 5

# 使用 BlueScreenView 工具分析
# https://www.nirsoft.net/utils/blue_screen_view.html
```

### 15.6 系统还原

```powershell
# 查看还原点
Get-ComputerRestorePoint

# 创建还原点
Checkpoint-Computer -Description "Before Changes" -RestorePointType MODIFY_SETTINGS

# 启用系统还原
Enable-ComputerRestore -Drive "C:\"

# 禁用系统还原
Disable-ComputerRestore -Drive "C:\"

# 还原系统（需要重启）
Restore-Computer -RestorePoint 1

# 使用 rstrui.exe 图形界面
rstrui.exe

# 配置系统还原空间
vssadmin list shadowstorage
vssadmin resize shadowstorage /for=C: /on=C: /maxsize=10GB
```

---

## 16. 常见错误与解决方案

### 16.1 系统错误

| 错误 | 原因 | 解决方案 |
|------|------|----------|
| 0x80070005 | 访问被拒绝 | 以管理员身份运行 |
| 0x80070057 | 参数错误 | 检查命令参数 |
| 0x8007000E | 内存不足 | 关闭其他程序，增加内存 |
| 0x80070002 | 文件未找到 | 检查文件路径 |
| 0x80070020 | 文件被占用 | 关闭占用程序 |
| 0x80004005 | 未指定错误 | 检查权限和依赖 |
| 0x800F081F | 源文件未找到 | 使用 DISM 修复 |

### 16.2 网络错误

| 错误 | 原因 | 解决方案 |
|------|------|----------|
| DNS_PROBE_FINISHED_NXDOMAIN | DNS 解析失败 | 更换 DNS 服务器 |
| ERR_CONNECTION_REFUSED | 连接被拒绝 | 检查防火墙和服务 |
| ERR_CONNECTION_TIMED_OUT | 连接超时 | 检查网络连接 |
| 网络路径未找到 | 共享不可访问 | 检查共享权限和网络 |
| RPC 服务器不可用 | RPC 服务问题 | 启动 RPC 服务 |

```powershell
# DNS 问题解决
ipconfig /flushdns
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 8.8.8.8,8.8.4.4

# 网络重置
netsh winsock reset
netsh int ip reset

# 检查网络服务
Get-Service -Name "Dnscache","DHCP","NlaSvc" | Start-Service
```

### 16.3 权限错误

```powershell
# 错误：访问被拒绝
# 解决方案 1：以管理员身份运行
Start-Process powershell -Verb RunAs

# 解决方案 2：获取所有权
takeown /f "C:\path\to\file" /r /d y
icacls "C:\path\to\file" /grant administrators:F /t

# 解决方案 3：检查 UAC 设置
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA

# 错误：无法删除文件
# 解决方案：使用安全模式或命令行
del /f /q "C:\path\to\file"
Remove-Item -Path "C:\path\to\file" -Force
```

### 16.4 服务错误

```powershell
# 错误：服务无法启动
# 检查服务依赖
sc qc servicename
Get-Service servicename -DependentServices

# 检查服务账户
Get-CimInstance Win32_Service | Where-Object Name -eq "servicename" | Select-Object Name, StartName

# 重置服务
sc config servicename start= auto
sc failure servicename reset= 86400 actions= restart/60000/restart/60000/restart/60000

# 错误：服务标记为删除
# 重启计算机或关闭服务管理器

# 错误：服务没有响应
# 强制停止
taskkill /f /fi "services eq servicename"
Stop-Process -Name "processname" -Force
```

### 16.5 Windows 更新错误

| 错误代码 | 说明 | 解决方案 |
|----------|------|----------|
| 0x80240017 | 不适用于此系统 | 检查系统版本 |
| 0x8024402C | 无法连接到更新服务 | 检查网络和代理 |
| 0x80070643 | 安装失败 | 运行 Windows 更新疑难解答 |
| 0x800F0922 | 系统保留分区空间不足 | 扩展系统保留分区 |
| 0x80073712 | 组件存储损坏 | 运行 DISM 修复 |

```powershell
# Windows 更新疑难解答
# 设置 -> 更新和安全 -> 疑难解答 -> Windows 更新

# 重置 Windows 更新组件
net stop wuauserv
net stop cryptSvc
net stop bits
net stop msiserver
ren C:\Windows\SoftwareDistribution SoftwareDistribution.old
ren C:\Windows\System32\catroot2 catroot2.old
net start wuauserv
net start cryptSvc
net start bits
net start msiserver

# 清除更新缓存
Remove-Item -Path "C:\Windows\SoftwareDistribution\*" -Recurse -Force
Remove-Item -Path "C:\Windows\System32\catroot2\*" -Recurse -Force

# 使用 DISM 修复
DISM /Online /Cleanup-Image /RestoreHealth
sfc /scannow
```

---

## 17. 最佳实践与技巧

### 17.1 系统优化

```powershell
# 禁用不必要的服务
Set-Service -Name "DiagTrack" -StartupType Disabled  # 诊断跟踪
Set-Service -Name "dmwappushservice" -StartupType Disabled  # WAP 推送

# 清理临时文件
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue

# 清理磁盘
cleanmgr /d C: /verylowdisk

# 使用 PowerShell 清理
Get-ChildItem -Path "C:\Windows\Temp" -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path "$env:TEMP" -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue

# 禁用休眠（节省磁盘空间）
powercfg /hibernate off

# 调整虚拟内存
# 系统属性 -> 高级 -> 性能设置 -> 高级 -> 虚拟内存

# 禁用视觉效果
# 系统属性 -> 高级 -> 性能设置 -> 调整为最佳性能
```

### 17.2 安全最佳实践

```powershell
# 1. 保持系统更新
Install-WindowsUpdate -AcceptAll

# 2. 启用防火墙
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# 3. 启用 Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $false

# 4. 配置强密码策略
net accounts /minpwlen:12 /maxpwage:90 /minpwage:1 /uniquepw:5

# 5. 禁用不必要的服务
Set-Service -Name "RemoteRegistry" -StartupType Disabled

# 6. 启用审核策略
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# 7. 限制管理员账户
Disable-LocalUser -Name "Administrator"

# 8. 配置账户锁定策略
net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30

# 9. 禁用 SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# 10. 启用 BitLocker
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -RecoveryPasswordProtector
```

### 17.3 备份策略

```powershell
# 使用 Windows 备份
wbadmin start backup -backupTarget:D: -include:C: -allCritical -quiet

# 创建系统映像
wbadmin start backup -backupTarget:\\server\share -include:C: -allCritical -quiet

# 备份注册表
reg export HKLM\SOFTWARE backup_software.reg
reg export HKCU backup_user.reg

# 备份组策略
Backup-GPO -All -Path "C:\GPOBackup"

# 使用 robocopy 备份文件
robocopy C:\Data D:\Backup\Data /MIR /R:3 /W:10 /LOG:backup.log

# 计划备份任务
$action = New-ScheduledTaskAction -Execute "wbadmin" -Argument "start backup -backupTarget:D: -include:C: -allCritical -quiet"
$trigger = New-ScheduledTaskTrigger -Daily -At 2am
Register-ScheduledTask -TaskName "DailyBackup" -Action $action -Trigger $trigger -User "SYSTEM"
```

### 17.4 常用快捷键

| 快捷键 | 功能 |
|--------|------|
| Win + R | 运行对话框 |
| Win + E | 文件资源管理器 |
| Win + I | 设置 |
| Win + X | 快速链接菜单 |
| Win + L | 锁定屏幕 |
| Win + D | 显示桌面 |
| Win + Tab | 任务视图 |
| Win + Shift + S | 截图工具 |
| Ctrl + Shift + Esc | 任务管理器 |
| Win + Pause | 系统属性 |
| Win + V | 剪贴板历史 |
| Win + . | 表情符号面板 |

### 17.5 常用运行命令

| 命令 | 功能 |
|------|------|
| cmd | 命令提示符 |
| powershell | PowerShell |
| regedit | 注册表编辑器 |
| gpedit.msc | 组策略编辑器 |
| secpol.msc | 本地安全策略 |
| services.msc | 服务管理 |
| devmgmt.msc | 设备管理器 |
| diskmgmt.msc | 磁盘管理 |
| compmgmt.msc | 计算机管理 |
| eventvwr.msc | 事件查看器 |
| taskschd.msc | 任务计划程序 |
| perfmon.msc | 性能监视器 |
| lusrmgr.msc | 本地用户和组 |
| ncpa.cpl | 网络连接 |
| appwiz.cpl | 程序和功能 |
| sysdm.cpl | 系统属性 |
| firewall.cpl | Windows 防火墙 |
| control | 控制面板 |
| msconfig | 系统配置 |
| msinfo32 | 系统信息 |
| dxdiag | DirectX 诊断 |
| cleanmgr | 磁盘清理 |
| mstsc | 远程桌面连接 |

---

## 附录：命令速查表

### 系统信息

```powershell
systeminfo                    # 系统信息
hostname                      # 计算机名
whoami /all                   # 当前用户信息
Get-ComputerInfo              # 详细系统信息
```

### 用户管理

```powershell
net user                      # 用户列表
net user username /add        # 创建用户
net user username /delete     # 删除用户
net localgroup administrators username /add  # 添加到管理员组
```

### 网络

```powershell
ipconfig /all                 # IP 配置
ping hostname                 # 连通性测试
netstat -ano                  # 网络连接
nslookup hostname             # DNS 查询
```

### 服务

```powershell
sc query                      # 服务列表
sc start servicename          # 启动服务
sc stop servicename           # 停止服务
Get-Service                   # PowerShell 查看服务
```

### 进程

```powershell
tasklist                      # 进程列表
taskkill /im name.exe /f      # 结束进程
Get-Process                   # PowerShell 查看进程
```

### 文件操作

```powershell
dir                           # 列出文件
copy source dest              # 复制文件
move source dest              # 移动文件
del filename                  # 删除文件
mkdir dirname                 # 创建目录
```

---

> 本笔记持续更新中，最后更新：2025年12月
> 
> Windows 是微软公司的注册商标。
> 本笔记仅供学习和参考使用。
