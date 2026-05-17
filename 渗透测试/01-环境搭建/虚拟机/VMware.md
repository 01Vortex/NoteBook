# VMware 虚拟化平台

> VMware 是业界领先的虚拟化平台，用于创建和管理虚拟机环境
> 本笔记基于 VMware Workstation Pro 17.x / VMware Fusion 13.x

---

## 目录

1. [基础概念](#1-基础概念)
2. [安装与配置](#2-安装与配置)
3. [虚拟机创建](#3-虚拟机创建)
4. [网络配置](#4-网络配置)
5. [快照与克隆](#5-快照与克隆)
6. [共享文件夹](#6-共享文件夹)
7. [性能优化](#7-性能优化)
8. [高级功能](#8-高级功能)
9. [命令行工具](#9-命令行工具)
10. [渗透测试环境搭建](#10-渗透测试环境搭建)
11. [常见错误与解决方案](#11-常见错误与解决方案)
12. [最佳实践](#12-最佳实践)

---

## 1. 基础概念

### 1.1 什么是 VMware？

VMware 是一款虚拟化软件，允许在一台物理计算机上运行多个操作系统。

**核心产品线：**
- **VMware Workstation Pro**：Windows/Linux 桌面虚拟化
- **VMware Fusion**：macOS 桌面虚拟化
- **VMware ESXi**：企业级裸机虚拟化
- **VMware Player**：免费精简版（已停止更新）

### 1.2 核心概念

**虚拟机（VM）：** 模拟的完整计算机系统
**宿主机（Host）：** 运行 VMware 的物理机器
**客户机（Guest）：** 虚拟机内运行的操作系统
**快照（Snapshot）：** 虚拟机某一时刻的完整状态
**克隆（Clone）：** 复制虚拟机的副本

### 1.3 虚拟化类型

```
类型1（裸机虚拟化）：ESXi
  └─ 直接运行在硬件上

类型2（托管虚拟化）：Workstation/Fusion
  └─ 运行在操作系统之上
```

---

## 2. 安装与配置

### 2.1 系统要求

**最低配置：**
- CPU：64位处理器，支持虚拟化（Intel VT-x / AMD-V）
- 内存：4GB RAM（推荐 8GB+）
- 硬盘：1GB 安装空间 + 虚拟机存储空间
- 操作系统：Windows 10/11, Linux, macOS

**检查 CPU 虚拟化支持：**

```powershell
# Windows - PowerShell
systeminfo | findstr /i "虚拟化"
# 或
Get-ComputerInfo | Select-Object HyperVisorPresent, HyperVRequirementVirtualizationFirmwareEnabled

# Linux
egrep -c '(vmx|svm)' /proc/cpuinfo
# 输出 > 0 表示支持

# 检查是否启用
lscpu | grep Virtualization
```

### 2.2 下载与安装

**官方下载：**
```
https://www.vmware.com/products/workstation-pro.html
```

**安装步骤（Windows）：**

```powershell
# 1. 以管理员身份运行安装程序
.\VMware-workstation-full-17.x.x-xxxxx.exe

# 2. 安装选项
# - 增强型键盘驱动（推荐）
# - 添加到系统路径
# - 创建桌面快捷方式

# 3. 许可证密钥（试用或购买）
# 试用期：30天
```

**静默安装：**

```powershell
# Windows 静默安装
.\VMware-workstation-full-17.x.x-xxxxx.exe /s /v"/qn EULAS_AGREED=1 SERIALNUMBER=XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"

# Linux 静默安装
sudo sh VMware-Workstation-Full-17.x.x-xxxxx.x86_64.bundle --console --required --eulas-agreed
```

### 2.3 首次配置

**启用虚拟化技术（BIOS/UEFI）：**

```
1. 重启电脑，进入 BIOS/UEFI（通常按 F2/F12/Del）
2. 找到以下选项并启用：
   - Intel: Intel Virtualization Technology (VT-x)
   - AMD: AMD-V / SVM Mode
3. 保存并退出
```

**Windows 禁用 Hyper-V（重要）：**

```powershell
# VMware 与 Hyper-V 冲突，需要禁用 Hyper-V

# 方法1：通过 PowerShell（管理员）
Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All

# 方法2：通过 DISM
dism.exe /Online /Disable-Feature:Microsoft-Hyper-V

# 方法3：通过控制面板
# 控制面板 → 程序 → 启用或关闭 Windows 功能 → 取消勾选 Hyper-V

# 重启电脑生效
```

**配置默认路径：**

```
Edit → Preferences → Workspace
- Default location for virtual machines: D:\VMware\VMs
- Keep VMs running after Workstation closes: 根据需要
```

---

## 3. 虚拟机创建

### 3.1 创建新虚拟机（GUI）

**典型安装：**

```
1. File → New Virtual Machine → Typical
2. 选择安装源：
   - Installer disc image file (iso): 推荐
   - Installer disc: 物理光驱
   - I will install the operating system later: 稍后安装
3. 选择操作系统类型和版本
4. 命名虚拟机和存储位置
5. 指定磁盘大小
   - Store virtual disk as a single file: 性能更好
   - Split virtual disk into multiple files: 便于移动
6. 自定义硬件（可选）
7. Finish
```

**自定义安装（高级）：**

```
1. File → New Virtual Machine → Custom (advanced)
2. 选择硬件兼容性
   - Workstation 17.x: 最新功能
   - Workstation 14.x: 更好的兼容性
3. 安装源选择
4. 操作系统类型
5. 虚拟机名称和位置
6. 处理器配置
   - Number of processors: 1-2（根据宿主机）
   - Number of cores per processor: 2-4
7. 内存分配
   - 推荐值：系统推荐的最小值 × 2
8. 网络类型
   - NAT: 推荐，共享宿主机网络
   - Bridged: 独立 IP
   - Host-only: 仅与宿主机通信
9. I/O 控制器类型
   - LSI Logic (推荐)
   - BusLogic (旧系统)
10. 磁盘类型
    - SCSI (推荐)
    - SATA
    - NVMe (最新)
11. 创建新虚拟磁盘
12. 磁盘大小和分配方式
    - Allocate all disk space now: 性能最佳，占用空间大
    - 不勾选: 动态增长，节省空间
13. 磁盘文件名
14. Finish
```

### 3.2 命令行创建虚拟机

**使用 vmrun 创建：**

```powershell
# Windows PowerShell
$vmrun = "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"

# 创建虚拟机配置文件
$vmxContent = @"
.encoding = "UTF-8"
config.version = "8"
virtualHW.version = "19"

numvcpus = "2"
memsize = "2048"
guestOS = "ubuntu-64"
displayName = "Kali-Linux"

# 网络配置
ethernet0.present = "TRUE"
ethernet0.connectionType = "nat"
ethernet0.virtualDev = "e1000"
ethernet0.addressType = "generated"

# 磁盘配置
scsi0.present = "TRUE"
scsi0.virtualDev = "lsilogic"
scsi0:0.present = "TRUE"
scsi0:0.fileName = "disk.vmdk"
scsi0:0.deviceType = "scsi-hardDisk"

# CD/DVD
ide1:0.present = "TRUE"
ide1:0.fileName = "kali-linux.iso"
ide1:0.deviceType = "cdrom-image"

# USB
usb.present = "TRUE"
ehci.present = "TRUE"
"@

# 保存配置文件
$vmxContent | Out-File -FilePath "D:\VMware\VMs\Kali-Linux\Kali-Linux.vmx" -Encoding UTF8

# 启动虚拟机
& $vmrun start "D:\VMware\VMs\Kali-Linux\Kali-Linux.vmx"
```

### 3.3 常用操作系统安装

**Kali Linux（渗透测试）：**

```powershell
# 下载 Kali Linux ISO
# https://www.kali.org/get-kali/

# 推荐配置
- CPU: 2核心
- 内存: 4GB
- 硬盘: 80GB
- 网络: NAT
```

**Ubuntu Server（靶机）：**

```powershell
# 推荐配置
- CPU: 1-2核心
- 内存: 2GB
- 硬盘: 20GB
- 网络: NAT 或 Host-only
```

**Windows 10/11（测试环境）：**

```powershell
# 推荐配置
- CPU: 2-4核心
- 内存: 4-8GB
- 硬盘: 60GB
- 网络: NAT
```

---

## 4. 网络配置

### 4.1 网络模式详解

**NAT（网络地址转换）：**

```
特点：
- 虚拟机通过宿主机 IP 访问外网
- 虚拟机有独立的内部 IP（192.168.x.x）
- 外部无法直接访问虚拟机
- 虚拟机之间可以互相访问

适用场景：
- 日常使用
- 需要上网但不需要外部访问
- 渗透测试实验环境

默认网段：192.168.137.0/24（Windows）
```

**Bridged（桥接模式）：**

```
特点：
- 虚拟机直接连接到物理网络
- 获得与宿主机同网段的 IP
- 外部可以直接访问虚拟机
- 虚拟机相当于网络中的独立主机

适用场景：
- 需要外部访问虚拟机
- 虚拟机需要提供服务
- 模拟真实网络环境

IP 范围：与宿主机同网段
```

**Host-only（仅主机模式）：**

```
特点：
- 虚拟机只能与宿主机通信
- 虚拟机之间可以互相访问
- 无法访问外网
- 完全隔离的网络环境

适用场景：
- 恶意软件分析
- 隔离的测试环境
- 不需要联网的实验

默认网段：192.168.x.0/24
```

### 4.2 网络配置命令

**查看虚拟网络：**

```powershell
# Windows - 查看 VMware 虚拟网卡
Get-NetAdapter | Where-Object {$_.Name -like "VMware*"}

# 查看虚拟网络配置
Get-Content "C:\ProgramData\VMware\vmnetdhcp.conf"
Get-Content "C:\ProgramData\VMware\vmnetnat.conf"
```

**配置静态 IP（虚拟机内）：**

```bash
# Linux - 编辑网络配置
sudo nano /etc/netplan/01-netcfg.yaml

# 配置示例
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: no
      addresses:
        - 192.168.137.100/24
      gateway4: 192.168.137.2
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4

# 应用配置
sudo netplan apply
```


**Windows 静态 IP 配置：**

```powershell
# PowerShell 配置静态 IP
New-NetIPAddress -InterfaceAlias "以太网" -IPAddress 192.168.137.100 -PrefixLength 24 -DefaultGateway 192.168.137.2
Set-DnsClientServerAddress -InterfaceAlias "以太网" -ServerAddresses ("8.8.8.8","8.8.4.4")
```

### 4.3 端口转发（NAT 模式）

**配置端口转发：**

```
Edit → Virtual Network Editor → NAT Settings → Port Forwarding

示例：将宿主机 8080 端口转发到虚拟机 80 端口
Host Port: 8080
Virtual Machine IP: 192.168.137.100
Virtual Machine Port: 80
```

**命令行配置（Windows）：**

```powershell
# 编辑 NAT 配置文件
notepad "C:\ProgramData\VMware\vmnetnat.conf"

# 添加端口转发规则
[incomingtcp]
8080 = 192.168.137.100:80
3389 = 192.168.137.100:3389

[incomingudp]
53 = 192.168.137.100:53

# 重启 VMware NAT 服务
Restart-Service "VMware NAT Service"
```

---

## 5. 快照与克隆

### 5.1 快照管理

**创建快照：**

```
VM → Snapshot → Take Snapshot
- Name: 描述性名称（如：Clean Install）
- Description: 详细说明
- Snapshot the virtual machine's memory: 保存内存状态（推荐）
```

**命令行快照：**

```powershell
# 创建快照
& $vmrun snapshot "D:\VMware\VMs\Kali-Linux\Kali-Linux.vmx" "CleanInstall"

# 列出所有快照
& $vmrun listSnapshots "D:\VMware\VMs\Kali-Linux\Kali-Linux.vmx"

# 恢复快照
& $vmrun revertToSnapshot "D:\VMware\VMs\Kali-Linux\Kali-Linux.vmx" "CleanInstall"

# 删除快照
& $vmrun deleteSnapshot "D:\VMware\VMs\Kali-Linux\Kali-Linux.vmx" "CleanInstall"
```

**快照最佳实践：**

```
1. 重要节点创建快照
   - 系统安装完成
   - 工具安装完成
   - 配置完成
   - 测试前

2. 快照命名规范
   - 日期 + 描述：2024-01-15_CleanInstall
   - 版本号：v1.0_BaseSystem

3. 定期清理旧快照
   - 快照会占用大量磁盘空间
   - 保留关键快照即可
```

### 5.2 克隆虚拟机

**完整克隆：**

```
VM → Manage → Clone
1. Clone from: Current state / Existing snapshot
2. Clone type: Create a full clone
3. Name and location
4. Finish

特点：
- 完全独立的副本
- 占用完整磁盘空间
- 可以独立移动
```

**链接克隆：**

```
Clone type: Create a linked clone

特点：
- 基于快照创建
- 共享父虚拟机磁盘
- 节省磁盘空间
- 依赖父虚拟机
```

**命令行克隆：**

```powershell
# 完整克隆
& $vmrun clone "D:\VMware\VMs\Kali-Linux\Kali-Linux.vmx" `
    "D:\VMware\VMs\Kali-Clone\Kali-Clone.vmx" `
    full `
    -snapshot="CleanInstall" `
    -cloneName="Kali-Clone"

# 链接克隆
& $vmrun clone "D:\VMware\VMs\Kali-Linux\Kali-Linux.vmx" `
    "D:\VMware\VMs\Kali-Linked\Kali-Linked.vmx" `
    linked `
    -snapshot="CleanInstall" `
    -cloneName="Kali-Linked"
```

---

## 6. 共享文件夹

### 6.1 启用共享文件夹

**GUI 配置：**

```
VM → Settings → Options → Shared Folders
1. 选择 Always enabled
2. Add → 选择宿主机文件夹
3. Name: 共享名称
4. Enable this share: 勾选
5. Read-only: 根据需要
```

**命令行配置：**

```powershell
# 添加共享文件夹
& $vmrun addSharedFolder "D:\VMware\VMs\Kali-Linux\Kali-Linux.vmx" `
    "SharedData" `
    "D:\SharedData"

# 列出共享文件夹
& $vmrun listSharedFolders "D:\VMware\VMs\Kali-Linux\Kali-Linux.vmx"

# 删除共享文件夹
& $vmrun removeSharedFolder "D:\VMware\VMs\Kali-Linux\Kali-Linux.vmx" "SharedData"
```

### 6.2 访问共享文件夹

**Linux 访问：**

```bash
# 安装 VMware Tools（必需）
sudo apt update
sudo apt install open-vm-tools open-vm-tools-desktop

# 挂载共享文件夹
sudo mkdir /mnt/hgfs
sudo vmhgfs-fuse .host:/ /mnt/hgfs -o allow_other

# 自动挂载（添加到 /etc/fstab）
echo ".host:/ /mnt/hgfs fuse.vmhgfs-fuse allow_other,defaults 0 0" | sudo tee -a /etc/fstab

# 访问共享文件夹
cd /mnt/hgfs/SharedData
```


**Windows 访问：**

```
安装 VMware Tools 后，共享文件夹自动映射为网络驱动器
路径：\\vmware-host\Shared Folders\SharedData
```

---

## 7. 性能优化

### 7.1 硬件配置优化

**CPU 优化：**

```
VM → Settings → Hardware → Processors
- Number of processors: 不超过宿主机物理核心数的 50%
- Number of cores per processor: 2-4
- Virtualize Intel VT-x/EPT or AMD-V/RVI: 启用
- Virtualize CPU performance counters: 启用（性能监控）
```

**内存优化：**

```
VM → Settings → Hardware → Memory
- 推荐分配：宿主机内存的 25-50%
- 避免过度分配导致宿主机使用交换空间

示例：
- 宿主机 16GB → 虚拟机 4-8GB
- 宿主机 32GB → 虚拟机 8-16GB
```

**磁盘优化：**

```
1. 使用 SSD 存储虚拟机
2. 预分配磁盘空间（性能最佳）
3. 定期整理磁盘碎片

# 磁盘碎片整理
VM → Settings → Hardware → Hard Disk → Defragment

# 压缩磁盘
VM → Settings → Hardware → Hard Disk → Compact
```

### 7.2 系统配置优化

**禁用不必要的设备：**

```
VM → Settings → Hardware
- 移除软驱（Floppy）
- 移除打印机（Printer）
- 移除声卡（Sound Card）- 如果不需要
```

**3D 图形加速：**

```
VM → Settings → Hardware → Display
- Accelerate 3D graphics: 启用（需要图形界面）
- Graphics memory: 根据需要调整（最大 8GB）
- Use host setting for monitors: 启用
```

**电源管理：**

```
VM → Settings → Options → Power
- Power Controls:
  - Soft power: 推荐
  - Hard power: 强制关机
- Suspend: 
  - Suspend to memory: 快速恢复
  - Suspend to disk: 节省内存
```

### 7.3 宿主机优化

**Windows 宿主机优化：**

```powershell
# 禁用 Windows Defender 实时保护（可选，注意安全风险）
Set-MpPreference -DisableRealtimeMonitoring $true

# 排除 VMware 目录
Add-MpPreference -ExclusionPath "D:\VMware\VMs"

# 禁用系统还原（节省空间）
Disable-ComputerRestore -Drive "D:\"

# 关闭索引服务（针对虚拟机目录）
# 右键虚拟机目录 → 属性 → 取消勾选"允许索引此驱动器上文件的内容"

# 设置高性能电源计划
powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
```

---

## 8. 高级功能

### 8.1 VMware Tools

**安装 VMware Tools（Linux）：**

```bash
# 方法1：使用发行版仓库（推荐）
sudo apt update
sudo apt install open-vm-tools open-vm-tools-desktop

# 方法2：使用 VMware 官方工具
# VM → Install VMware Tools
sudo mkdir /mnt/cdrom
sudo mount /dev/cdrom /mnt/cdrom
cd /mnt/cdrom
tar -xzf VMwareTools-*.tar.gz -C /tmp
cd /tmp/vmware-tools-distrib
sudo ./vmware-install.pl

# 验证安装
vmware-toolbox-cmd -v
```

**VMware Tools 功能：**

```
- 时间同步
- 共享文件夹
- 拖放文件
- 复制粘贴
- 自动调整分辨率
- 性能优化
```

### 8.2 USB 设备直通

**连接 USB 设备：**

```
VM → Removable Devices → USB Device → Connect

注意：
- USB 设备会从宿主机断开
- 一次只能连接到一个虚拟机
```

**USB 控制器配置：**

```
VM → Settings → Hardware → USB Controller
- USB compatibility: USB 3.1 / USB 2.0
- Show all USB input devices: 显示所有 USB 设备
- Share Bluetooth devices with the virtual machine: 共享蓝牙
```

**自动连接 USB 设备：**

```
VM → Settings → Options → USB
- Automatically connect new USB devices: 启用
```

### 8.3 虚拟机加密

**加密虚拟机：**

```
VM → Manage → Encrypt
1. 设置加密密码
2. 可选：添加密码提示
3. Encrypt

特点：
- 保护虚拟机数据安全
- 需要密码才能启动
- 性能略有下降
```

**命令行加密：**

```powershell
# 加密虚拟机（需要 VMware Workstation Pro）
& "C:\Program Files (x86)\VMware\VMware Workstation\vmware-vdiskmanager.exe" `
    -k "D:\VMware\VMs\Kali-Linux\disk.vmdk"
```

### 8.4 远程连接

**启用远程连接：**

```
Edit → Preferences → Shared VMs
1. Enable Sharing: 启用
2. Port: 443（默认）
3. Require username and password: 启用认证
```

**远程连接虚拟机：**

```
File → Connect to Server
- Server: 宿主机 IP:443
- Username: 宿主机用户名
- Password: 宿主机密码
```

---

## 9. 命令行工具

### 9.1 vmrun 常用命令

**虚拟机电源管理：**

```powershell
$vmrun = "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
$vmx = "D:\VMware\VMs\Kali-Linux\Kali-Linux.vmx"

# 启动虚拟机
& $vmrun start $vmx

# 启动虚拟机（无 GUI）
& $vmrun start $vmx nogui

# 停止虚拟机（软关机）
& $vmrun stop $vmx soft

# 停止虚拟机（硬关机）
& $vmrun stop $vmx hard

# 重启虚拟机
& $vmrun reset $vmx soft

# 暂停虚拟机
& $vmrun pause $vmx

# 恢复虚拟机
& $vmrun unpause $vmx

# 挂起虚拟机
& $vmrun suspend $vmx soft
```


**虚拟机信息查询：**

```powershell
# 列出所有运行的虚拟机
& $vmrun list

# 获取虚拟机 IP 地址
& $vmrun getGuestIPAddress $vmx

# 等待虚拟机获取 IP（超时 60 秒）
& $vmrun getGuestIPAddress $vmx -wait 60

# 列出虚拟机进程
& $vmrun listProcessesInGuest $vmx -interactive
```

**虚拟机内执行命令：**

```powershell
# 在虚拟机内运行命令（需要 VMware Tools）
& $vmrun -gu root -gp password runProgramInGuest $vmx /bin/bash "-c 'ls -la'"

# 在虚拟机内运行脚本
& $vmrun -gu root -gp password runScriptInGuest $vmx /bin/bash "echo 'Hello World'"

# 复制文件到虚拟机
& $vmrun -gu root -gp password copyFileFromHostToGuest $vmx "C:\test.txt" "/tmp/test.txt"

# 从虚拟机复制文件
& $vmrun -gu root -gp password copyFileFromGuestToHost $vmx "/tmp/test.txt" "C:\test.txt"

# 在虚拟机内创建目录
& $vmrun -gu root -gp password createDirectoryInGuest $vmx "/tmp/testdir"

# 删除虚拟机内文件
& $vmrun -gu root -gp password deleteFileInGuest $vmx "/tmp/test.txt"
```

### 9.2 vmware-vdiskmanager

**磁盘管理工具：**

```powershell
$vdiskmanager = "C:\Program Files (x86)\VMware\VMware Workstation\vmware-vdiskmanager.exe"

# 创建虚拟磁盘
& $vdiskmanager -c -s 40GB -a lsilogic -t 0 "D:\VMware\VMs\disk.vmdk"
# -c: 创建
# -s: 大小
# -a: 适配器类型（lsilogic, buslogic, ide）
# -t: 磁盘类型（0=单文件增长, 1=多文件增长, 2=单文件预分配, 3=多文件预分配）

# 扩展虚拟磁盘
& $vdiskmanager -x 80GB "D:\VMware\VMs\disk.vmdk"

# 压缩虚拟磁盘
& $vdiskmanager -k "D:\VMware\VMs\disk.vmdk"

# 整理虚拟磁盘碎片
& $vdiskmanager -d "D:\VMware\VMs\disk.vmdk"

# 重命名虚拟磁盘
& $vdiskmanager -n "D:\VMware\VMs\disk.vmdk" "D:\VMware\VMs\disk-new.vmdk"

# 转换磁盘类型
& $vdiskmanager -r "D:\VMware\VMs\disk.vmdk" -t 0 "D:\VMware\VMs\disk-converted.vmdk"

# 查看磁盘信息
& $vdiskmanager -i "D:\VMware\VMs\disk.vmdk"
```

### 9.3 批量管理脚本

**批量启动虚拟机：**

```powershell
# 批量启动脚本
$vmrun = "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
$vms = @(
    "D:\VMware\VMs\Kali-Linux\Kali-Linux.vmx",
    "D:\VMware\VMs\Ubuntu-Server\Ubuntu-Server.vmx",
    "D:\VMware\VMs\Windows-10\Windows-10.vmx"
)

foreach ($vm in $vms) {
    Write-Host "启动虚拟机: $vm"
    & $vmrun start $vm nogui
    Start-Sleep -Seconds 5
}

# 等待所有虚拟机获取 IP
foreach ($vm in $vms) {
    Write-Host "等待虚拟机获取 IP: $vm"
    $ip = & $vmrun getGuestIPAddress $vm -wait 120
    Write-Host "IP 地址: $ip"
}
```

**批量关闭虚拟机：**

```powershell
# 批量关闭脚本
$vmrun = "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"

# 获取所有运行的虚拟机
$runningVMs = & $vmrun list

# 跳过第一行（标题）
$runningVMs | Select-Object -Skip 1 | ForEach-Object {
    Write-Host "关闭虚拟机: $_"
    & $vmrun stop $_ soft
}
```

**批量快照脚本：**

```powershell
# 批量创建快照
$vmrun = "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
$vms = Get-ChildItem -Path "D:\VMware\VMs" -Recurse -Filter "*.vmx"
$snapshotName = "Backup-$(Get-Date -Format 'yyyy-MM-dd-HHmm')"

foreach ($vm in $vms) {
    Write-Host "创建快照: $($vm.FullName) - $snapshotName"
    & $vmrun snapshot $vm.FullName $snapshotName
}
```

---

## 10. 渗透测试环境搭建

### 10.1 攻击机配置（Kali Linux）

**推荐配置：**

```
- CPU: 2-4 核心
- 内存: 4-8GB
- 硬盘: 80GB
- 网络: NAT（可访问外网和靶机）
- 显示: 启用 3D 加速
```

**安装后配置：**

```bash
# 更新系统
sudo apt update && sudo apt upgrade -y

# 安装 VMware Tools
sudo apt install open-vm-tools open-vm-tools-desktop -y

# 安装常用工具
sudo apt install -y \
    vim git curl wget \
    net-tools nmap masscan \
    metasploit-framework \
    burpsuite sqlmap \
    john hydra hashcat \
    wireshark tcpdump

# 配置静态 IP（可选）
sudo nano /etc/network/interfaces
# 添加：
# auto eth0
# iface eth0 inet static
#     address 192.168.137.10
#     netmask 255.255.255.0
#     gateway 192.168.137.2
#     dns-nameservers 8.8.8.8

# 重启网络
sudo systemctl restart networking
```

### 10.2 靶机环境配置

**DVWA（Damn Vulnerable Web Application）：**

```bash
# 使用 Docker 快速部署
docker run -d -p 80:80 vulnerables/web-dvwa

# 或手动安装
sudo apt install apache2 mysql-server php php-mysqli php-gd -y
cd /var/www/html
sudo git clone https://github.com/digininja/DVWA.git
sudo chown -R www-data:www-data DVWA
sudo chmod -R 755 DVWA

# 配置数据库
sudo mysql -u root -p
CREATE DATABASE dvwa;
CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
FLUSH PRIVILEGES;
EXIT;

# 访问：http://靶机IP/DVWA
```

**Metasploitable 2/3：**

```
下载地址：
https://sourceforge.net/projects/metasploitable/

配置：
- CPU: 1 核心
- 内存: 512MB-1GB
- 网络: Host-only（隔离环境）

默认凭据：
- 用户名: msfadmin
- 密码: msfadmin
```

### 10.3 网络拓扑设计

**隔离实验环境：**

```
┌─────────────────┐
│   宿主机 (Host)  │
└────────┬────────┘
         │
    ┌────┴────┐
    │ VMnet1  │ (Host-only: 192.168.100.0/24)
    └────┬────┘
         │
    ┌────┴────────────────┐
    │                     │
┌───┴────┐          ┌────┴─────┐
│ Kali   │          │ 靶机环境  │
│ .10    │ ────────>│ .20-.30  │
└────────┘          └──────────┘
```


**配置步骤：**

```powershell
# 1. 创建 Host-only 网络
Edit → Virtual Network Editor
- Add Network → VMnet1
- Type: Host-only
- Subnet IP: 192.168.100.0
- Subnet mask: 255.255.255.0
- DHCP: 禁用（使用静态 IP）

# 2. 配置 Kali Linux
# 网络适配器1: NAT（访问外网）
# 网络适配器2: Host-only (VMnet1)（访问靶机）

# 3. 配置靶机
# 网络适配器: Host-only (VMnet1)（仅内网）
```

**多网段环境：**

```
┌─────────────────┐
│   宿主机 (Host)  │
└────────┬────────┘
         │
    ┌────┴────┐
    │ VMnet8  │ (NAT: 192.168.137.0/24)
    └────┬────┘
         │
    ┌────┴────┐
    │  Kali   │ (路由器角色)
    │  .10    │
    └────┬────┘
         │
    ┌────┴────┐
    │ VMnet2  │ (Host-only: 192.168.200.0/24)
    └────┬────┘
         │
    ┌────┴────────────────┐
    │                     │
┌───┴────┐          ┌────┴─────┐
│ 靶机1   │          │ 靶机2     │
│ .20    │          │ .30      │
└────────┘          └──────────┘
```

---

## 11. 常见错误与解决方案

### 11.1 虚拟化相关错误

**错误1：Intel VT-x is disabled**

```
错误信息：
"Intel VT-x is disabled. Intel VT-x might be disabled if it has been disabled in the BIOS/firmware settings or the host has not been power-cycled since changing this setting."

解决方案：
1. 重启电脑，进入 BIOS/UEFI
2. 找到 Virtualization Technology 选项
3. 设置为 Enabled
4. 保存并退出
5. 完全关机后再开机（不是重启）

# 验证是否启用
systeminfo | findstr /i "虚拟化"
```

**错误2：VMware 与 Hyper-V 冲突**

```
错误信息：
"VMware Workstation and Hyper-V are not compatible. Remove the Hyper-V role from the system before running VMware Workstation."

解决方案：
# 方法1：禁用 Hyper-V
bcdedit /set hypervisorlaunchtype off
Restart-Computer

# 方法2：使用 Windows 功能
dism.exe /Online /Disable-Feature:Microsoft-Hyper-V

# 方法3：禁用 Windows Sandbox 和 WSL2
Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
Disable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform

# 重启后验证
bcdedit /enum | findstr hypervisorlaunchtype
# 应显示：hypervisorlaunchtype    Off
```

**错误3：Device/Credential Guard 冲突**

```
错误信息：
"VMware Workstation and Device/Credential Guard are not compatible."

解决方案：
# 禁用 Device Guard
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 0 /f

# 禁用 Credential Guard
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LsaCfgFlags" /t REG_DWORD /d 0 /f

# 禁用 HVCI
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 0 /f

# 重启电脑
Restart-Computer
```

### 11.2 网络问题

**错误4：虚拟机无法上网（NAT 模式）**

```
症状：
- 虚拟机无法 ping 通外网
- 可以 ping 通网关

解决方案：
# 1. 重启 VMware 网络服务
Restart-Service "VMware NAT Service"
Restart-Service "VMware DHCP Service"

# 2. 检查虚拟网卡
Get-NetAdapter | Where-Object {$_.Name -like "VMware*"}
# 确保 VMware Network Adapter VMnet8 已启用

# 3. 重置虚拟网络
Edit → Virtual Network Editor → Restore Defaults

# 4. 检查防火墙
# 允许 VMware 通过防火墙

# 5. 虚拟机内检查 DNS
# Linux
cat /etc/resolv.conf
# 应包含：nameserver 192.168.137.2

# 手动设置 DNS
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
```

**错误5：Host-only 网络无法通信**

```
症状：
- 宿主机无法 ping 通虚拟机
- 虚拟机之间无法通信

解决方案：
# 1. 检查 Host-only 网卡 IP
Get-NetIPAddress -InterfaceAlias "VMware Network Adapter VMnet1"

# 2. 手动配置 IP（如果没有）
New-NetIPAddress -InterfaceAlias "VMware Network Adapter VMnet1" `
    -IPAddress 192.168.100.1 `
    -PrefixLength 24

# 3. 检查防火墙规则
# 允许 VMnet1 网络通信
New-NetFirewallRule -DisplayName "VMware Host-only" `
    -Direction Inbound `
    -InterfaceAlias "VMware Network Adapter VMnet1" `
    -Action Allow

# 4. 虚拟机内检查路由
# Linux
ip route show
# 应有默认路由指向网关
```

### 11.3 性能问题

**错误6：虚拟机运行缓慢**

```
症状：
- 虚拟机响应慢
- CPU 使用率高
- 磁盘 I/O 慢

解决方案：
# 1. 检查宿主机资源
Get-Counter '\Processor(_Total)\% Processor Time'
Get-Counter '\Memory\Available MBytes'

# 2. 减少虚拟机资源分配
# 确保所有虚拟机总资源 < 宿主机 80%

# 3. 禁用不必要的服务
# 虚拟机内禁用：
# - 索引服务
# - Windows Search
# - Superfetch

# 4. 使用 SSD 存储虚拟机

# 5. 启用虚拟化性能计数器
VM → Settings → Processors → Virtualize CPU performance counters

# 6. 磁盘碎片整理
# 宿主机和虚拟机都需要
```

**错误7：磁盘空间不足**

```
症状：
- 虚拟机无法启动
- 提示磁盘空间不足

解决方案：
# 1. 清理快照
VM → Snapshot → Snapshot Manager → Delete

# 2. 压缩虚拟磁盘
# 虚拟机内先清理
# Linux
sudo apt clean
sudo apt autoremove
sudo dd if=/dev/zero of=/tmp/zero bs=1M
sudo rm /tmp/zero

# Windows
cleanmgr
# 运行磁盘清理

# 然后在宿主机压缩
& "C:\Program Files (x86)\VMware\VMware Workstation\vmware-vdiskmanager.exe" `
    -k "D:\VMware\VMs\Kali-Linux\disk.vmdk"

# 3. 扩展虚拟磁盘
& "C:\Program Files (x86)\VMware\VMware Workstation\vmware-vdiskmanager.exe" `
    -x 100GB "D:\VMware\VMs\Kali-Linux\disk.vmdk"

# 虚拟机内扩展分区
# Linux
sudo growpart /dev/sda 1
sudo resize2fs /dev/sda1
```


### 11.4 启动问题

**错误8：虚拟机无法启动 - 文件锁定**

```
错误信息：
"Failed to lock the file"
"Cannot open the disk 'xxx.vmdk' or one of the snapshot disks it depends on."

解决方案：
# 1. 关闭所有 VMware 进程
Get-Process | Where-Object {$_.Name -like "vmware*"} | Stop-Process -Force

# 2. 删除锁定文件
Remove-Item "D:\VMware\VMs\Kali-Linux\*.lck" -Recurse -Force

# 3. 检查磁盘文件完整性
& "C:\Program Files (x86)\VMware\VMware Workstation\vmware-vdiskmanager.exe" `
    -R "D:\VMware\VMs\Kali-Linux\disk.vmdk"

# 4. 如果问题持续，重建 vmx 文件
# 备份原 vmx 文件
Copy-Item "D:\VMware\VMs\Kali-Linux\Kali-Linux.vmx" `
    "D:\VMware\VMs\Kali-Linux\Kali-Linux.vmx.bak"

# 使用 VMware 重新添加虚拟机
# File → Open → 选择 vmx 文件
```

**错误9：快照损坏**

```
错误信息：
"The parent virtual disk has been modified since the child was created."

解决方案：
# 方法1：删除所有快照（数据会丢失）
VM → Snapshot → Snapshot Manager → Delete All

# 方法2：修复快照链
# 1. 关闭虚拟机
# 2. 找到所有 vmdk 文件
Get-ChildItem "D:\VMware\VMs\Kali-Linux\*.vmdk"

# 3. 合并快照
& "C:\Program Files (x86)\VMware\VMware Workstation\vmware-vdiskmanager.exe" `
    -r "D:\VMware\VMs\Kali-Linux\disk-000001.vmdk" `
    -t 0 "D:\VMware\VMs\Kali-Linux\disk-repaired.vmdk"

# 4. 编辑 vmx 文件，指向新磁盘
# scsi0:0.fileName = "disk-repaired.vmdk"
```

**错误10：VMware Tools 安装失败**

```
症状：
- 无法安装 VMware Tools
- 共享文件夹不可用
- 无法拖放文件

解决方案：
# Linux - 使用 open-vm-tools
sudo apt update
sudo apt install open-vm-tools open-vm-tools-desktop -y

# 如果仍然失败，手动安装
# 1. 挂载 VMware Tools ISO
sudo mkdir /mnt/cdrom
sudo mount /dev/cdrom /mnt/cdrom

# 2. 解压并安装
cd /tmp
tar -xzf /mnt/cdrom/VMwareTools-*.tar.gz
cd vmware-tools-distrib
sudo ./vmware-install.pl -d

# 3. 重启虚拟机
sudo reboot

# 验证安装
vmware-toolbox-cmd -v
```

### 11.5 共享文件夹问题

**错误11：共享文件夹不显示**

```
症状：
- /mnt/hgfs 目录为空
- 无法访问共享文件夹

解决方案：
# 1. 确认 VMware Tools 已安装
vmware-toolbox-cmd -v

# 2. 手动挂载
sudo mkdir -p /mnt/hgfs
sudo vmhgfs-fuse .host:/ /mnt/hgfs -o allow_other

# 3. 检查共享文件夹配置
vmware-hgfsclient
# 应列出所有共享文件夹名称

# 4. 自动挂载（添加到 /etc/fstab）
echo ".host:/ /mnt/hgfs fuse.vmhgfs-fuse allow_other,defaults 0 0" | sudo tee -a /etc/fstab

# 5. 如果使用 systemd
sudo systemctl enable vmtoolsd
sudo systemctl start vmtoolsd

# 6. 权限问题
sudo chmod 755 /mnt/hgfs
sudo chown $USER:$USER /mnt/hgfs
```

### 11.6 克隆和快照问题

**错误12：克隆后 MAC 地址冲突**

```
症状：
- 克隆的虚拟机网络不正常
- IP 地址冲突

解决方案：
# 1. 重新生成 MAC 地址
VM → Settings → Network Adapter → Advanced
- MAC Address: Generate

# 2. Linux 清除网络配置
sudo rm /etc/udev/rules.d/70-persistent-net.rules
sudo rm /etc/machine-id
sudo systemd-machine-id-setup

# 3. 重启虚拟机
sudo reboot

# 4. 验证新 MAC 地址
ip link show
```

**错误13：快照占用大量空间**

```
症状：
- 磁盘空间快速增长
- 快照文件巨大

解决方案：
# 1. 查看快照大小
Get-ChildItem "D:\VMware\VMs\Kali-Linux\*.vmdk" | Select-Object Name, @{N="Size(GB)";E={[math]::Round($_.Length/1GB,2)}}

# 2. 删除不需要的快照
VM → Snapshot → Snapshot Manager → Delete

# 3. 合并快照到基础磁盘
VM → Snapshot → Snapshot Manager → Delete All
# 这会将所有更改合并到基础磁盘

# 4. 压缩磁盘
& "C:\Program Files (x86)\VMware\VMware Workstation\vmware-vdiskmanager.exe" `
    -k "D:\VMware\VMs\Kali-Linux\disk.vmdk"
```

---

## 12. 最佳实践

### 12.1 虚拟机管理

**命名规范：**

```
格式：[用途]-[系统]-[版本]-[日期]

示例：
- Pentest-Kali-2024.1-20240115
- Target-Ubuntu-22.04-20240115
- Analysis-Windows-10-20240115
```

**目录结构：**

```
D:\VMware\
├── VMs\
│   ├── Kali-Linux\
│   │   ├── Kali-Linux.vmx
│   │   ├── disk.vmdk
│   │   └── snapshots\
│   ├── Ubuntu-Server\
│   └── Windows-10\
├── ISOs\
│   ├── kali-linux-2024.1.iso
│   ├── ubuntu-22.04.iso
│   └── windows-10.iso
├── Templates\
│   └── Base-Kali\
└── Backups\
    └── 2024-01\
```

**快照策略：**

```
1. 基础快照
   - CleanInstall: 系统安装完成
   - BaseTools: 基础工具安装完成
   - Configured: 配置完成

2. 工作快照
   - BeforeTest: 测试前
   - AfterUpdate: 更新后
   - Milestone: 重要节点

3. 快照命名
   - 格式：[日期]-[描述]
   - 示例：20240115-CleanInstall
```

### 12.2 安全实践

**隔离环境：**

```
1. 使用 Host-only 网络隔离危险环境
2. 禁用共享文件夹（恶意软件分析时）
3. 禁用拖放和复制粘贴
4. 使用快照保护系统状态
```

**权限控制：**

```
# 虚拟机文件权限
icacls "D:\VMware\VMs" /grant "Users:(OI)(CI)R" /T

# 加密敏感虚拟机
VM → Manage → Encrypt
```

**备份策略：**

```powershell
# 自动备份脚本
$source = "D:\VMware\VMs"
$destination = "E:\Backups\VMware\$(Get-Date -Format 'yyyy-MM-dd')"
$exclude = @("*.log", "*.lck", "vmware*.log")

# 创建备份目录
New-Item -ItemType Directory -Path $destination -Force

# 复制虚拟机文件（排除日志和锁文件）
Get-ChildItem -Path $source -Recurse | 
    Where-Object { $exclude -notcontains $_.Extension } |
    Copy-Item -Destination {
        $dest = $_.FullName.Replace($source, $destination)
        $null = New-Item -ItemType Directory -Path (Split-Path $dest) -Force
        $dest
    }

# 压缩备份
Compress-Archive -Path $destination -DestinationPath "$destination.zip"
Remove-Item -Path $destination -Recurse -Force
```


### 12.3 性能优化实践

**资源分配原则：**

```
1. CPU 分配
   - 单个虚拟机 ≤ 宿主机物理核心数的 50%
   - 所有虚拟机总和 ≤ 宿主机物理核心数的 80%

2. 内存分配
   - 单个虚拟机 ≤ 宿主机内存的 50%
   - 所有虚拟机总和 ≤ 宿主机内存的 75%
   - 保留至少 4GB 给宿主机

3. 磁盘分配
   - 使用 SSD 存储虚拟机
   - 预分配磁盘空间（性能优先）
   - 动态增长（空间优先）

示例（宿主机：8核 32GB 内存）：
- Kali Linux: 2核 8GB
- 靶机1: 2核 4GB
- 靶机2: 2核 4GB
- 宿主机保留: 2核 16GB
```

**磁盘优化：**

```powershell
# 1. 定期压缩磁盘
$vdiskmanager = "C:\Program Files (x86)\VMware\VMware Workstation\vmware-vdiskmanager.exe"
$vmdks = Get-ChildItem "D:\VMware\VMs" -Recurse -Filter "*.vmdk" | 
    Where-Object { $_.Name -notmatch "-\d{6}\.vmdk$" }

foreach ($vmdk in $vmdks) {
    Write-Host "压缩磁盘: $($vmdk.FullName)"
    & $vdiskmanager -k $vmdk.FullName
}

# 2. 整理碎片
foreach ($vmdk in $vmdks) {
    Write-Host "整理碎片: $($vmdk.FullName)"
    & $vdiskmanager -d $vmdk.FullName
}
```

**网络优化：**

```
1. 使用 VMXNET3 网络适配器（性能最佳）
   VM → Settings → Network Adapter → Advanced → Adapter Type → VMXNET3

2. 启用巨型帧（Jumbo Frames）
   - 适用于大量数据传输场景

3. 禁用不使用的网络适配器
```

### 12.4 自动化脚本

**虚拟机管理脚本：**

```powershell
# VMware 管理工具类
class VMwareManager {
    [string]$vmrun
    [string]$vdiskmanager
    
    VMwareManager() {
        $this.vmrun = "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
        $this.vdiskmanager = "C:\Program Files (x86)\VMware\VMware Workstation\vmware-vdiskmanager.exe"
    }
    
    # 启动虚拟机
    [void]Start([string]$vmxPath, [bool]$nogui = $false) {
        $params = @("start", $vmxPath)
        if ($nogui) { $params += "nogui" }
        & $this.vmrun $params
    }
    
    # 停止虚拟机
    [void]Stop([string]$vmxPath, [string]$mode = "soft") {
        & $this.vmrun stop $vmxPath $mode
    }
    
    # 创建快照
    [void]Snapshot([string]$vmxPath, [string]$snapshotName) {
        & $this.vmrun snapshot $vmxPath $snapshotName
    }
    
    # 恢复快照
    [void]Revert([string]$vmxPath, [string]$snapshotName) {
        & $this.vmrun revertToSnapshot $vmxPath $snapshotName
    }
    
    # 获取 IP 地址
    [string]GetIP([string]$vmxPath) {
        return & $this.vmrun getGuestIPAddress $vmxPath -wait 60
    }
    
    # 列出所有运行的虚拟机
    [array]ListRunning() {
        $output = & $this.vmrun list
        return $output | Select-Object -Skip 1
    }
}

# 使用示例
$vm = [VMwareManager]::new()
$vmx = "D:\VMware\VMs\Kali-Linux\Kali-Linux.vmx"

# 启动虚拟机
$vm.Start($vmx, $true)

# 等待并获取 IP
Start-Sleep -Seconds 30
$ip = $vm.GetIP($vmx)
Write-Host "虚拟机 IP: $ip"

# 创建快照
$vm.Snapshot($vmx, "BeforeTest-$(Get-Date -Format 'yyyyMMdd-HHmm')")
```

**批量环境部署脚本：**

```powershell
# 渗透测试环境自动部署
param(
    [string]$BaseDir = "D:\VMware\VMs",
    [string]$ISODir = "D:\VMware\ISOs"
)

$vmrun = "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"

# 环境配置
$environments = @(
    @{
        Name = "Kali-Linux"
        OS = "ubuntu-64"
        CPU = 2
        Memory = 4096
        Disk = 80
        ISO = "$ISODir\kali-linux-2024.1.iso"
        Network = "nat"
    },
    @{
        Name = "Ubuntu-Target"
        OS = "ubuntu-64"
        CPU = 1
        Memory = 2048
        Disk = 20
        ISO = "$ISODir\ubuntu-22.04.iso"
        Network = "hostonly"
    },
    @{
        Name = "Windows-Target"
        OS = "windows10-64"
        CPU = 2
        Memory = 4096
        Disk = 60
        ISO = "$ISODir\windows-10.iso"
        Network = "hostonly"
    }
)

# 创建虚拟机
foreach ($env in $environments) {
    $vmPath = Join-Path $BaseDir $env.Name
    $vmxPath = Join-Path $vmPath "$($env.Name).vmx"
    
    # 创建目录
    New-Item -ItemType Directory -Path $vmPath -Force | Out-Null
    
    # 生成 VMX 配置
    $vmxContent = @"
.encoding = "UTF-8"
config.version = "8"
virtualHW.version = "19"
numvcpus = "$($env.CPU)"
memsize = "$($env.Memory)"
guestOS = "$($env.OS)"
displayName = "$($env.Name)"

# 网络配置
ethernet0.present = "TRUE"
ethernet0.connectionType = "$($env.Network)"
ethernet0.virtualDev = "e1000"
ethernet0.addressType = "generated"

# 磁盘配置
scsi0.present = "TRUE"
scsi0.virtualDev = "lsilogic"
scsi0:0.present = "TRUE"
scsi0:0.fileName = "disk.vmdk"
scsi0:0.deviceType = "scsi-hardDisk"

# CD/DVD
ide1:0.present = "TRUE"
ide1:0.fileName = "$($env.ISO)"
ide1:0.deviceType = "cdrom-image"

# USB
usb.present = "TRUE"
ehci.present = "TRUE"
"@
    
    # 保存 VMX 文件
    $vmxContent | Out-File -FilePath $vmxPath -Encoding UTF8
    
    # 创建虚拟磁盘
    $diskPath = Join-Path $vmPath "disk.vmdk"
    & "C:\Program Files (x86)\VMware\VMware Workstation\vmware-vdiskmanager.exe" `
        -c -s "$($env.Disk)GB" -a lsilogic -t 0 $diskPath
    
    Write-Host "创建虚拟机: $($env.Name)"
}

Write-Host "`n环境部署完成！"
Write-Host "请手动安装操作系统并配置网络。"
```

### 12.5 故障排查清单

**虚拟机无法启动：**

```
□ 检查 CPU 虚拟化是否启用（BIOS）
□ 检查 Hyper-V 是否禁用
□ 检查 Device Guard 是否禁用
□ 检查磁盘空间是否充足
□ 检查 .lck 文件是否存在
□ 检查 vmx 文件是否损坏
□ 检查快照链是否完整
□ 查看 vmware.log 日志文件
```

**网络不通：**

```
□ 检查网络适配器类型
□ 检查虚拟网络服务是否运行
□ 检查防火墙规则
□ 检查虚拟机内网络配置
□ 检查 DNS 设置
□ 检查路由表
□ 尝试重置虚拟网络
□ 检查 NAT 配置文件
```

**性能问题：**

```
□ 检查宿主机资源使用率
□ 检查虚拟机资源分配
□ 检查是否使用 SSD
□ 检查是否启用 3D 加速
□ 检查是否安装 VMware Tools
□ 检查快照数量
□ 检查磁盘碎片
□ 检查后台进程
```

**共享文件夹问题：**

```
□ 检查 VMware Tools 是否安装
□ 检查共享文件夹是否启用
□ 检查 vmhgfs-fuse 是否运行
□ 检查挂载点权限
□ 检查 /etc/fstab 配置
□ 尝试手动挂载
□ 重启 vmtoolsd 服务
```

---

## 附录

### A. 常用命令速查

```powershell
# 虚拟机电源管理
vmrun start <vmx> [nogui]
vmrun stop <vmx> [soft|hard]
vmrun reset <vmx> [soft|hard]
vmrun suspend <vmx> [soft|hard]
vmrun pause <vmx>
vmrun unpause <vmx>

# 快照管理
vmrun snapshot <vmx> <name>
vmrun listSnapshots <vmx>
vmrun revertToSnapshot <vmx> <name>
vmrun deleteSnapshot <vmx> <name>

# 虚拟机信息
vmrun list
vmrun getGuestIPAddress <vmx> [-wait]

# 磁盘管理
vmware-vdiskmanager -c -s <size> -t <type> <vmdk>
vmware-vdiskmanager -x <size> <vmdk>
vmware-vdiskmanager -k <vmdk>
vmware-vdiskmanager -d <vmdk>
```

### B. 网络配置参考

```
NAT 网络：
- 网段: 192.168.137.0/24
- 网关: 192.168.137.2
- DHCP: 192.168.137.128-254

Host-only 网络：
- 网段: 192.168.x.0/24（可自定义）
- 网关: 192.168.x.1
- DHCP: 可选

Bridged 网络：
- 与宿主机同网段
- 需要路由器分配 IP
```

### C. 推荐资源

**官方文档：**
- VMware Workstation 文档: https://docs.vmware.com/
- VMware KB 知识库: https://kb.vmware.com/

**社区资源：**
- VMware Communities: https://communities.vmware.com/
- Reddit r/vmware: https://reddit.com/r/vmware

**渗透测试资源：**
- Kali Linux: https://www.kali.org/
- Metasploitable: https://sourceforge.net/projects/metasploitable/
- DVWA: https://github.com/digininja/DVWA
- VulnHub: https://www.vulnhub.com/

---

**最后更新：** 2024-01-15
**适用版本：** VMware Workstation Pro 17.x / VMware Fusion 13.x
**作者备注：** 本笔记持续更新，欢迎补充和纠正
