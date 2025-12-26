
> OpenWRT 是一个针对嵌入式设备（主要是路由器）的 Linux 发行版。与厂商提供的固件不同，OpenWRT 是完全可定制的——你可以把它想象成一个运行在路由器上的迷你 Linux 系统，拥有完整的包管理器、文件系统和网络功能。
>
> 简单来说：**OpenWRT 让你的路由器从"傻瓜设备"变成"智能服务器"**。

---

## 目录

1. [基础概念与入门](#1-基础概念与入门)
2. [安装与刷机](#2-安装与刷机)
3. [基本配置](#3-基本配置)
4. [网络配置详解](#4-网络配置详解)
5. [无线网络配置](#5-无线网络配置)
6. [防火墙配置](#6-防火墙配置)
7. [软件包管理](#7-软件包管理)
8. [常用服务配置](#8-常用服务配置)
9. [高级网络功能](#9-高级网络功能)
10. [性能优化](#10-性能优化)
11. [故障排查](#11-故障排查)
12. [常见错误汇总](#12-常见错误汇总)

---

## 1. 基础概念与入门

### 1.1 什么是 OpenWRT？

OpenWRT 的核心特点：

| 特性 | 说明 |
|------|------|
| 开源免费 | 基于 GPL 协议，完全开源 |
| 可写文件系统 | 不像原厂固件只读，可以自由安装软件 |
| 包管理器 | 使用 opkg，类似 apt/yum |
| 高度可定制 | 从内核到应用都可以定制 |
| 活跃社区 | 大量插件和教程支持 |

### 1.2 为什么选择 OpenWRT？

原厂固件的局限：
- 功能固定，无法扩展
- 安全更新慢或没有
- 无法安装第三方软件
- 配置选项有限

OpenWRT 能做什么：
- 科学上网（Clash、Passwall、SSR-Plus）
- 广告过滤（AdGuard Home、AdBlock）
- 内网穿透（frp、ZeroTier）
- NAS 功能（Samba、FTP）
- 流量监控与 QoS
- 多拨/负载均衡
- Docker 容器（高端设备）

### 1.3 硬件要求与设备选择

#### 最低配置

| 组件 | 最低要求 | 推荐配置 |
|------|----------|----------|
| Flash | 8MB | 16MB+ |
| RAM | 64MB | 128MB+ |
| CPU | 400MHz | 800MHz+ |

> **⚠️ 重要提示**
> 
> Flash 小于 8MB 的设备无法安装 LuCI（Web 界面），只能用命令行。
> 如果要安装插件（如科学上网），建议 Flash 128MB+，RAM 256MB+。

#### 推荐设备（2024年）

**入门级（100-200元）**
- 红米 AC2100：性价比之王，MT7621 芯片
- 小米 4A 千兆版：便宜够用
- 斐讯 K2P：二手便宜，性能不错

**中端（200-500元）**
- 小米 AX3600：WiFi 6，性能强
- 红米 AX6/AX6S：性价比高
- GL.iNet 系列：原生支持 OpenWRT

**高端/软路由**
- J4125 小主机：x86 架构，性能无敌
- R2S/R4S：ARM 架构，功耗低
- NanoPi R5S：2.5G 网口

### 1.4 OpenWRT 版本说明

```
版本命名规则：主版本.次版本.修订版本
例如：23.05.2

主要版本：
- 稳定版（Release）：如 23.05.x，适合生产环境
- 开发版（Snapshot）：最新功能，可能不稳定
```

查看设备支持：https://openwrt.org/toh/start

---

## 2. 安装与刷机

### 2.1 刷机前准备

**必备工具**
- 网线（不要用无线刷机！）
- 电脑（Windows/Mac/Linux）
- 对应设备的 OpenWRT 固件
- 备份原厂固件（以防万一）

**固件下载**
- 官方：https://downloads.openwrt.org/
- 第三方编译：恩山论坛、GitHub

**固件类型说明**

| 文件类型 | 用途 | 说明 |
|----------|------|------|
| factory.bin | 从原厂固件刷入 | 首次刷机用 |
| sysupgrade.bin | OpenWRT 升级 | 已是 OpenWRT 时用 |
| initramfs.bin | 临时系统 | 救砖用，重启后消失 |
| ext4/squashfs | 文件系统类型 | squashfs 支持恢复出厂 |

### 2.2 常见刷机方法

#### 方法一：Web 界面刷机（最简单）

适用于：原厂固件支持上传固件升级

```
1. 登录原厂路由器管理界面
2. 找到"固件升级"或"系统升级"
3. 上传 factory.bin 文件
4. 等待刷机完成（约2-5分钟）
5. 路由器会自动重启
```

#### 方法二：TFTP 刷机

适用于：支持 TFTP 恢复模式的设备

```bash
# Windows 开启 TFTP 服务
# 控制面板 → 程序 → 启用或关闭 Windows 功能 → TFTP 客户端

# 设置电脑 IP 为 192.168.1.2（或设备要求的 IP）
# 将固件重命名为设备要求的名称（如 firmware.bin）

# 路由器进入恢复模式（通常是按住 Reset 键开机）
# TFTP 会自动传输固件
```

#### 方法三：Breed/U-Boot 刷机（推荐）

Breed 是一个第三方 Bootloader，被称为"路由器的 BIOS"，刷入后几乎不可能变砖。

```
1. 先刷入 Breed（需要原厂固件支持或 TTL）
2. 按住 Reset 键开机，进入 Breed 控制台
3. 浏览器访问 192.168.1.1
4. 选择固件更新 → 上传固件
5. 等待刷机完成
```

> **Breed 的优势**
> - 刷坏了可以重新刷
> - 支持备份/恢复原厂固件
> - 支持环境变量修改

#### 方法四：SSH/SCP 刷机

适用于：已经是 OpenWRT 或有 SSH 访问权限

```bash
# 1. 将固件上传到路由器
scp openwrt-sysupgrade.bin root@192.168.1.1:/tmp/

# 2. SSH 登录路由器
ssh root@192.168.1.1

# 3. 执行刷机命令
sysupgrade -v /tmp/openwrt-sysupgrade.bin

# 保留配置刷机
sysupgrade -v /tmp/openwrt-sysupgrade.bin

# 不保留配置刷机（推荐大版本升级时使用）
sysupgrade -n /tmp/openwrt-sysupgrade.bin
```

### 2.3 首次登录

刷机完成后：

```
1. 用网线连接电脑和路由器 LAN 口
2. 电脑设置为自动获取 IP
3. 浏览器访问 192.168.1.1
4. 默认用户名：root，密码：空（直接回车）
5. 首次登录后立即设置密码！
```

SSH 登录：
```bash
ssh root@192.168.1.1
# 首次连接会提示确认指纹，输入 yes
```

> **⚠️ 常见错误 #1：刷机后无法访问**
> 
> 原因：IP 地址冲突或不在同一网段
> 
> 解决：
> 1. 手动设置电脑 IP 为 192.168.1.2
> 2. 子网掩码 255.255.255.0
> 3. 网关 192.168.1.1

---

## 3. 基本配置

### 3.1 系统配置文件结构

OpenWRT 的配置文件都在 `/etc/config/` 目录下：

```
/etc/config/
├── dhcp          # DHCP 服务配置
├── dropbear      # SSH 服务配置
├── firewall      # 防火墙配置
├── network       # 网络配置（核心）
├── system        # 系统配置（主机名、时区等）
├── wireless      # 无线配置
└── ...
```

### 3.2 UCI 配置系统

UCI（Unified Configuration Interface）是 OpenWRT 的统一配置接口。

```bash
# 查看配置
uci show network              # 查看网络配置
uci show wireless             # 查看无线配置
uci get network.lan.ipaddr    # 获取 LAN IP

# 修改配置
uci set network.lan.ipaddr='192.168.2.1'    # 修改 LAN IP
uci set system.@system[0].hostname='MyRouter'  # 修改主机名

# 提交并应用
uci commit                    # 保存修改
/etc/init.d/network restart   # 重启网络服务

# 或者一条命令应用所有更改
uci commit && reload_config
```

UCI 配置文件格式：
```
config 类型 '名称'
    option 选项 '值'
    list 列表项 '值'
```

示例（/etc/config/network）：
```
config interface 'lan'
    option proto 'static'
    option ipaddr '192.168.1.1'
    option netmask '255.255.255.0'
    option device 'br-lan'
```

### 3.3 修改管理密码

```bash
# 方法1：命令行
passwd

# 方法2：LuCI 界面
# 系统 → 管理权 → 路由器密码
```

### 3.4 修改 LAN IP 地址

如果你的主路由是 192.168.1.1，OpenWRT 作为旁路由需要改 IP：

```bash
# 命令行方式
uci set network.lan.ipaddr='192.168.2.1'
uci commit network
/etc/init.d/network restart

# 或直接编辑配置文件
vi /etc/config/network
# 修改 lan 接口的 ipaddr
```

> **⚠️ 注意**：修改 IP 后，需要用新 IP 访问路由器！

### 3.5 时区与 NTP 设置

```bash
# 设置时区为中国
uci set system.@system[0].timezone='CST-8'
uci set system.@system[0].zonename='Asia/Shanghai'
uci commit system

# 设置 NTP 服务器
uci set system.ntp.server='ntp.aliyun.com'
uci add_list system.ntp.server='cn.pool.ntp.org'
uci commit system
/etc/init.d/sysntpd restart
```

LuCI 界面：系统 → 系统 → 常规设置

### 3.6 SSH 配置

```bash
# 查看 SSH 配置
uci show dropbear

# 修改 SSH 端口（安全考虑）
uci set dropbear.@dropbear[0].Port='22222'

# 禁止密码登录（使用密钥）
uci set dropbear.@dropbear[0].PasswordAuth='off'
uci set dropbear.@dropbear[0].RootPasswordAuth='off'

# 应用配置
uci commit dropbear
/etc/init.d/dropbear restart
```

添加 SSH 公钥：
```bash
# 将公钥添加到授权文件
cat >> /etc/dropbear/authorized_keys << 'EOF'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB... your-key
EOF

chmod 600 /etc/dropbear/authorized_keys
```

---

## 4. 网络配置详解

### 4.1 网络架构理解

OpenWRT 的网络配置分为三层：

```
物理设备（Physical Device）
    ↓
逻辑设备（Device/Bridge）
    ↓
接口（Interface）
```

举例说明：
```
eth0（物理网口）
    ↓
br-lan（网桥，把多个端口桥接在一起）
    ↓
lan（接口，配置 IP 地址）
```

### 4.2 查看网络状态

```bash
# 查看所有网络接口
ip addr
ifconfig

# 查看路由表
ip route
route -n

# 查看网桥
brctl show

# 查看 DHCP 租约
cat /tmp/dhcp.leases

# 查看 DNS
cat /tmp/resolv.conf.d/resolv.conf.auto
```

### 4.3 WAN 口配置

#### DHCP 自动获取（最常见）

```bash
# /etc/config/network
config interface 'wan'
    option device 'eth0.2'      # WAN 口设备
    option proto 'dhcp'         # DHCP 协议

config interface 'wan6'
    option device 'eth0.2'
    option proto 'dhcpv6'       # IPv6
```

#### PPPoE 拨号

```bash
config interface 'wan'
    option device 'eth0.2'
    option proto 'pppoe'
    option username 'your_username'    # 宽带账号
    option password 'your_password'    # 宽带密码
    option ipv6 'auto'
```

#### 静态 IP

```bash
config interface 'wan'
    option device 'eth0.2'
    option proto 'static'
    option ipaddr '10.0.0.2'
    option netmask '255.255.255.0'
    option gateway '10.0.0.1'
    option dns '8.8.8.8 114.114.114.114'
```

### 4.4 LAN 口配置

```bash
# /etc/config/network
config device
    option name 'br-lan'
    option type 'bridge'
    list ports 'eth0.1'         # 桥接的端口

config interface 'lan'
    option device 'br-lan'
    option proto 'static'
    option ipaddr '192.168.1.1'
    option netmask '255.255.255.0'
```

### 4.5 DHCP 服务配置

```bash
# /etc/config/dhcp
config dnsmasq
    option domainneeded '1'
    option localise_queries '1'
    option rebind_protection '1'
    option local '/lan/'
    option domain 'lan'
    option expandhosts '1'
    option authoritative '1'
    option readethers '1'
    option leasefile '/tmp/dhcp.leases'
    option resolvfile '/tmp/resolv.conf.d/resolv.conf.auto'

config dhcp 'lan'
    option interface 'lan'
    option start '100'          # 起始 IP：192.168.1.100
    option limit '150'          # 数量：150 个
    option leasetime '12h'      # 租约时间
    list dhcp_option '6,192.168.1.1'  # DNS 服务器

config dhcp 'wan'
    option interface 'wan'
    option ignore '1'           # WAN 口不提供 DHCP
```

#### 静态 IP 绑定（MAC 绑定）

```bash
# 方法1：配置文件
config host
    option name 'PC1'
    option mac '00:11:22:33:44:55'
    option ip '192.168.1.10'

# 方法2：命令行
uci add dhcp host
uci set dhcp.@host[-1].name='PC1'
uci set dhcp.@host[-1].mac='00:11:22:33:44:55'
uci set dhcp.@host[-1].ip='192.168.1.10'
uci commit dhcp
/etc/init.d/dnsmasq restart
```

### 4.6 DNS 配置

```bash
# 自定义上游 DNS
uci add_list dhcp.@dnsmasq[0].server='114.114.114.114'
uci add_list dhcp.@dnsmasq[0].server='8.8.8.8'
uci commit dhcp
/etc/init.d/dnsmasq restart

# 添加自定义域名解析
echo "192.168.1.100 myserver.lan" >> /etc/hosts
/etc/init.d/dnsmasq restart

# 或使用 dnsmasq 配置
echo "address=/myserver.lan/192.168.1.100" >> /etc/dnsmasq.conf
```

### 4.7 旁路由配置

旁路由是指 OpenWRT 不作为主路由，而是作为网关提供特殊功能（如科学上网）。

```
网络拓扑：
光猫 → 主路由(192.168.1.1) → OpenWRT旁路由(192.168.1.2)
                ↓
            其他设备
```

**OpenWRT 旁路由配置：**

```bash
# 1. 修改 LAN IP（不能和主路由冲突）
uci set network.lan.ipaddr='192.168.1.2'

# 2. 设置网关为主路由
uci set network.lan.gateway='192.168.1.1'

# 3. 设置 DNS
uci set network.lan.dns='192.168.1.1'

# 4. 关闭 DHCP（让主路由分配 IP）
uci set dhcp.lan.ignore='1'

# 5. 应用配置
uci commit
/etc/init.d/network restart
/etc/init.d/dnsmasq restart
```

**客户端设置：**
- 方法1：手动设置网关为 192.168.1.2
- 方法2：在主路由 DHCP 中设置网关为 192.168.1.2

---

## 5. 无线网络配置

### 5.1 无线配置文件结构

```bash
# /etc/config/wireless

# 无线设备配置（硬件相关）
config wifi-device 'radio0'
    option type 'mac80211'
    option path 'pci0000:00/0000:00:00.0'
    option channel '36'
    option band '5g'
    option htmode 'VHT80'
    option disabled '0'

# 无线接口配置（SSID 相关）
config wifi-iface 'default_radio0'
    option device 'radio0'
    option network 'lan'
    option mode 'ap'
    option ssid 'OpenWRT-5G'
    option encryption 'psk2'
    option key 'your_password'
```

### 5.2 无线参数详解

| 参数 | 说明 | 常用值 |
|------|------|--------|
| channel | 信道 | 2.4G: 1,6,11; 5G: 36,149 |
| band | 频段 | 2g, 5g |
| htmode | 带宽模式 | HT20, HT40, VHT80, HE80 |
| txpower | 发射功率 | 默认或具体 dBm 值 |
| country | 国家代码 | CN, US |
| disabled | 是否禁用 | 0=启用, 1=禁用 |

| 加密方式 | 说明 | 推荐 |
|----------|------|------|
| none | 无加密 | ❌ 不推荐 |
| psk | WPA-PSK | ❌ 已过时 |
| psk2 | WPA2-PSK | ✅ 推荐 |
| psk-mixed | WPA/WPA2 混合 | 兼容旧设备 |
| sae | WPA3-SAE | ✅ 最安全 |
| sae-mixed | WPA2/WPA3 混合 | ✅ 推荐 |

### 5.3 常用无线命令

```bash
# 查看无线状态
wifi status
iwinfo

# 扫描周围 WiFi
iwinfo wlan0 scan

# 重启无线
wifi reload
wifi down && wifi up

# 查看已连接的客户端
iwinfo wlan0 assoclist

# 查看无线配置
uci show wireless
```

### 5.4 配置示例

#### 基本 WiFi 配置

```bash
# 设置 2.4G WiFi
uci set wireless.radio0.disabled='0'
uci set wireless.radio0.channel='6'
uci set wireless.radio0.htmode='HT40'
uci set wireless.radio0.country='CN'

uci set wireless.default_radio0.ssid='MyWiFi-2.4G'
uci set wireless.default_radio0.encryption='psk2'
uci set wireless.default_radio0.key='your_password'

# 设置 5G WiFi
uci set wireless.radio1.disabled='0'
uci set wireless.radio1.channel='149'
uci set wireless.radio1.htmode='VHT80'
uci set wireless.radio1.country='CN'

uci set wireless.default_radio1.ssid='MyWiFi-5G'
uci set wireless.default_radio1.encryption='psk2'
uci set wireless.default_radio1.key='your_password'

uci commit wireless
wifi reload
```

#### 访客网络（隔离）

```bash
# 创建访客网络接口
uci set network.guest='interface'
uci set network.guest.proto='static'
uci set network.guest.ipaddr='192.168.2.1'
uci set network.guest.netmask='255.255.255.0'

# 创建访客 WiFi
uci add wireless wifi-iface
uci set wireless.@wifi-iface[-1].device='radio0'
uci set wireless.@wifi-iface[-1].network='guest'
uci set wireless.@wifi-iface[-1].mode='ap'
uci set wireless.@wifi-iface[-1].ssid='Guest-WiFi'
uci set wireless.@wifi-iface[-1].encryption='psk2'
uci set wireless.@wifi-iface[-1].key='guest_password'
uci set wireless.@wifi-iface[-1].isolate='1'  # 客户端隔离

# 配置访客 DHCP
uci set dhcp.guest='dhcp'
uci set dhcp.guest.interface='guest'
uci set dhcp.guest.start='100'
uci set dhcp.guest.limit='50'
uci set dhcp.guest.leasetime='1h'

uci commit
/etc/init.d/network restart
wifi reload
```

#### 无线中继（Repeater）

```bash
# 1. 扫描并连接上级 WiFi
uci set wireless.wwan='wifi-iface'
uci set wireless.wwan.device='radio0'
uci set wireless.wwan.network='wwan'
uci set wireless.wwan.mode='sta'           # 客户端模式
uci set wireless.wwan.ssid='UpstreamWiFi'  # 上级 WiFi 名称
uci set wireless.wwan.encryption='psk2'
uci set wireless.wwan.key='upstream_password'

# 2. 创建 wwan 接口
uci set network.wwan='interface'
uci set network.wwan.proto='dhcp'

# 3. 配置防火墙
uci add_list firewall.@zone[1].network='wwan'

uci commit
/etc/init.d/network restart
wifi reload
```

> **⚠️ 常见错误 #2：WiFi 无法启动**
> 
> 原因：驱动不支持或配置错误
> 
> 排查：
> ```bash
> logread | grep -i wireless
> dmesg | grep -i wifi
> ```

---

## 6. 防火墙配置

### 6.1 防火墙基础概念

OpenWRT 使用 fw4（基于 nftables）或 fw3（基于 iptables）作为防火墙。

核心概念：
- **Zone（区域）**：网络接口的分组，如 lan、wan
- **Forwarding（转发）**：区域之间的流量转发规则
- **Rule（规则）**：具体的放行/拒绝规则
- **Redirect（重定向）**：端口转发/NAT

```
默认区域：
┌─────────────────────────────────────────┐
│  lan (内网)                              │
│  - input: ACCEPT (允许访问路由器)         │
│  - output: ACCEPT                        │
│  - forward: ACCEPT (内网互访)            │
└─────────────────────────────────────────┘
          ↓ forward: ACCEPT (允许上网)
┌─────────────────────────────────────────┐
│  wan (外网)                              │
│  - input: REJECT (拒绝外网访问路由器)     │
│  - output: ACCEPT                        │
│  - forward: REJECT                       │
│  - masq: 1 (NAT 伪装)                    │
└─────────────────────────────────────────┘
```

### 6.2 防火墙配置文件

```bash
# /etc/config/firewall

# 默认设置
config defaults
    option syn_flood '1'
    option input 'ACCEPT'
    option output 'ACCEPT'
    option forward 'REJECT'

# LAN 区域
config zone
    option name 'lan'
    list network 'lan'
    option input 'ACCEPT'
    option output 'ACCEPT'
    option forward 'ACCEPT'

# WAN 区域
config zone
    option name 'wan'
    list network 'wan'
    list network 'wan6'
    option input 'REJECT'
    option output 'ACCEPT'
    option forward 'REJECT'
    option masq '1'              # NAT
    option mtu_fix '1'

# LAN → WAN 转发
config forwarding
    option src 'lan'
    option dest 'wan'
```

### 6.3 端口转发

将外网端口映射到内网设备：

```bash
# 示例：将外网 8080 端口转发到内网 192.168.1.100:80

# 方法1：配置文件
config redirect
    option name 'Web-Server'
    option src 'wan'
    option src_dport '8080'
    option dest 'lan'
    option dest_ip '192.168.1.100'
    option dest_port '80'
    option proto 'tcp'
    option target 'DNAT'

# 方法2：命令行
uci add firewall redirect
uci set firewall.@redirect[-1].name='Web-Server'
uci set firewall.@redirect[-1].src='wan'
uci set firewall.@redirect[-1].src_dport='8080'
uci set firewall.@redirect[-1].dest='lan'
uci set firewall.@redirect[-1].dest_ip='192.168.1.100'
uci set firewall.@redirect[-1].dest_port='80'
uci set firewall.@redirect[-1].proto='tcp'
uci set firewall.@redirect[-1].target='DNAT'
uci commit firewall
/etc/init.d/firewall restart
```

### 6.4 开放端口

允许外网访问路由器的某个端口：

```bash
# 开放 SSH 端口（22）
config rule
    option name 'Allow-SSH'
    option src 'wan'
    option dest_port '22'
    option proto 'tcp'
    option target 'ACCEPT'

# 命令行方式
uci add firewall rule
uci set firewall.@rule[-1].name='Allow-SSH'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].dest_port='22'
uci set firewall.@rule[-1].proto='tcp'
uci set firewall.@rule[-1].target='ACCEPT'
uci commit firewall
/etc/init.d/firewall restart
```

### 6.5 流量规则示例

```bash
# 禁止某个 MAC 地址上网
config rule
    option name 'Block-Device'
    option src 'lan'
    option src_mac '00:11:22:33:44:55'
    option dest 'wan'
    option target 'REJECT'

# 禁止访问某个 IP
config rule
    option name 'Block-IP'
    option src 'lan'
    option dest 'wan'
    option dest_ip '1.2.3.4'
    option target 'REJECT'

# 限制某设备只能访问特定端口
config rule
    option name 'Limit-Ports'
    option src 'lan'
    option src_ip '192.168.1.100'
    option dest 'wan'
    option dest_port '80 443'
    option proto 'tcp'
    option target 'ACCEPT'
```

### 6.6 防火墙命令

```bash
# 查看防火墙状态
/etc/init.d/firewall status

# 重启防火墙
/etc/init.d/firewall restart

# 查看 iptables 规则（fw3）
iptables -L -n -v
iptables -t nat -L -n -v

# 查看 nftables 规则（fw4）
nft list ruleset

# 临时关闭防火墙（调试用）
/etc/init.d/firewall stop
```

---

## 7. 软件包管理

### 7.1 opkg 基础

opkg 是 OpenWRT 的包管理器，类似于 Debian 的 apt。

```bash
# 更新软件源
opkg update

# 搜索软件包
opkg list | grep <keyword>
opkg find <package>

# 安装软件包
opkg install <package>

# 卸载软件包
opkg remove <package>

# 查看已安装的包
opkg list-installed

# 查看包信息
opkg info <package>

# 查看包的文件列表
opkg files <package>
```

### 7.2 软件源配置

```bash
# 官方源配置文件
cat /etc/opkg/distfeeds.conf

# 添加第三方源
echo "src/gz custom https://example.com/packages" >> /etc/opkg/customfeeds.conf

# 国内镜像源（加速下载）
# 清华源
sed -i 's/downloads.openwrt.org/mirrors.tuna.tsinghua.edu.cn\/openwrt/g' /etc/opkg/distfeeds.conf

# 中科大源
sed -i 's/downloads.openwrt.org/mirrors.ustc.edu.cn\/openwrt/g' /etc/opkg/distfeeds.conf
```

### 7.3 常用软件包

```bash
# 中文语言包
opkg install luci-i18n-base-zh-cn

# 文件管理
opkg install luci-app-filetransfer

# 磁盘管理
opkg install block-mount e2fsprogs

# USB 支持
opkg install kmod-usb-core kmod-usb-storage kmod-usb2 kmod-usb3

# 网络工具
opkg install tcpdump iperf3 mtr bind-dig

# 编辑器
opkg install vim-full nano

# 科学上网相关（需要第三方源）
# opkg install luci-app-passwall
# opkg install luci-app-openclash
```

### 7.4 空间不足处理

```bash
# 查看存储空间
df -h

# 查看大文件
du -sh /* | sort -rh | head -20

# 清理 opkg 缓存
rm -rf /tmp/opkg-lists/*

# 挂载外部存储扩展空间（Extroot）
# 1. 安装必要包
opkg update
opkg install block-mount kmod-fs-ext4 e2fsprogs

# 2. 格式化 U 盘
mkfs.ext4 /dev/sda1

# 3. 配置挂载
block detect > /etc/config/fstab
uci set fstab.@mount[0].target='/overlay'
uci set fstab.@mount[0].enabled='1'
uci commit fstab

# 4. 复制数据并重启
mount /dev/sda1 /mnt
cp -a /overlay/* /mnt/
reboot
```

> **⚠️ 常见错误 #3：opkg update 失败**
> 
> 原因：网络问题或源不可用
> 
> 解决：
> 1. 检查网络连接：`ping 8.8.8.8`
> 2. 检查 DNS：`nslookup downloads.openwrt.org`
> 3. 更换镜像源
> 4. 检查时间是否正确（HTTPS 需要）

---

## 8. 常用服务配置

### 8.1 Samba 文件共享

```bash
# 安装
opkg update
opkg install samba4-server luci-app-samba4

# 配置 /etc/config/samba4
config samba
    option workgroup 'WORKGROUP'
    option name 'OpenWRT'
    option description 'OpenWRT Samba Server'

config sambashare
    option name 'share'
    option path '/mnt/sda1/share'
    option read_only 'no'
    option guest_ok 'yes'
    option create_mask '0666'
    option dir_mask '0777'

# 设置 Samba 用户密码
smbpasswd -a root

# 启动服务
/etc/init.d/samba4 enable
/etc/init.d/samba4 start
```

### 8.2 FTP 服务器

```bash
# 安装
opkg install vsftpd

# 配置 /etc/vsftpd.conf
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_root=/mnt/sda1

# 启动
/etc/init.d/vsftpd enable
/etc/init.d/vsftpd start

# 防火墙开放端口
uci add firewall rule
uci set firewall.@rule[-1].name='Allow-FTP'
uci set firewall.@rule[-1].src='lan'
uci set firewall.@rule[-1].dest_port='21'
uci set firewall.@rule[-1].proto='tcp'
uci set firewall.@rule[-1].target='ACCEPT'
uci commit firewall
/etc/init.d/firewall restart
```

### 8.3 DDNS 动态域名

```bash
# 安装
opkg install ddns-scripts luci-app-ddns

# 常用 DDNS 服务商脚本
opkg install ddns-scripts-cloudflare
opkg install ddns-scripts-aliyun
opkg install ddns-scripts-dnspod

# 配置示例（Cloudflare）
config service 'cloudflare'
    option enabled '1'
    option service_name 'cloudflare.com-v4'
    option domain 'subdomain.example.com'
    option username 'your_email'
    option password 'your_api_key'
    option ip_source 'web'
    option ip_url 'http://ip.sb'
```

### 8.4 WireGuard VPN

```bash
# 安装
opkg install wireguard-tools luci-app-wireguard

# 生成密钥对
wg genkey | tee privatekey | wg pubkey > publickey

# 配置 /etc/config/network
config interface 'wg0'
    option proto 'wireguard'
    option private_key 'YOUR_PRIVATE_KEY'
    option listen_port '51820'
    list addresses '10.0.0.1/24'

config wireguard_wg0
    option public_key 'PEER_PUBLIC_KEY'
    option allowed_ips '10.0.0.2/32'
    option persistent_keepalive '25'

# 防火墙配置
config zone
    option name 'wg'
    list network 'wg0'
    option input 'ACCEPT'
    option output 'ACCEPT'
    option forward 'ACCEPT'

config forwarding
    option src 'wg'
    option dest 'lan'

config forwarding
    option src 'wg'
    option dest 'wan'

# 开放 WireGuard 端口
config rule
    option name 'Allow-WireGuard'
    option src 'wan'
    option dest_port '51820'
    option proto 'udp'
    option target 'ACCEPT'
```

### 8.5 AdGuard Home 广告过滤

```bash
# 下载 AdGuard Home
cd /tmp
wget https://github.com/AdguardTeam/AdGuardHome/releases/download/v0.107.43/AdGuardHome_linux_arm64.tar.gz
tar -xzf AdGuardHome_linux_arm64.tar.gz
mv AdGuardHome /usr/bin/

# 安装为服务
AdGuardHome -s install

# 访问 http://192.168.1.1:3000 进行初始化配置

# 配置 OpenWRT 使用 AdGuard Home 作为 DNS
uci set dhcp.@dnsmasq[0].port='0'  # 禁用 dnsmasq 的 DNS
uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#53'
uci commit dhcp
/etc/init.d/dnsmasq restart
```

### 8.6 frp 内网穿透

```bash
# 下载 frpc（客户端）
cd /tmp
wget https://github.com/fatedier/frp/releases/download/v0.52.3/frp_0.52.3_linux_arm64.tar.gz
tar -xzf frp_0.52.3_linux_arm64.tar.gz
cp frp_0.52.3_linux_arm64/frpc /usr/bin/

# 配置 /etc/frpc.ini
[common]
server_addr = your_server_ip
server_port = 7000
token = your_token

[ssh]
type = tcp
local_ip = 127.0.0.1
local_port = 22
remote_port = 6000

[web]
type = http
local_ip = 192.168.1.100
local_port = 80
custom_domains = web.example.com

# 创建启动脚本 /etc/init.d/frpc
#!/bin/sh /etc/rc.common
START=99
STOP=10
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/frpc -c /etc/frpc.ini
    procd_set_param respawn
    procd_close_instance
}

# 启动
chmod +x /etc/init.d/frpc
/etc/init.d/frpc enable
/etc/init.d/frpc start
```

---

## 9. 高级网络功能

### 9.1 VLAN 配置

VLAN 用于在同一物理网络上划分多个逻辑网络。

```bash
# 查看交换机配置
swconfig list
swconfig dev switch0 show

# 配置 VLAN（DSA 架构，新版 OpenWRT）
# /etc/config/network

config device
    option name 'br-lan'
    option type 'bridge'
    list ports 'lan1'
    list ports 'lan2'

config device
    option name 'br-guest'
    option type 'bridge'
    list ports 'lan3'
    list ports 'lan4'

# 旧版交换机配置（swconfig）
config switch
    option name 'switch0'
    option reset '1'
    option enable_vlan '1'

config switch_vlan
    option device 'switch0'
    option vlan '1'
    option ports '1 2 3 6t'    # 6t 表示 tagged

config switch_vlan
    option device 'switch0'
    option vlan '2'
    option ports '4 5 6t'
```

### 9.2 多拨与负载均衡

```bash
# 安装 mwan3
opkg install mwan3 luci-app-mwan3

# 创建多个 WAN 接口
config interface 'wan'
    option proto 'pppoe'
    option username 'user1'
    option password 'pass1'
    option device 'eth0.2'

config interface 'wan2'
    option proto 'pppoe'
    option username 'user2'
    option password 'pass2'
    option device 'eth0.3'

# mwan3 配置 /etc/config/mwan3
config interface 'wan'
    option enabled '1'
    list track_ip '8.8.8.8'
    option reliability '1'
    option count '1'
    option timeout '2'
    option interval '5'
    option down '3'
    option up '3'

config interface 'wan2'
    option enabled '1'
    list track_ip '8.8.4.4'
    option reliability '1'

config member 'wan_m1_w1'
    option interface 'wan'
    option metric '1'
    option weight '1'

config member 'wan2_m1_w1'
    option interface 'wan2'
    option metric '1'
    option weight '1'

config policy 'balanced'
    list use_member 'wan_m1_w1'
    list use_member 'wan2_m1_w1'

config rule 'default_rule'
    option dest_ip '0.0.0.0/0'
    option use_policy 'balanced'
```

### 9.3 QoS 流量控制

```bash
# 安装 SQM（Smart Queue Management）
opkg install sqm-scripts luci-app-sqm

# 配置 /etc/config/sqm
config queue 'eth1'
    option enabled '1'
    option interface 'wan'
    option download '100000'    # 下载带宽 kbps
    option upload '50000'       # 上传带宽 kbps
    option qdisc 'cake'
    option script 'piece_of_cake.qos'
    option linklayer 'ethernet'
    option overhead '44'

# 启动
/etc/init.d/sqm enable
/etc/init.d/sqm start
```

### 9.4 策略路由

根据源 IP、目标 IP 或端口选择不同的出口：

```bash
# 创建路由表
echo "100 custom" >> /etc/iproute2/rt_tables

# 添加路由规则
ip rule add from 192.168.1.100 table custom
ip route add default via 10.0.0.1 table custom

# 持久化配置 /etc/config/network
config rule
    option in 'lan'
    option src '192.168.1.100/32'
    option lookup 'custom'

config route
    option interface 'wan2'
    option target '0.0.0.0/0'
    option gateway '10.0.0.1'
    option table 'custom'
```

### 9.5 IPv6 配置

```bash
# /etc/config/network

# WAN6 接口（DHCPv6）
config interface 'wan6'
    option device '@wan'
    option proto 'dhcpv6'
    option reqaddress 'try'
    option reqprefix 'auto'

# LAN IPv6
config interface 'lan'
    option proto 'static'
    option ip6assign '60'

# /etc/config/dhcp
config dhcp 'lan'
    option dhcpv6 'server'
    option ra 'server'
    option ra_management '1'
    option ra_default '1'
```

---

## 10. 性能优化

### 10.1 系统优化

```bash
# 调整内核参数 /etc/sysctl.conf
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

# 应用
sysctl -p

# 开启 BBR（需要内核支持）
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p
```

### 10.2 DNS 优化

```bash
# 使用 DNS 缓存
uci set dhcp.@dnsmasq[0].cachesize='10000'
uci set dhcp.@dnsmasq[0].min_cache_ttl='3600'
uci commit dhcp
/etc/init.d/dnsmasq restart

# 使用更快的上游 DNS
uci add_list dhcp.@dnsmasq[0].server='119.29.29.29'  # DNSPod
uci add_list dhcp.@dnsmasq[0].server='223.5.5.5'    # 阿里 DNS
```

### 10.3 无线优化

```bash
# 选择干扰少的信道
# 2.4G 推荐：1, 6, 11（不重叠）
# 5G 推荐：36, 149（DFS 信道可能有雷达干扰）

# 调整发射功率
uci set wireless.radio0.txpower='20'

# 启用 802.11r 快速漫游（多 AP 环境）
uci set wireless.default_radio0.ieee80211r='1'
uci set wireless.default_radio0.mobility_domain='abcd'
uci set wireless.default_radio0.ft_over_ds='0'
uci set wireless.default_radio0.ft_psk_generate_local='1'

# 启用 WMM（QoS）
uci set wireless.default_radio0.wmm='1'
```

### 10.4 硬件加速

```bash
# 查看是否支持硬件 NAT
cat /sys/kernel/debug/mtk_ppe/bind

# 开启软件流量卸载
uci set firewall.@defaults[0].flow_offloading='1'

# 开启硬件流量卸载（需要硬件支持）
uci set firewall.@defaults[0].flow_offloading_hw='1'

uci commit firewall
/etc/init.d/firewall restart
```

---

## 11. 故障排查

### 11.1 常用诊断命令

```bash
# 查看系统日志
logread
logread -f              # 实时查看
logread | grep error    # 过滤错误

# 查看内核日志
dmesg

# 查看系统资源
top
free -m
df -h

# 网络诊断
ping 8.8.8.8            # 测试网络连通性
traceroute 8.8.8.8      # 追踪路由
nslookup google.com     # DNS 解析测试
tcpdump -i eth0         # 抓包

# 查看连接状态
netstat -tunlp
ss -tunlp
cat /proc/net/nf_conntrack | wc -l  # 连接数

# 查看接口状态
ifstatus wan
ifstatus lan
```

### 11.2 网络不通排查流程

```
1. 检查物理连接
   - 网线是否插好
   - 指示灯是否正常

2. 检查接口状态
   ifstatus wan
   ip addr show

3. 检查 IP 获取
   - DHCP: 是否获取到 IP
   - PPPoE: 是否拨号成功

4. 检查路由
   ip route
   是否有默认路由

5. 检查 DNS
   nslookup google.com
   cat /tmp/resolv.conf.d/resolv.conf.auto

6. 检查防火墙
   iptables -L -n -v
   /etc/init.d/firewall stop  # 临时关闭测试

7. 检查日志
   logread | grep -i error
```

### 11.3 WiFi 问题排查

```bash
# 查看无线状态
wifi status
iwinfo

# 查看无线日志
logread | grep -i hostapd
logread | grep -i wireless

# 重启无线
wifi down && wifi up

# 检查驱动
lsmod | grep -i wifi
dmesg | grep -i wifi

# 扫描信道干扰
iwinfo wlan0 scan
```

### 11.4 救砖方法

**软砖（能进系统但配置错误）**

```bash
# 方法1：恢复出厂设置
firstboot && reboot

# 方法2：故障安全模式
# 开机时按住 Reset 键，等待指示灯闪烁后松开
# 或者开机后快速按 f 键进入 failsafe 模式
mount_root
firstboot
reboot
```

**硬砖（无法启动）**

```
1. 尝试 TFTP 恢复
2. 使用 Breed/U-Boot 恢复
3. TTL 线刷（需要拆机）
4. 编程器刷写（最后手段）
```

---

## 12. 常见错误汇总

### 错误 #1：刷机后无法访问 192.168.1.1

```
原因：
1. IP 地址不在同一网段
2. 网线没插 LAN 口
3. 电脑有多个网卡

解决：
1. 手动设置电脑 IP 为 192.168.1.2
2. 确认网线插在 LAN 口（不是 WAN 口）
3. 禁用其他网卡
```

### 错误 #2：WiFi 无法启动或不稳定

```
原因：
1. 驱动不支持
2. 信道设置不当
3. 国家代码未设置

解决：
1. 检查设备是否完全支持
2. 设置合法信道（CN: 1-13, 36-64, 149-165）
3. 设置国家代码：uci set wireless.radio0.country='CN'
```

### 错误 #3：opkg update 失败

```
错误信息：
Failed to download xxx, wget returned 4

原因：
1. 网络不通
2. DNS 解析失败
3. 系统时间不对（HTTPS 证书验证）

解决：
1. ping 8.8.8.8 测试网络
2. 设置 DNS：echo "nameserver 8.8.8.8" > /etc/resolv.conf
3. 同步时间：ntpd -q -p ntp.aliyun.com
4. 更换镜像源
```

### 错误 #4：PPPoE 拨号失败

```
错误信息：
pppd: PAP authentication failed

原因：
1. 账号密码错误
2. MAC 地址绑定
3. 运营商限制

解决：
1. 确认账号密码正确
2. 克隆原设备 MAC：uci set network.wan.macaddr='xx:xx:xx:xx:xx:xx'
3. 联系运营商解绑
```

### 错误 #5：端口转发不生效

```
原因：
1. 防火墙规则错误
2. 内网设备防火墙阻止
3. 运营商封锁端口
4. 没有公网 IP

解决：
1. 检查防火墙配置
2. 关闭内网设备防火墙测试
3. 换用非常用端口（如 8080）
4. 使用内网穿透（frp、ZeroTier）
```

### 错误 #6：空间不足无法安装软件

```
错误信息：
No space left on device

解决：
1. 清理缓存：rm -rf /tmp/opkg-lists/*
2. 卸载不需要的包：opkg remove xxx
3. 使用 Extroot 扩展存储
4. 使用精简固件
```

### 错误 #7：LuCI 界面无法访问

```
原因：
1. uhttpd 服务未启动
2. 端口被占用
3. LuCI 未安装

解决：
1. 启动服务：/etc/init.d/uhttpd start
2. 检查端口：netstat -tlnp | grep 80
3. 安装 LuCI：opkg install luci
```

### 错误 #8：DNS 解析失败

```
原因：
1. 上游 DNS 不可用
2. dnsmasq 配置错误
3. 防火墙阻止

解决：
1. 测试上游 DNS：nslookup google.com 8.8.8.8
2. 重启 dnsmasq：/etc/init.d/dnsmasq restart
3. 检查防火墙 DNS 规则
```

### 错误 #9：系统时间不对

```
原因：
1. NTP 服务未启动
2. 时区设置错误
3. 网络不通无法同步

解决：
1. 手动同步：ntpd -q -p ntp.aliyun.com
2. 设置时区：uci set system.@system[0].timezone='CST-8'
3. 检查 NTP 服务：/etc/init.d/sysntpd restart
```

### 错误 #10：升级后配置丢失

```
原因：
1. 使用了 sysupgrade -n（不保留配置）
2. 配置文件不在保留列表中

预防：
1. 升级前备份：sysupgrade -b /tmp/backup.tar.gz
2. 将自定义配置加入保留列表：/etc/sysupgrade.conf
```

---

## 附录：常用命令速查

### 系统管理

```bash
reboot                      # 重启
poweroff                    # 关机
firstboot                   # 恢复出厂设置
sysupgrade xxx.bin          # 系统升级
passwd                      # 修改密码
```

### 网络管理

```bash
ifup wan                    # 启动 WAN 接口
ifdown wan                  # 停止 WAN 接口
/etc/init.d/network restart # 重启网络
wifi reload                 # 重载无线
```

### 服务管理

```bash
/etc/init.d/xxx start       # 启动服务
/etc/init.d/xxx stop        # 停止服务
/etc/init.d/xxx restart     # 重启服务
/etc/init.d/xxx enable      # 开机自启
/etc/init.d/xxx disable     # 禁止自启
```

### UCI 配置

```bash
uci show xxx                # 查看配置
uci set xxx.yyy='zzz'       # 设置值
uci add_list xxx.yyy='zzz'  # 添加列表项
uci delete xxx.yyy          # 删除配置
uci commit                  # 保存配置
reload_config               # 应用配置
```

### 文件操作

```bash
vi /etc/config/xxx          # 编辑配置文件
cat /etc/config/xxx         # 查看配置文件
scp file root@192.168.1.1:/tmp/  # 上传文件
```

---

## 附录：推荐资源

**官方资源**
- 官网：https://openwrt.org/
- 下载：https://downloads.openwrt.org/
- 文档：https://openwrt.org/docs/start
- 设备支持列表：https://openwrt.org/toh/start

**社区资源**
- 恩山论坛：https://www.right.com.cn/forum/
- GitHub：https://github.com/openwrt/openwrt
- Reddit：https://www.reddit.com/r/openwrt/

**常用第三方固件**
- ImmortalWrt：https://immortalwrt.org/
- LEDE：历史版本
- Padavan：华硕路由器

---

> 📝 **学习建议**
> 
> 1. 先在虚拟机或旧设备上练习，避免把主路由刷坏
> 2. 刷机前一定要备份原厂固件
> 3. 遇到问题先看日志：`logread | grep error`
> 4. 善用搜索引擎和恩山论坛
> 5. 保持固件更新，关注安全公告
