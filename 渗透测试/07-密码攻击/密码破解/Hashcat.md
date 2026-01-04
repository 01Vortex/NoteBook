

> 世界上最快的密码恢复工具 - 基于 2024/2025 最新版本

---

## 目录

1. [Hashcat 概述](#1-hashcat-概述)
2. [安装与配置](#2-安装与配置)
3. [核心概念](#3-核心概念)
4. [基础使用](#4-基础使用)
5. [攻击模式详解](#5-攻击模式详解)
6. [规则攻击](#6-规则攻击)
7. [掩码攻击](#7-掩码攻击)
8. [高级技巧](#8-高级技巧)
9. [实战案例](#9-实战案例)
10. [性能优化](#10-性能优化)
11. [常见错误与解决](#11-常见错误与解决)

---

## 1. Hashcat 概述

### 1.1 什么是 Hashcat？

Hashcat 是世界上最快、最先进的密码恢复工具。它利用 GPU（显卡）的强大并行计算能力，可以在极短时间内尝试数十亿个密码组合。

**通俗理解**：如果把密码破解比作开锁，传统 CPU 工具就像一个人拿着钥匙一把一把试，而 Hashcat 就像同时派出几千个人一起试，速度快得惊人。

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Hashcat 工作原理                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────────────┐   │
│   │  密码字典    │     │  Hashcat    │     │  目标哈希           │   │
│   │  或掩码规则  │ ──▶ │  (GPU 加速)  │ ──▶ │  5f4dcc3b5aa765d6...│   │
│   └─────────────┘     └─────────────┘     └─────────────────────┘   │
│                              │                                       │
│                              ▼                                       │
│                    ┌─────────────────────┐                          │
│                    │  计算每个候选密码    │                          │
│                    │  的哈希值并比对      │                          │
│                    └─────────────────────┘                          │
│                              │                                       │
│                              ▼                                       │
│                    ┌─────────────────────┐                          │
│                    │  匹配成功！          │                          │
│                    │  password → 5f4d... │                          │
│                    └─────────────────────┘                          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.2 Hashcat vs John the Ripper

| 特性 | Hashcat | John the Ripper |
|------|---------|-----------------|
| 主要加速 | GPU | CPU |
| 速度 | 极快（GPU 并行） | 较快（CPU 优化） |
| 哈希类型 | 600+ 种 | 400+ 种 |
| 学习曲线 | 较陡 | 较平缓 |
| 内存需求 | 较高（GPU 显存） | 较低 |
| 适用场景 | 大规模破解 | 灵活性高、格式转换 |

### 1.3 支持的哈希类型

Hashcat 支持超过 600 种哈希类型，包括：

```
┌─────────────────────────────────────────────────────────────────────┐
│ 常见哈希类型分类                                                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 【通用哈希】                                                          │
│ • MD5, SHA1, SHA256, SHA512                                         │
│ • MD4, RIPEMD-160, Whirlpool                                        │
│                                                                      │
│ 【操作系统】                                                          │
│ • Windows: NTLM, LM, NTLMv2, MSCash2                                │
│ • Linux: md5crypt, sha256crypt, sha512crypt, bcrypt                 │
│ • macOS: PBKDF2-SHA512                                              │
│                                                                      │
│ 【数据库】                                                            │
│ • MySQL, PostgreSQL, Oracle, MSSQL                                  │
│ • MongoDB, Redis                                                    │
│                                                                      │
│ 【Web 应用】                                                          │
│ • WordPress, Joomla, Drupal, phpBB                                  │
│ • Django, Laravel, bcrypt                                           │
│                                                                      │
│ 【网络协议】                                                          │
│ • WPA/WPA2/WPA3, Kerberos, SNMP                                     │
│ • NetNTLMv1/v2, RADIUS                                              │
│                                                                      │
│ 【加密货币】                                                          │
│ • Bitcoin, Ethereum, Litecoin 钱包                                  │
│                                                                      │
│ 【文档加密】                                                          │
│ • MS Office, PDF, ZIP, RAR, 7z                                      │
│ • KeePass, 1Password, LastPass                                      │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.4 法律声明

```
⚠️ 重要提醒 ⚠️

Hashcat 是一个合法的安全审计工具，但必须在合法授权的情况下使用：

✓ 合法使用场景：
  • 恢复自己忘记的密码
  • 授权的渗透测试
  • 安全审计和合规检查
  • 学术研究和教育目的
  • CTF 比赛

✗ 非法使用：
  • 未经授权破解他人密码
  • 入侵他人系统
  • 任何违反当地法律的行为

违法使用可能导致严重的法律后果！
```

---

## 2. 安装与配置

### 2.1 系统要求

```
┌─────────────────────────────────────────────────────────────────────┐
│ 硬件要求                                                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 【最低配置】                                                          │
│ • CPU: 64 位处理器                                                   │
│ • 内存: 4GB RAM                                                      │
│ • GPU: 支持 OpenCL 1.2+ 或 CUDA                                     │
│ • 显存: 1GB+                                                         │
│                                                                      │
│ 【推荐配置】                                                          │
│ • CPU: 多核处理器                                                    │
│ • 内存: 16GB+ RAM                                                    │
│ • GPU: NVIDIA RTX 3080/4080/4090 或 AMD RX 6800+                   │
│ • 显存: 8GB+                                                         │
│ • 存储: SSD（用于大字典）                                            │
│                                                                      │
│ 【支持的 GPU】                                                        │
│ • NVIDIA: CUDA（推荐，性能最佳）                                     │
│ • AMD: ROCm / OpenCL                                                │
│ • Intel: OpenCL                                                     │
│ • Apple Silicon: Metal                                              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 安装方法

```bash
# Kali Linux（预装）
hashcat --version

# 如果未安装
sudo apt update
sudo apt install hashcat

# Ubuntu/Debian
sudo apt update
sudo apt install hashcat

# Arch Linux
sudo pacman -S hashcat

# macOS
brew install hashcat

# Windows
# 从官网下载: https://hashcat.net/hashcat/
# 解压到任意目录即可使用

# 从源码编译（获取最新版本）
git clone https://github.com/hashcat/hashcat.git
cd hashcat
make
sudo make install
```

### 2.3 GPU 驱动安装

```bash
# NVIDIA GPU（推荐）
# 安装 NVIDIA 驱动
sudo apt install nvidia-driver-535  # 或更新版本

# 安装 CUDA Toolkit
sudo apt install nvidia-cuda-toolkit

# 验证安装
nvidia-smi
nvcc --version

# AMD GPU
# 安装 ROCm
wget https://repo.radeon.com/amdgpu-install/latest/ubuntu/jammy/amdgpu-install_5.7.50700-1_all.deb
sudo apt install ./amdgpu-install_5.7.50700-1_all.deb
sudo amdgpu-install --usecase=rocm

# 验证安装
rocminfo
clinfo

# Intel GPU
sudo apt install intel-opencl-icd

# 验证 OpenCL 设备
clinfo
hashcat -I
```

### 2.4 验证安装

```bash
# 查看版本
hashcat --version

# 查看帮助
hashcat --help

# 列出支持的设备
hashcat -I

# 基准测试
hashcat -b

# 测试特定哈希类型
hashcat -b -m 0      # MD5
hashcat -b -m 1000   # NTLM
hashcat -b -m 22000  # WPA-PBKDF2-PMKID+EAPOL

# 输出示例
# Speed.#1.........: 25000.0 MH/s (MD5)
# Speed.#1.........: 45000.0 MH/s (NTLM)
```


---

## 3. 核心概念

### 3.1 哈希模式 (-m)

每种哈希类型都有一个唯一的模式编号：

```bash
# 查看所有支持的哈希模式
hashcat --help | grep -E "^\s+[0-9]+"

# 常用哈希模式速查表
┌──────────┬────────────────────────────────────────────────────────┐
│ 模式 (-m) │ 哈希类型                                               │
├──────────┼────────────────────────────────────────────────────────┤
│ 0        │ MD5                                                    │
│ 10       │ md5($pass.$salt)                                       │
│ 20       │ md5($salt.$pass)                                       │
│ 50       │ HMAC-MD5 (key = $pass)                                 │
│ 100      │ SHA1                                                   │
│ 110      │ sha1($pass.$salt)                                      │
│ 300      │ MySQL4.1/MySQL5                                        │
│ 400      │ phpass (WordPress, Joomla, phpBB3)                     │
│ 500      │ md5crypt, MD5(Unix)                                    │
│ 900      │ MD4                                                    │
│ 1000     │ NTLM                                                   │
│ 1100     │ Domain Cached Credentials (DCC), MS Cache              │
│ 1400     │ SHA256                                                 │
│ 1700     │ SHA512                                                 │
│ 1800     │ sha512crypt, SHA512(Unix)                              │
│ 2100     │ Domain Cached Credentials 2 (DCC2), MS Cache 2         │
│ 2500     │ WPA/WPA2 (已弃用，使用 22000)                           │
│ 2611     │ vBulletin < v3.8.5                                     │
│ 2711     │ vBulletin >= v3.8.5                                    │
│ 3000     │ LM                                                     │
│ 3200     │ bcrypt                                                 │
│ 5500     │ NetNTLMv1 / NetNTLMv1+ESS                              │
│ 5600     │ NetNTLMv2                                              │
│ 6300     │ AIX {smd5}                                             │
│ 7300     │ IPMI2 RAKP HMAC-SHA1                                   │
│ 7500     │ Kerberos 5 AS-REQ Pre-Auth etype 23                    │
│ 10000    │ Django (PBKDF2-SHA256)                                 │
│ 10900    │ PBKDF2-HMAC-SHA256                                     │
│ 11300    │ Bitcoin/Litecoin wallet.dat                            │
│ 11600    │ 7-Zip                                                  │
│ 12500    │ RAR3-hp                                                │
│ 13000    │ RAR5                                                   │
│ 13100    │ Kerberos 5 TGS-REP etype 23 (Kerberoasting)            │
│ 13400    │ KeePass 1/2                                            │
│ 13600    │ WinZip                                                 │
│ 16800    │ WPA-PMKID-PBKDF2                                       │
│ 17200    │ PKZIP (Compressed)                                     │
│ 18200    │ Kerberos 5 AS-REP etype 23 (AS-REP Roasting)           │
│ 22000    │ WPA-PBKDF2-PMKID+EAPOL (推荐用于 WiFi)                  │
│ 22100    │ BitLocker                                              │
│ 28100    │ Windows Hello PIN/Password                             │
└──────────┴────────────────────────────────────────────────────────┘

# 识别哈希类型
# 使用 hashid 或 hash-identifier
hashid '5f4dcc3b5aa765d61d8327deb882cf99'
# 输出: [+] MD5

# 或使用 haiti
haiti '5f4dcc3b5aa765d61d8327deb882cf99'
```

### 3.2 攻击模式 (-a)

```bash
# Hashcat 支持多种攻击模式
┌──────────┬────────────────────────────────────────────────────────┐
│ 模式 (-a) │ 说明                                                   │
├──────────┼────────────────────────────────────────────────────────┤
│ 0        │ 字典攻击 (Straight/Dictionary)                         │
│ 1        │ 组合攻击 (Combination)                                 │
│ 3        │ 掩码攻击 (Brute-force/Mask)                            │
│ 6        │ 混合攻击：字典 + 掩码 (Hybrid Wordlist + Mask)         │
│ 7        │ 混合攻击：掩码 + 字典 (Hybrid Mask + Wordlist)         │
│ 9        │ 关联攻击 (Association)                                 │
└──────────┴────────────────────────────────────────────────────────┘
```

### 3.3 哈希格式

```bash
# 不同哈希类型的格式示例

# MD5 (模式 0)
5f4dcc3b5aa765d61d8327deb882cf99

# MD5 带盐 (模式 10)
# 格式: hash:salt
5f4dcc3b5aa765d61d8327deb882cf99:salt123

# SHA1 (模式 100)
5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8

# NTLM (模式 1000)
32ed87bdb5fdc5e9cba88547376818d4

# sha512crypt (模式 1800)
$6$rounds=5000$salt$hash...

# bcrypt (模式 3200)
$2a$10$N9qo8uLOickgx2ZMRZoMye...

# WPA/WPA2 (模式 22000)
# 使用 hcxpcapngtool 从握手包转换
WPA*02*hash*mac*essid*...

# Kerberos TGS-REP (模式 13100)
$krb5tgs$23$*user$realm$spn*$hash...

# NetNTLMv2 (模式 5600)
username::domain:challenge:response:blob
```

### 3.4 输出格式

```bash
# 破解结果输出格式
# hash:password

# 示例
5f4dcc3b5aa765d61d8327deb882cf99:password
32ed87bdb5fdc5e9cba88547376818d4:admin123

# 输出到文件
hashcat -m 0 hashes.txt wordlist.txt -o cracked.txt

# 输出格式选项
--outfile-format=1   # hash:password (默认)
--outfile-format=2   # password
--outfile-format=3   # hash:password:hex_plain
--outfile-format=4   # hex_plain
--outfile-format=5   # hash:password:hex_plain:crack_pos
```

---

## 4. 基础使用

### 4.1 基本语法

```bash
# 基本格式
hashcat [选项] 哈希文件 [字典/掩码]

# 最简单的用法
hashcat -m 0 hash.txt wordlist.txt

# 完整示例
hashcat -m 0 -a 0 hash.txt wordlist.txt -o cracked.txt

# 参数说明
# -m 0      : 哈希模式（MD5）
# -a 0      : 攻击模式（字典攻击）
# hash.txt  : 包含哈希的文件
# wordlist.txt : 密码字典
# -o        : 输出文件
```

### 4.2 常用选项

```bash
# 基本选项
-m, --hash-type       # 哈希类型
-a, --attack-mode     # 攻击模式
-o, --outfile         # 输出文件
-r, --rules-file      # 规则文件
-w, --workload-profile # 工作负载配置 (1-4)

# 显示选项
--show                # 显示已破解的哈希
--left                # 显示未破解的哈希
--username            # 忽略哈希文件中的用户名
--status              # 启用状态显示
--status-timer=X      # 状态更新间隔（秒）

# 性能选项
-d, --devices         # 指定设备
-D, --opencl-device-types # 设备类型 (1=CPU, 2=GPU, 3=FPGA)
-w, --workload-profile # 工作负载 (1=低, 2=默认, 3=高, 4=噩梦)
-O, --optimized-kernel-enable # 启用优化内核（限制密码长度）
--force               # 忽略警告强制运行

# 会话选项
--session=name        # 会话名称
--restore             # 恢复会话
--restore-file-path   # 恢复文件路径

# 增量选项
--increment           # 启用增量模式
--increment-min=X     # 最小长度
--increment-max=X     # 最大长度

# 温度控制
--hwmon-temp-abort=X  # 温度超过 X 度时中止
```

### 4.3 第一个破解示例

```bash
# 步骤 1: 准备哈希文件
echo "5f4dcc3b5aa765d61d8327deb882cf99" > hash.txt

# 步骤 2: 准备字典（使用 rockyou）
# Kali 中位置: /usr/share/wordlists/rockyou.txt
# 如果是压缩的，先解压
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# 步骤 3: 运行 Hashcat
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

# 步骤 4: 查看结果
hashcat -m 0 hash.txt --show
# 输出: 5f4dcc3b5aa765d61d8327deb882cf99:password

# 带详细输出的命令
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt \
    --status \
    --status-timer=10 \
    -o cracked.txt
```

### 4.4 批量破解

```bash
# 准备多个哈希
cat > hashes.txt << EOF
5f4dcc3b5aa765d61d8327deb882cf99
e10adc3949ba59abbe56e057f20f883e
d8578edf8458ce06fbc5bb76a58c5ca4
25f9e794323b453885f5181f1b624d0b
EOF

# 批量破解
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt -o cracked.txt

# 查看所有已破解
hashcat -m 0 hashes.txt --show

# 查看未破解
hashcat -m 0 hashes.txt --left
```

### 4.5 会话管理

```bash
# 创建命名会话
hashcat -m 0 -a 0 hashes.txt wordlist.txt --session=mysession

# 暂停会话
# 按 'p' 暂停，按 'r' 恢复，按 'q' 退出并保存

# 恢复会话
hashcat --session=mysession --restore

# 查看会话状态
hashcat --session=mysession --status

# 会话文件位置
ls ~/.local/share/hashcat/sessions/
# 或 Windows: %APPDATA%\hashcat\sessions\
```


---

## 5. 攻击模式详解

### 5.1 字典攻击 (-a 0)

字典攻击是最基本也是最常用的攻击方式，使用预先准备好的密码列表逐个尝试。

```bash
# 基本字典攻击
hashcat -m 0 -a 0 hash.txt wordlist.txt

# 使用多个字典
hashcat -m 0 -a 0 hash.txt wordlist1.txt wordlist2.txt wordlist3.txt

# 常用字典位置（Kali Linux）
/usr/share/wordlists/rockyou.txt           # 最常用，1400万密码
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/fasttrack.txt
/usr/share/seclists/Passwords/            # SecLists 集合

# 推荐字典
# rockyou.txt - 通用密码
# darkweb2017-top10000.txt - 暗网泄露
# xato-net-10-million-passwords.txt - 大型字典
# probable-v2-top12000.txt - 高概率密码

# 字典攻击 + 规则
hashcat -m 0 -a 0 hash.txt wordlist.txt -r rules/best64.rule
```

**字典攻击的优缺点**：

```
优点：
✓ 速度快（只尝试字典中的密码）
✓ 对常见密码非常有效
✓ 资源消耗相对较低

缺点：
✗ 只能破解字典中存在的密码
✗ 对复杂密码无效
✗ 依赖字典质量
```

### 5.2 组合攻击 (-a 1)

组合攻击将两个字典中的单词组合在一起，适合破解由两个单词组成的密码。

```bash
# 基本组合攻击
hashcat -m 0 -a 1 hash.txt dict1.txt dict2.txt

# 示例
# dict1.txt: hello, world, admin
# dict2.txt: 123, 456, 789
# 组合结果: hello123, hello456, hello789, world123, world456...

# 创建测试字典
echo -e "admin\nuser\ntest" > dict1.txt
echo -e "123\n456\n@123" > dict2.txt

# 运行组合攻击
hashcat -m 0 -a 1 hash.txt dict1.txt dict2.txt

# 组合攻击 + 规则
hashcat -m 0 -a 1 hash.txt dict1.txt dict2.txt -j '$-' -k '$!'
# -j: 应用于左边字典的规则
# -k: 应用于右边字典的规则
# 结果: admin-123!, user-456!, test-@123!
```

### 5.3 掩码攻击 (-a 3)

掩码攻击（也称暴力破解）按照指定的模式生成所有可能的密码组合。

```bash
# 掩码字符集
# ?l = 小写字母 (a-z)
# ?u = 大写字母 (A-Z)
# ?d = 数字 (0-9)
# ?s = 特殊字符 (!@#$%^&*...)
# ?a = 所有可打印字符 (?l?u?d?s)
# ?b = 所有字节 (0x00-0xff)

# 基本掩码攻击
hashcat -m 0 -a 3 hash.txt ?l?l?l?l?l?l    # 6位小写字母
hashcat -m 0 -a 3 hash.txt ?d?d?d?d?d?d    # 6位数字
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a    # 6位任意字符

# 混合掩码
hashcat -m 0 -a 3 hash.txt ?u?l?l?l?l?d?d  # 首字母大写 + 4小写 + 2数字
# 示例: Admin01, Hello99, World42

# 固定字符 + 掩码
hashcat -m 0 -a 3 hash.txt admin?d?d?d     # admin + 3位数字
hashcat -m 0 -a 3 hash.txt ?d?d?d?d@123    # 4位数字 + @123

# 自定义字符集
hashcat -m 0 -a 3 hash.txt -1 ?l?d ?1?1?1?1?1?1
# -1 定义字符集1为小写字母和数字
# ?1 使用字符集1

# 多个自定义字符集
hashcat -m 0 -a 3 hash.txt -1 ?l?u -2 ?d?s -3 abc ?1?1?2?2?3
# -1: 大小写字母
# -2: 数字和特殊字符
# -3: 只有 a, b, c

# 增量模式（从短到长）
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a?a?a --increment --increment-min=1 --increment-max=8
# 从1位尝试到8位
```

**掩码攻击计算量**：

```
┌─────────────────────────────────────────────────────────────────────┐
│ 掩码攻击组合数计算                                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ ?l (26) × 6位 = 26^6 = 308,915,776 (约3亿)                          │
│ ?d (10) × 6位 = 10^6 = 1,000,000 (100万)                            │
│ ?a (95) × 6位 = 95^6 = 735,091,890,625 (约7350亿)                   │
│                                                                      │
│ 假设速度 10 GH/s (100亿/秒):                                         │
│ • 6位小写: 0.03秒                                                    │
│ • 6位数字: 0.0001秒                                                  │
│ • 6位任意: 73秒                                                      │
│ • 8位任意: 约19年                                                    │
│                                                                      │
│ 结论: 掩码越精确，破解越快！                                          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.4 混合攻击 (-a 6 和 -a 7)

混合攻击结合字典和掩码，非常适合破解"单词+数字"类型的密码。

```bash
# 模式 6: 字典 + 掩码（字典在前）
hashcat -m 0 -a 6 hash.txt wordlist.txt ?d?d?d
# 示例: password123, admin456, hello789

hashcat -m 0 -a 6 hash.txt wordlist.txt ?d?d?d?d
# 示例: password1234, admin5678

hashcat -m 0 -a 6 hash.txt wordlist.txt ?s?d?d
# 示例: password!23, admin@45

# 模式 7: 掩码 + 字典（掩码在前）
hashcat -m 0 -a 7 hash.txt ?d?d?d wordlist.txt
# 示例: 123password, 456admin, 789hello

hashcat -m 0 -a 7 hash.txt ?u?u?u wordlist.txt
# 示例: ABCpassword, XYZadmin

# 混合攻击 + 规则
hashcat -m 0 -a 6 hash.txt wordlist.txt ?d?d?d -r rules/best64.rule
```

### 5.5 关联攻击 (-a 9)

关联攻击是 Hashcat 6.0+ 的新功能，使用用户名或其他关联信息来生成密码候选。

```bash
# 准备哈希文件（包含用户名）
# 格式: username:hash
cat > hashes_with_users.txt << EOF
john:5f4dcc3b5aa765d61d8327deb882cf99
admin:e10adc3949ba59abbe56e057f20f883e
EOF

# 关联攻击
hashcat -m 0 -a 9 hashes_with_users.txt wordlist.txt

# 这会尝试基于用户名的变体
# 如 john -> john123, john!, John, JOHN 等
```

---

## 6. 规则攻击

### 6.1 规则基础

规则攻击通过对字典中的每个单词应用变换规则，大大扩展了攻击范围。

```bash
# 使用规则文件
hashcat -m 0 -a 0 hash.txt wordlist.txt -r rules/best64.rule

# 使用多个规则文件
hashcat -m 0 -a 0 hash.txt wordlist.txt -r rules/best64.rule -r rules/toggles1.rule

# 内置规则文件位置
ls /usr/share/hashcat/rules/
# 或
ls ~/.local/share/hashcat/rules/

# 常用规则文件
# best64.rule        - 最常用的64条规则
# rockyou-30000.rule - 基于 rockyou 分析的规则
# d3ad0ne.rule       - 大型规则集
# dive.rule          - 深度规则
# toggles1.rule      - 大小写切换
# leetspeak.rule     - Leet 替换
# InsidePro-PasswordsPro.rule - 专业规则集
```

### 6.2 规则语法

```bash
# 基本规则函数
┌──────────┬────────────────────────────────────────────────────────┐
│ 规则      │ 说明                                                   │
├──────────┼────────────────────────────────────────────────────────┤
│ :        │ 不做任何修改                                            │
│ l        │ 全部转小写                                              │
│ u        │ 全部转大写                                              │
│ c        │ 首字母大写                                              │
│ C        │ 首字母小写，其余大写                                    │
│ t        │ 大小写切换                                              │
│ r        │ 反转字符串                                              │
│ d        │ 复制字符串                                              │
│ f        │ 反转并追加                                              │
│ $X       │ 在末尾追加字符 X                                        │
│ ^X       │ 在开头添加字符 X                                        │
│ [        │ 删除第一个字符                                          │
│ ]        │ 删除最后一个字符                                        │
│ sXY      │ 将 X 替换为 Y                                           │
│ @X       │ 删除所有 X 字符                                         │
│ DN       │ 删除位置 N 的字符                                       │
│ iNX      │ 在位置 N 插入字符 X                                     │
│ oNX      │ 用 X 覆盖位置 N 的字符                                  │
│ 'N       │ 截断到 N 个字符                                         │
│ xNM      │ 从位置 N 提取 M 个字符                                  │
└──────────┴────────────────────────────────────────────────────────┘

# 示例（假设原始单词是 "password"）
:           → password      (不变)
l           → password      (已经是小写)
u           → PASSWORD      (全大写)
c           → Password      (首字母大写)
t           → PASSWORD      (切换大小写)
r           → drowssap      (反转)
d           → passwordpassword (复制)
$1          → password1     (末尾加1)
$!          → password!     (末尾加!)
^1          → 1password     (开头加1)
[           → assword       (删除首字符)
]           → passwor       (删除尾字符)
sa@         → p@ssword      (a替换为@)
se3         → passw0rd      (e替换为3... 等等，这里应该是 so0)
so0         → passw0rd      (o替换为0)
```

### 6.3 创建自定义规则

```bash
# 创建规则文件
cat > my_rules.rule << EOF
:
l
u
c
$1
$!
$123
^1
sa@
se3
so0
si1
c $1
c $!
c $123
l $1
l $!
u $1
EOF

# 使用自定义规则
hashcat -m 0 -a 0 hash.txt wordlist.txt -r my_rules.rule

# 常见密码模式规则
cat > common_patterns.rule << EOF
# 原始
:
# 大小写变换
l
u
c
C
t
# 数字后缀
$1
$12
$123
$1234
$!
$@
$#
# 数字前缀
^1
^12
^123
# Leet speak
sa@
se3
si1
so0
ss$
# 组合
c $1
c $!
c $123
l $1
u $1
# 年份后缀
$2$0$2$4
$2$0$2$5
# 常见后缀
$!$!
$!$@$#
EOF

# 测试规则效果
echo "password" | hashcat -r my_rules.rule --stdout
```

### 6.4 规则生成工具

```bash
# 使用 hashcat-utils 中的工具
# 安装
git clone https://github.com/hashcat/hashcat-utils.git
cd hashcat-utils/src
make

# rli - 规则生成
./rli wordlist.txt rules.rule > expanded_wordlist.txt

# 使用 Mentalist（GUI 工具）生成规则
# 可以可视化创建复杂规则链

# 使用 PACK (Password Analysis and Cracking Kit)
# 分析密码模式并生成规则
python3 statsgen.py passwords.txt
python3 rulegen.py passwords.txt
```


---

## 7. 掩码攻击

### 7.1 掩码文件 (.hcmask)

掩码文件允许你定义多个掩码，Hashcat 会按顺序尝试。

```bash
# 创建掩码文件
cat > masks.hcmask << EOF
# 纯数字
?d?d?d?d
?d?d?d?d?d
?d?d?d?d?d?d
?d?d?d?d?d?d?d
?d?d?d?d?d?d?d?d

# 小写字母
?l?l?l?l?l?l
?l?l?l?l?l?l?l
?l?l?l?l?l?l?l?l

# 首字母大写 + 小写 + 数字
?u?l?l?l?l?d?d
?u?l?l?l?l?l?d?d
?u?l?l?l?l?l?l?d?d

# 常见模式
?u?l?l?l?l?l?d?d?s
?l?l?l?l?l?l?d?d?d?d
EOF

# 使用掩码文件
hashcat -m 0 -a 3 hash.txt masks.hcmask

# 带自定义字符集的掩码文件
cat > custom_masks.hcmask << EOF
# 格式: [自定义字符集,]掩码
# 自定义字符集1为小写和数字
?l?d,?1?1?1?1?1?1
# 自定义字符集1为特定字符
aeiou,?1?1?1?1?1
# 多个自定义字符集
?l?u,?d?s,?1?1?2?2?1?1
EOF
```

### 7.2 常用掩码模式

```bash
# 针对不同密码策略的掩码

# 1. 纯数字密码（如 PIN 码）
hashcat -m 0 -a 3 hash.txt ?d?d?d?d           # 4位
hashcat -m 0 -a 3 hash.txt ?d?d?d?d?d?d       # 6位
hashcat -m 0 -a 3 hash.txt ?d?d?d?d?d?d?d?d   # 8位

# 2. 纯小写字母
hashcat -m 0 -a 3 hash.txt ?l?l?l?l?l?l       # 6位
hashcat -m 0 -a 3 hash.txt ?l?l?l?l?l?l?l?l   # 8位

# 3. 首字母大写（常见模式）
hashcat -m 0 -a 3 hash.txt ?u?l?l?l?l?l       # Password
hashcat -m 0 -a 3 hash.txt ?u?l?l?l?l?l?d?d   # Password12

# 4. 字母+数字
hashcat -m 0 -a 3 hash.txt -1 ?l?d ?1?1?1?1?1?1?1?1  # 8位字母数字

# 5. 复杂密码（大小写+数字+特殊）
hashcat -m 0 -a 3 hash.txt ?u?l?l?l?l?d?d?s   # Passw0rd!

# 6. 年份后缀
hashcat -m 0 -a 3 hash.txt ?l?l?l?l?l?l2024
hashcat -m 0 -a 3 hash.txt ?l?l?l?l?l?l2025
hashcat -m 0 -a 3 hash.txt ?u?l?l?l?l?l202?d

# 7. 手机号（中国）
hashcat -m 0 -a 3 hash.txt 1?d?d?d?d?d?d?d?d?d?d

# 8. 日期格式
hashcat -m 0 -a 3 hash.txt ?d?d?d?d?d?d?d?d   # YYYYMMDD
hashcat -m 0 -a 3 hash.txt ?d?d?d?d-?d?d-?d?d # YYYY-MM-DD
```

### 7.3 增量掩码攻击

```bash
# 从短密码到长密码逐步尝试
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a?a?a \
    --increment \
    --increment-min=1 \
    --increment-max=8

# 这会依次尝试:
# ?a (1位)
# ?a?a (2位)
# ?a?a?a (3位)
# ...
# ?a?a?a?a?a?a?a?a (8位)

# 针对特定长度范围
hashcat -m 0 -a 3 hash.txt ?l?l?l?l?l?l?l?l \
    --increment \
    --increment-min=6 \
    --increment-max=8
# 只尝试 6-8 位小写字母

# 增量模式 + 自定义字符集
hashcat -m 0 -a 3 hash.txt -1 ?l?d ?1?1?1?1?1?1?1?1 \
    --increment \
    --increment-min=4 \
    --increment-max=8
```

### 7.4 Markov 链攻击

Markov 链攻击基于统计分析，优先尝试更可能的字符组合。

```bash
# 生成 Markov 统计文件
# 使用 hashcat-utils 中的 hcstatgen
./hcstatgen wordlist.txt hashcat.hcstat2

# 使用 Markov 攻击
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a?a?a \
    --markov-hcstat2=hashcat.hcstat2 \
    --markov-threshold=100

# 参数说明
# --markov-hcstat2: Markov 统计文件
# --markov-threshold: 阈值（越低越快但覆盖越少）

# 禁用 Markov（纯暴力）
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a --markov-disable
```

---

## 8. 高级技巧

### 8.1 分布式破解

```bash
# 使用 --skip 和 --limit 分割任务
# 机器 1
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a --skip=0 --limit=1000000000

# 机器 2
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a --skip=1000000000 --limit=1000000000

# 机器 3
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a --skip=2000000000 --limit=1000000000

# 使用 Hashtopolis（分布式破解平台）
# https://github.com/hashtopolis/server
# 提供 Web 界面管理多台破解机器

# 使用 Hashview
# https://github.com/hashview/hashview
# 另一个分布式管理平台
```

### 8.2 Brain 功能（去重）

Hashcat Brain 可以在分布式环境中避免重复计算。

```bash
# 启动 Brain 服务器
hashcat --brain-server --brain-host=0.0.0.0 --brain-port=6863 --brain-password=secret

# 客户端连接
hashcat -m 0 -a 0 hash.txt wordlist.txt \
    --brain-client \
    --brain-host=192.168.1.100 \
    --brain-port=6863 \
    --brain-password=secret

# Brain 会记录已尝试的密码，避免重复
```

### 8.3 慢速哈希优化

对于 bcrypt、scrypt 等慢速哈希，需要特殊策略。

```bash
# bcrypt 破解（非常慢）
hashcat -m 3200 -a 0 bcrypt_hash.txt wordlist.txt -w 3

# 使用更小的字典
hashcat -m 3200 -a 0 bcrypt_hash.txt top10000.txt

# 使用精确的掩码
hashcat -m 3200 -a 3 bcrypt_hash.txt ?d?d?d?d?d?d

# 优化内核（可能限制密码长度）
hashcat -m 3200 -a 0 bcrypt_hash.txt wordlist.txt -O

# 对于 PBKDF2、Argon2 等，策略类似
# 关键是减少候选密码数量
```

### 8.4 Prince 攻击

Prince 攻击是一种智能组合攻击，基于概率生成密码。

```bash
# 使用 princeprocessor 生成候选密码
# 安装
git clone https://github.com/hashcat/princeprocessor.git
cd princeprocessor/src
make

# 生成候选密码
./pp64.bin wordlist.txt | hashcat -m 0 hash.txt

# 限制长度
./pp64.bin --pw-min=6 --pw-max=10 wordlist.txt | hashcat -m 0 hash.txt

# 限制元素数量
./pp64.bin --elem-cnt-min=2 --elem-cnt-max=3 wordlist.txt | hashcat -m 0 hash.txt
```

### 8.5 Combinator 攻击增强

```bash
# 使用 combinator 工具
# 安装 hashcat-utils
git clone https://github.com/hashcat/hashcat-utils.git
cd hashcat-utils/src
make

# 组合两个字典
./combinator.bin dict1.txt dict2.txt | hashcat -m 0 hash.txt

# 三个字典组合
./combinator.bin dict1.txt dict2.txt > combined.txt
./combinator.bin combined.txt dict3.txt | hashcat -m 0 hash.txt

# 使用 combinator3
./combinator3.bin dict1.txt dict2.txt dict3.txt | hashcat -m 0 hash.txt
```

### 8.6 Keyboard Walk 攻击

针对键盘上相邻按键组成的密码（如 qwerty, 123456）。

```bash
# 使用 kwprocessor 生成键盘行走密码
# 安装
git clone https://github.com/hashcat/kwprocessor.git
cd kwprocessor
make

# 生成键盘行走密码
./kwp basechars/full.base keymaps/en-us.keymap routes/2-to-16-max-3-direction-changes.route | hashcat -m 0 hash.txt

# 参数说明
# basechars: 起始字符
# keymaps: 键盘布局
# routes: 行走路线规则
```

---

## 9. 实战案例

### 9.1 破解 Windows NTLM 哈希

```bash
# 获取 NTLM 哈希（使用 mimikatz、secretsdump 等）
# 格式: username:RID:LM_hash:NTLM_hash:::

# 提取 NTLM 哈希
cat ntlm_dump.txt | cut -d: -f4 > ntlm_hashes.txt

# 或者直接使用完整格式
# hashcat 会自动识别

# 破解 NTLM
hashcat -m 1000 -a 0 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt

# 使用规则
hashcat -m 1000 -a 0 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# 掩码攻击
hashcat -m 1000 -a 3 ntlm_hashes.txt ?u?l?l?l?l?l?d?d

# 查看结果
hashcat -m 1000 ntlm_hashes.txt --show
```

### 9.2 破解 Linux Shadow 文件

```bash
# 从 /etc/shadow 提取哈希
# 格式: username:$id$salt$hash:...

# 识别哈希类型
# $1$ = MD5 (模式 500)
# $5$ = SHA256 (模式 7400)
# $6$ = SHA512 (模式 1800)
# $y$ = yescrypt (模式 ?)

# 提取哈希
cat shadow | grep -v ':\*:' | grep -v ':!:' | cut -d: -f2 > linux_hashes.txt

# 破解 SHA512crypt
hashcat -m 1800 -a 0 linux_hashes.txt /usr/share/wordlists/rockyou.txt

# 这类哈希较慢，使用小字典
hashcat -m 1800 -a 0 linux_hashes.txt /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt

# 使用规则
hashcat -m 1800 -a 0 linux_hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule -w 3
```

### 9.3 破解 WPA/WPA2 WiFi 密码

```bash
# 步骤 1: 捕获握手包（使用 aircrack-ng）
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon
sudo aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF wlan0mon

# 步骤 2: 转换格式（使用 hcxpcapngtool）
# 安装 hcxtools
sudo apt install hcxtools

# 转换
hcxpcapngtool -o hash.hc22000 capture-01.cap

# 或者从 PMKID 攻击获取
hcxdumptool -i wlan0mon -o dump.pcapng --enable_status=1
hcxpcapngtool -o hash.hc22000 dump.pcapng

# 步骤 3: 破解
hashcat -m 22000 -a 0 hash.hc22000 /usr/share/wordlists/rockyou.txt

# 使用规则
hashcat -m 22000 -a 0 hash.hc22000 wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# 掩码攻击（8位数字密码）
hashcat -m 22000 -a 3 hash.hc22000 ?d?d?d?d?d?d?d?d

# 手机号作为密码
hashcat -m 22000 -a 3 hash.hc22000 1?d?d?d?d?d?d?d?d?d?d

# 查看结果
hashcat -m 22000 hash.hc22000 --show
```

### 9.4 破解 Kerberos 票据 (Kerberoasting)

```bash
# 获取 TGS 票据（使用 GetUserSPNs.py）
impacket-GetUserSPNs -request -dc-ip 192.168.1.1 domain.local/user:password

# 保存哈希
# 格式: $krb5tgs$23$*user$realm$spn*$hash...

# 破解 Kerberos TGS-REP (etype 23)
hashcat -m 13100 -a 0 krb5tgs_hashes.txt /usr/share/wordlists/rockyou.txt

# 使用规则
hashcat -m 13100 -a 0 krb5tgs_hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# AS-REP Roasting (etype 23)
hashcat -m 18200 -a 0 krb5asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

### 9.5 破解 Office 文档密码

```bash
# 提取哈希（使用 office2john）
office2john protected.docx > office_hash.txt

# 或使用 hashcat 自带工具
# 对于 Office 2013+
# 模式 9600: MS Office 2013

# 清理哈希格式
cat office_hash.txt | cut -d: -f2 > clean_hash.txt

# 破解
hashcat -m 9600 -a 0 clean_hash.txt /usr/share/wordlists/rockyou.txt

# Office 版本对应模式
# 9400: MS Office 2007
# 9500: MS Office 2010
# 9600: MS Office 2013
# 9700: MS Office 2016/2019/365
```

### 9.6 破解 ZIP/RAR 压缩包

```bash
# ZIP 文件
# 提取哈希
zip2john protected.zip > zip_hash.txt

# 清理格式
cat zip_hash.txt | cut -d: -f2 > clean_zip_hash.txt

# 识别 ZIP 类型
# 17200: PKZIP (Compressed)
# 17210: PKZIP (Uncompressed)
# 17220: PKZIP (Compressed Multi-File)
# 17225: PKZIP (Mixed Multi-File)
# 17230: PKZIP (Compressed Multi-File Checksum-Only)
# 13600: WinZip

# 破解
hashcat -m 17200 -a 0 clean_zip_hash.txt /usr/share/wordlists/rockyou.txt

# RAR 文件
rar2john protected.rar > rar_hash.txt

# RAR3
hashcat -m 12500 -a 0 rar3_hash.txt wordlist.txt

# RAR5
hashcat -m 13000 -a 0 rar5_hash.txt wordlist.txt

# 7-Zip
7z2john protected.7z > 7z_hash.txt
hashcat -m 11600 -a 0 7z_hash.txt wordlist.txt
```


### 9.7 破解数据库哈希

```bash
# MySQL
# 格式: *HASH (41字符)
# 模式 300: MySQL4.1/MySQL5
hashcat -m 300 -a 0 mysql_hashes.txt wordlist.txt

# PostgreSQL
# 模式 12: PostgreSQL
hashcat -m 12 -a 0 postgres_hashes.txt wordlist.txt

# MSSQL
# 模式 131: MSSQL (2000)
# 模式 132: MSSQL (2005)
# 模式 1731: MSSQL (2012, 2014)
hashcat -m 1731 -a 0 mssql_hashes.txt wordlist.txt

# Oracle
# 模式 112: Oracle S (Type 11)
# 模式 12300: Oracle T (Type 12)
hashcat -m 12300 -a 0 oracle_hashes.txt wordlist.txt

# MongoDB
# 模式 24100: MongoDB ServerKey SCRAM-SHA-1
# 模式 24200: MongoDB ServerKey SCRAM-SHA-256
hashcat -m 24100 -a 0 mongodb_hashes.txt wordlist.txt
```

### 9.8 破解 Web 应用哈希

```bash
# WordPress (phpass)
# 格式: $P$B...
# 模式 400
hashcat -m 400 -a 0 wordpress_hashes.txt wordlist.txt

# Joomla
# 模式 400 (MD5 phpass) 或 11 (Joomla < 2.5.18)
hashcat -m 400 -a 0 joomla_hashes.txt wordlist.txt

# Drupal
# 模式 7900: Drupal7
hashcat -m 7900 -a 0 drupal_hashes.txt wordlist.txt

# Django (PBKDF2-SHA256)
# 格式: pbkdf2_sha256$iterations$salt$hash
# 模式 10000
hashcat -m 10000 -a 0 django_hashes.txt wordlist.txt

# Laravel (bcrypt)
# 模式 3200
hashcat -m 3200 -a 0 laravel_hashes.txt wordlist.txt

# phpBB3
# 模式 400
hashcat -m 400 -a 0 phpbb_hashes.txt wordlist.txt

# vBulletin
# 模式 2611: vBulletin < v3.8.5
# 模式 2711: vBulletin >= v3.8.5
hashcat -m 2711 -a 0 vbulletin_hashes.txt wordlist.txt
```

---

## 10. 性能优化

### 10.1 工作负载配置

```bash
# 工作负载配置 (-w)
# 1 = 低 (桌面使用，不影响其他程序)
# 2 = 默认
# 3 = 高 (专用破解机)
# 4 = 噩梦 (最大性能，系统可能无响应)

hashcat -m 0 -a 0 hash.txt wordlist.txt -w 3

# 对于专用破解机
hashcat -m 0 -a 0 hash.txt wordlist.txt -w 4

# 注意: -w 4 可能导致系统无响应，谨慎使用
```

### 10.2 设备选择

```bash
# 查看可用设备
hashcat -I

# 输出示例:
# OpenCL Platform ID #1
#   Device ID #1: NVIDIA GeForce RTX 4090
#   Device ID #2: NVIDIA GeForce RTX 3080
# OpenCL Platform ID #2
#   Device ID #3: Intel(R) Core(TM) i9-13900K

# 使用特定设备
hashcat -m 0 -a 0 hash.txt wordlist.txt -d 1      # 只用设备1
hashcat -m 0 -a 0 hash.txt wordlist.txt -d 1,2    # 用设备1和2

# 只使用 GPU
hashcat -m 0 -a 0 hash.txt wordlist.txt -D 2

# 使用 CPU 和 GPU
hashcat -m 0 -a 0 hash.txt wordlist.txt -D 1,2

# 设备类型
# -D 1 = CPU
# -D 2 = GPU
# -D 3 = FPGA
```

### 10.3 优化内核

```bash
# 启用优化内核 (-O)
# 优点: 更快
# 缺点: 限制密码长度（通常最大 31 字符）
hashcat -m 0 -a 0 hash.txt wordlist.txt -O

# 检查是否支持优化内核
hashcat -m 0 --help | grep "Password length"

# 对于长密码，不要使用 -O
hashcat -m 0 -a 0 hash.txt wordlist.txt  # 支持更长密码
```

### 10.4 温度控制

```bash
# 设置温度限制
hashcat -m 0 -a 0 hash.txt wordlist.txt --hwmon-temp-abort=90

# 查看温度
hashcat -m 0 -a 0 hash.txt wordlist.txt --hwmon-disable=false

# 在运行时按 's' 查看状态，包括温度

# 建议温度设置
# --hwmon-temp-abort=85  # 超过85度中止
# 保持 GPU 温度在 70-80 度为佳
```

### 10.5 内存优化

```bash
# 对于大字典，使用流式处理
# Hashcat 会自动处理，但可以调整

# 减少内存使用
hashcat -m 0 -a 0 hash.txt wordlist.txt --bitmap-min=16

# 对于大量哈希
hashcat -m 0 -a 0 large_hashes.txt wordlist.txt --hash-info

# 分批处理大量哈希
split -l 100000 large_hashes.txt hash_part_
for f in hash_part_*; do
    hashcat -m 0 -a 0 "$f" wordlist.txt -o "cracked_$f"
done
```

### 10.6 性能基准参考

```
┌─────────────────────────────────────────────────────────────────────┐
│ GPU 性能参考 (2024/2025)                                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 【NVIDIA RTX 4090】                                                  │
│ • MD5:        ~165 GH/s                                             │
│ • NTLM:       ~300 GH/s                                             │
│ • SHA1:       ~55 GH/s                                              │
│ • SHA256:     ~22 GH/s                                              │
│ • bcrypt:     ~180 kH/s                                             │
│ • WPA2:       ~2.5 MH/s                                             │
│                                                                      │
│ 【NVIDIA RTX 3080】                                                  │
│ • MD5:        ~65 GH/s                                              │
│ • NTLM:       ~120 GH/s                                             │
│ • SHA1:       ~22 GH/s                                              │
│ • SHA256:     ~9 GH/s                                               │
│ • bcrypt:     ~70 kH/s                                              │
│ • WPA2:       ~1 MH/s                                               │
│                                                                      │
│ 【AMD RX 7900 XTX】                                                  │
│ • MD5:        ~90 GH/s                                              │
│ • NTLM:       ~160 GH/s                                             │
│ • SHA1:       ~30 GH/s                                              │
│ • SHA256:     ~12 GH/s                                              │
│                                                                      │
│ 注: 实际性能因驱动版本、温度等因素而异                                │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 11. 常见错误与解决

### 11.1 设备相关错误

```
┌─────────────────────────────────────────────────────────────────────┐
│ 错误: No devices found/left                                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 原因:                                                                │
│ 1. GPU 驱动未安装或版本过旧                                          │
│ 2. OpenCL/CUDA 运行时未安装                                         │
│ 3. 虚拟机中没有 GPU 直通                                            │
│                                                                      │
│ 解决方案:                                                            │
│ # 检查设备                                                           │
│ hashcat -I                                                           │
│ clinfo                                                               │
│                                                                      │
│ # 安装/更新驱动                                                      │
│ # NVIDIA                                                             │
│ sudo apt install nvidia-driver-535                                   │
│ sudo apt install nvidia-cuda-toolkit                                 │
│                                                                      │
│ # AMD                                                                │
│ sudo amdgpu-install --usecase=rocm                                   │
│                                                                      │
│ # 强制使用 CPU（临时方案）                                           │
│ hashcat -m 0 hash.txt wordlist.txt -D 1 --force                     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────────────┐
│ 错误: CL_OUT_OF_RESOURCES / CUDA_ERROR_OUT_OF_MEMORY                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 原因:                                                                │
│ GPU 显存不足                                                         │
│                                                                      │
│ 解决方案:                                                            │
│ # 减少工作负载                                                       │
│ hashcat -m 0 hash.txt wordlist.txt -w 1                             │
│                                                                      │
│ # 减少并行度                                                         │
│ hashcat -m 0 hash.txt wordlist.txt -n 1 -u 1                        │
│                                                                      │
│ # 关闭其他使用 GPU 的程序                                            │
│ # 检查显存使用                                                       │
│ nvidia-smi                                                           │
│                                                                      │
│ # 分批处理哈希                                                       │
│ split -l 10000 hashes.txt hash_batch_                               │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 11.2 哈希相关错误

```
┌─────────────────────────────────────────────────────────────────────┐
│ 错误: Line-length exception / Token length exception                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 原因:                                                                │
│ 1. 哈希格式不正确                                                    │
│ 2. 哈希类型选择错误                                                  │
│ 3. 文件编码问题                                                      │
│                                                                      │
│ 解决方案:                                                            │
│ # 检查哈希格式                                                       │
│ cat -A hash.txt  # 查看隐藏字符                                      │
│                                                                      │
│ # 移除空行和特殊字符                                                 │
│ sed -i '/^$/d' hash.txt                                             │
│ dos2unix hash.txt                                                    │
│                                                                      │
│ # 验证哈希类型                                                       │
│ hashid 'your_hash_here'                                             │
│                                                                      │
│ # 检查示例格式                                                       │
│ hashcat -m 1000 --example-hashes                                    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────────────┐
│ 错误: Separator unmatched                                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 原因:                                                                │
│ 带盐哈希的分隔符不正确                                               │
│                                                                      │
│ 解决方案:                                                            │
│ # 检查哈希格式要求                                                   │
│ hashcat -m 10 --example-hashes                                      │
│ # 输出: hash:salt                                                    │
│                                                                      │
│ # 确保使用正确的分隔符                                               │
│ # 大多数是冒号 (:)                                                   │
│ echo "hash:salt" > hash.txt                                         │
│                                                                      │
│ # 某些类型使用其他分隔符                                             │
│ # 查看 --example-hashes 输出                                        │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 11.3 性能相关错误

```
┌─────────────────────────────────────────────────────────────────────┐
│ 错误: Watchdog: Hardware monitoring interface not found              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 原因:                                                                │
│ 无法监控 GPU 温度（通常在虚拟机中）                                  │
│                                                                      │
│ 解决方案:                                                            │
│ # 禁用硬件监控                                                       │
│ hashcat -m 0 hash.txt wordlist.txt --hwmon-disable                  │
│                                                                      │
│ # 或使用 --force（不推荐）                                           │
│ hashcat -m 0 hash.txt wordlist.txt --force                          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────────────┐
│ 错误: Kernel execution timed out                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 原因:                                                                │
│ GPU 计算超时（Windows TDR 或 Linux 看门狗）                          │
│                                                                      │
│ 解决方案:                                                            │
│ # 降低工作负载                                                       │
│ hashcat -m 0 hash.txt wordlist.txt -w 1                             │
│                                                                      │
│ # Windows: 修改 TDR 超时                                             │
│ # 注册表: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\      │
│ #         GraphicsDrivers                                            │
│ # 添加 DWORD: TdrDelay = 60                                         │
│                                                                      │
│ # Linux: 增加 GPU 超时                                               │
│ # 对于 NVIDIA，编辑 /etc/modprobe.d/nvidia.conf                     │
│ # options nvidia NVreg_RegistryDwords="RMAppGpuTimeout=0"           │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 11.4 常见错误速查表

| 错误 | 原因 | 解决方案 |
|------|------|---------|
| No devices found | 驱动问题 | 安装/更新 GPU 驱动 |
| Out of memory | 显存不足 | 降低 -w 或分批处理 |
| Line-length exception | 哈希格式错误 | 检查格式，使用 --example-hashes |
| Separator unmatched | 分隔符错误 | 检查哈希格式要求 |
| Token length exception | 哈希长度错误 | 验证哈希类型 |
| Kernel timed out | GPU 超时 | 降低工作负载或修改超时设置 |
| Temperature abort | 温度过高 | 改善散热或降低 -w |
| Exhausted | 所有候选已尝试 | 使用更大字典或不同攻击模式 |
| All hashes found | 全部破解成功 | 使用 --show 查看结果 |
| Potfile disabled | 结果未保存 | 移除 --potfile-disable |

### 11.5 调试技巧

```bash
# 查看详细错误信息
hashcat -m 0 hash.txt wordlist.txt --debug-mode=1 --debug-file=debug.log

# 测试哈希格式
hashcat -m 0 --example-hashes

# 验证单个哈希
echo "5f4dcc3b5aa765d61d8327deb882cf99" | hashcat -m 0 --stdout

# 测试规则
echo "password" | hashcat -r rules/best64.rule --stdout | head -20

# 测试掩码
hashcat -m 0 -a 3 --stdout ?l?l?l?l | head -20

# 基准测试特定模式
hashcat -b -m 0

# 查看支持的哈希类型
hashcat --help | grep -E "^\s+[0-9]+" | less
```

---

## 总结

Hashcat 是密码破解领域最强大的工具，掌握它需要理解以下核心内容：

**基础知识**：
- 哈希类型识别和模式选择
- 攻击模式（字典、掩码、组合、混合）
- 基本命令语法和选项

**进阶技能**：
- 规则攻击和自定义规则
- 掩码优化和增量攻击
- 会话管理和恢复

**高级技术**：
- 分布式破解
- Markov 链和 Prince 攻击
- 性能优化和温度控制

**实战能力**：
- Windows/Linux 密码破解
- WiFi 密码破解
- Web 应用和数据库哈希破解

**最佳实践**：
1. 先用小字典快速测试
2. 使用规则扩展字典效果
3. 根据目标特征设计掩码
4. 监控温度避免硬件损坏
5. 保存会话以便恢复

---

> 📚 参考资料
> - [Hashcat 官方文档](https://hashcat.net/wiki/)
> - [Hashcat GitHub](https://github.com/hashcat/hashcat)
> - [Hashcat 示例哈希](https://hashcat.net/wiki/doku.php?id=example_hashes)
> - [规则函数参考](https://hashcat.net/wiki/doku.php?id=rule_based_attack)
> - [Hashcat Utils](https://github.com/hashcat/hashcat-utils)
