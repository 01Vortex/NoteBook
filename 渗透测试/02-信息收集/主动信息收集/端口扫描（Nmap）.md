# Nmap 端口扫描完全指南

> Nmap (Network Mapper) 是最强大的网络扫描和安全审计工具
> 本笔记涵盖从基础到高级的完整使用技巧

---

## 目录

1. [Nmap简介](#1-nmap简介)
2. [安装配置](#2-安装配置)
3. [基础扫描](#3-基础扫描)
4. [高级技术](#4-高级技术)
5. [NSE脚本](#5-nse脚本)
6. [输出报告](#6-输出报告)
7. [性能优化](#7-性能优化)
8. [规避检测](#8-规避检测)
9. [实战案例](#9-实战案例)
10. [常见错误](#10-常见错误)

---

## 1. Nmap简介

### 1.1 核心功能

```
✓ 主机发现
✓ 端口扫描
✓ 服务识别
✓ 操作系统检测
✓ 漏洞扫描
✓ 防火墙规避
```

### 1.2 扫描类型

```
TCP: SYN, Connect, ACK, Window
UDP: UDP扫描
其他: NULL, FIN, Xmas, Idle
```

---

## 2. 安装配置

### 2.1 Linux安装

```bash
# Ubuntu/Debian
sudo apt install nmap -y

# CentOS/RHEL
sudo yum install nmap -y

# 验证
nmap --version
```

### 2.2 Windows安装

```bash
# 下载
https://nmap.org/download.html

# 验证
nmap --version
```

---

## 3. 基础扫描

### 3.1 主机发现

```bash
# Ping扫描
nmap -sn 192.168.1.0/24

# 跳过主机发现
nmap -Pn target.com

# TCP SYN Ping
nmap -PS80,443 192.168.1.0/24
```

### 3.2 端口扫描

```bash
# SYN扫描（需要root）
sudo nmap -sS target.com

# Connect扫描
nmap -sT target.com

# UDP扫描
sudo nmap -sU target.com

# 综合扫描
sudo nmap -sS -sU target.com
```

### 3.3 端口指定

```bash
# 单个端口
nmap -p 80 target.com

# 多个端口
nmap -p 80,443,8080 target.com

# 端口范围
nmap -p 1-1000 target.com

# 所有端口
nmap -p- target.com

# 常用端口
nmap --top-ports 100 target.com

# 快速扫描
nmap -F target.com
```

### 3.4 目标指定

```bash
# 单个主机
nmap target.com

# 多个主机
nmap target1.com target2.com

# IP范围
nmap 192.168.1.1-254

# CIDR
nmap 192.168.1.0/24

# 从文件
nmap -iL targets.txt

# 排除主机
nmap 192.168.1.0/24 --exclude 192.168.1.1
```

---

## 4. 高级技术

### 4.1 服务版本探测

```bash
# 版本探测
nmap -sV target.com

# 强度等级（0-9）
nmap -sV --version-intensity 5 target.com

# 轻量级
nmap -sV --version-light target.com

# 全面探测
nmap -sV --version-all target.com
```

**输出示例：**
```
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.2p1
80/tcp  open  http    Apache 2.4.41
443/tcp open  ssl/http nginx 1.18.0
```

### 4.2 操作系统识别

```bash
# OS检测
sudo nmap -O target.com

# 激进检测
sudo nmap -O --osscan-guess target.com

# 组合扫描
sudo nmap -sS -sV -O target.com
```

### 4.3 综合扫描

```bash
# 全面扫描
sudo nmap -A target.com

# 等同于
sudo nmap -sS -sV -O -sC target.com

# 详细输出
sudo nmap -A -v target.com
```

---

## 5. NSE脚本

### 5.1 脚本分类

```
auth      - 认证
brute     - 暴力破解
default   - 默认脚本
discovery - 服务发现
exploit   - 漏洞利用
vuln      - 漏洞扫描
```

### 5.2 常用脚本

```bash
# 默认脚本
nmap -sC target.com

# 漏洞扫描
nmap --script=vuln target.com

# HTTP枚举
nmap --script=http-enum target.com

# SSL扫描
nmap --script=ssl-cert target.com

# SMB漏洞
nmap --script=smb-vuln-ms17-010 target.com
```

### 5.3 暴力破解

```bash
# SSH暴力破解
nmap --script=ssh-brute target.com

# FTP暴力破解
nmap --script=ftp-brute target.com

# 指定字典
nmap --script=ssh-brute --script-args userdb=users.txt,passdb=pass.txt target.com
```

### 5.4 Web扫描

```bash
# HTTP方法
nmap --script=http-methods target.com

# 目录遍历
nmap --script=http-ls target.com

# SQL注入
nmap --script=http-sql-injection target.com

# XSS检测
nmap --script=http-stored-xss target.com
```

---

## 6. 输出报告

### 6.1 输出格式

```bash
# 标准输出
nmap target.com -oN output.txt

# XML格式
nmap target.com -oX output.xml

# Grepable格式
nmap target.com -oG output.gnmap

# 所有格式
nmap target.com -oA output

# 追加输出
nmap target.com --append-output -oN output.txt
```

### 6.2 详细程度

```bash
# 详细输出
nmap -v target.com

# 更详细
nmap -vv target.com

# 调试模式
nmap -d target.com
nmap -dd target.com
```

---

## 7. 性能优化

### 7.1 时间模板

```bash
# T0 - 偏执（最慢）
nmap -T0 target.com

# T1 - 鬼祟
nmap -T1 target.com

# T2 - 文雅
nmap -T2 target.com

# T3 - 正常（默认）
nmap -T3 target.com

# T4 - 激进
nmap -T4 target.com

# T5 - 疯狂（最快）
nmap -T5 target.com
```

### 7.2 并发控制

```bash
# 最小并发
nmap --min-parallelism 10 target.com

# 最大并发
nmap --max-parallelism 100 target.com

# 主机组大小
nmap --min-hostgroup 50 target.com
nmap --max-hostgroup 100 target.com
```

### 7.3 超时设置

```bash
# 主机超时
nmap --host-timeout 5m target.com

# 扫描延迟
nmap --scan-delay 1s target.com

# 最大重试
nmap --max-retries 3 target.com
```

---

## 8. 规避检测

### 8.1 分片技术

```bash
# IP分片
sudo nmap -f target.com

# 指定MTU
sudo nmap --mtu 24 target.com
```

### 8.2 诱饵扫描

```bash
# 使用诱饵
sudo nmap -D RND:10 target.com

# 指定诱饵IP
sudo nmap -D decoy1,decoy2,ME target.com
```

### 8.3 源地址伪造

```bash
# 伪造源IP
sudo nmap -S 192.168.1.100 target.com

# 伪造源端口
sudo nmap --source-port 53 target.com
```

### 8.4 其他技巧

```bash
# 随机顺序
nmap --randomize-hosts target.com

# MAC地址伪造
sudo nmap --spoof-mac 0 target.com

# 坏校验和
sudo nmap --badsum target.com
```

---

## 9. 实战案例

### 9.1 内网扫描

```bash
# 快速发现主机
nmap -sn 192.168.1.0/24

# 扫描存活主机
nmap -sS -p 80,443,3389,22 192.168.1.0/24

# 详细扫描
nmap -sS -sV -O -p- 192.168.1.100
```

### 9.2 Web服务器扫描

```bash
# 基础扫描
nmap -p 80,443,8080,8443 target.com

# 服务识别
nmap -sV -p 80,443 target.com

# Web漏洞扫描
nmap --script=http-vuln-* target.com

# 完整扫描
nmap -sS -sV -p 80,443 --script=http-* target.com
```

### 9.3 数据库扫描

```bash
# MySQL
nmap -p 3306 --script=mysql-* target.com

# PostgreSQL
nmap -p 5432 --script=pgsql-* target.com

# MongoDB
nmap -p 27017 --script=mongodb-* target.com

# Redis
nmap -p 6379 --script=redis-* target.com
```

### 9.4 域控扫描

```bash
# SMB扫描
nmap -p 445 --script=smb-* target.com

# 永恒之蓝
nmap -p 445 --script=smb-vuln-ms17-010 target.com

# 域信息
nmap -p 389,636 --script=ldap-* target.com
```



---

## 10. 常见错误

### 10.1 权限问题

**错误：**
```
You requested a scan type which requires root privileges
```

**解决：**
```bash
# 使用sudo
sudo nmap -sS target.com

# 或使用不需要root的扫描
nmap -sT target.com
```

### 10.2 防火墙拦截

**错误：**
```
All 1000 scanned ports are filtered
```

**解决：**
```bash
# 使用不同扫描类型
sudo nmap -sA target.com

# 使用诱饵
sudo nmap -D RND:10 target.com

# 分片
sudo nmap -f target.com

# 伪造源端口
sudo nmap --source-port 53 target.com
```

### 10.3 扫描速度慢

**问题：**
```
扫描时间过长
```

**解决：**
```bash
# 使用快速模板
nmap -T4 target.com

# 减少端口
nmap -F target.com

# 跳过主机发现
nmap -Pn target.com

# 增加并发
nmap --min-parallelism 100 target.com
```

### 10.4 DNS解析问题

**错误：**
```
Failed to resolve target
```

**解决：**
```bash
# 禁用DNS解析
nmap -n target.com

# 使用IP地址
nmap 192.168.1.100

# 指定DNS服务器
nmap --dns-servers 8.8.8.8 target.com
```

### 10.5 输出文件权限

**错误：**
```
Failed to open output file
```

**解决：**
```bash
# 检查目录权限
ls -la

# 使用绝对路径
nmap target.com -oN /tmp/output.txt

# 修改权限
chmod 755 output_dir/
```

### 10.6 脚本错误

**错误：**
```
NSE: failed to initialize the script engine
```

**解决：**
```bash
# 更新脚本数据库
sudo nmap --script-updatedb

# 检查脚本路径
ls /usr/share/nmap/scripts/

# 重新安装
sudo apt reinstall nmap
```

### 10.7 UDP扫描不准确

**问题：**
```
UDP扫描结果不可靠
```

**解决：**
```bash
# 增加重试次数
sudo nmap -sU --max-retries 5 target.com

# 降低扫描速度
sudo nmap -sU -T2 target.com

# 结合版本探测
sudo nmap -sU -sV target.com
```

---

## 11. 最佳实践

### 11.1 扫描流程

```bash
# 第一步：主机发现
nmap -sn 192.168.1.0/24 -oG hosts.txt

# 第二步：端口扫描
nmap -sS -p- -iL hosts.txt -oA ports

# 第三步：服务识别
nmap -sV -p $(cat ports.gnmap | grep open | cut -d' ' -f2 | tr '\n' ',') target.com

# 第四步：漏洞扫描
nmap --script=vuln -p 80,443 target.com
```

### 11.2 常用组合

```bash
# 快速扫描
nmap -T4 -F target.com

# 标准扫描
nmap -sS -sV -O -p- target.com

# 全面扫描
nmap -A -T4 -p- target.com

# 隐蔽扫描
nmap -sS -T2 -f -D RND:10 target.com

# 内网扫描
nmap -sn 192.168.1.0/24 && nmap -sS -p 80,443,22,3389 192.168.1.0/24
```

### 11.3 脚本组合

```bash
# Web全面扫描
nmap -p 80,443 --script=http-enum,http-headers,http-methods,http-vuln-* target.com

# 数据库扫描
nmap -p 3306,5432,1433,27017 --script=*-brute,*-info target.com

# SMB扫描
nmap -p 445 --script=smb-enum-*,smb-vuln-* target.com

# SSL扫描
nmap -p 443 --script=ssl-cert,ssl-enum-ciphers,ssl-heartbleed target.com
```

### 11.4 输出处理

```bash
# 提取开放端口
grep "open" output.gnmap | cut -d' ' -f2

# 提取IP地址
grep "Up" output.gnmap | cut -d' ' -f2

# 转换XML为HTML
xsltproc output.xml -o output.html

# 合并多个扫描结果
cat scan1.gnmap scan2.gnmap > merged.gnmap
```

### 11.5 自动化脚本

```bash
#!/bin/bash
# nmap-auto.sh

TARGET=$1
OUTPUT_DIR="nmap_results"

mkdir -p $OUTPUT_DIR

echo "[*] Starting scan on $TARGET"

# 主机发现
echo "[*] Host discovery..."
nmap -sn $TARGET -oA $OUTPUT_DIR/hosts

# 端口扫描
echo "[*] Port scanning..."
nmap -sS -p- $TARGET -oA $OUTPUT_DIR/ports

# 服务识别
echo "[*] Service detection..."
nmap -sV -p $(grep open $OUTPUT_DIR/ports.gnmap | cut -d' ' -f2 | tr '\n' ',') $TARGET -oA $OUTPUT_DIR/services

# 漏洞扫描
echo "[*] Vulnerability scanning..."
nmap --script=vuln $TARGET -oA $OUTPUT_DIR/vulns

echo "[+] Scan complete! Results in $OUTPUT_DIR/"
```

### 11.6 安全建议

```
1. 获得授权
   - 书面授权
   - 明确范围
   - 遵守法律

2. 控制影响
   - 避免DoS
   - 控制速度
   - 选择时间

3. 保护数据
   - 加密传输
   - 安全存储
   - 及时删除

4. 记录过程
   - 保存日志
   - 记录时间
   - 截图证据
```

---

## 实战技巧总结

### 快速参考

```bash
# 快速扫描常用端口
nmap -F target.com

# 全面扫描
nmap -A -p- target.com

# 隐蔽扫描
nmap -sS -T2 -f target.com

# 漏洞扫描
nmap --script=vuln target.com

# 暴力破解
nmap --script=*-brute target.com
```

### 性能对比

```
扫描方式          速度    隐蔽性   准确性
-sT (Connect)     慢      低       高
-sS (SYN)         快      中       高
-sU (UDP)         很慢    中       中
-sN/-sF/-sX       中      高       中
-sI (Idle)        慢      很高     中
```

### 端口状态

```
open          - 端口开放
closed        - 端口关闭
filtered      - 被防火墙过滤
unfiltered    - 可达但状态未知
open|filtered - 开放或被过滤
closed|filtered - 关闭或被过滤
```

---

## 参考资源

**官方文档：**
- Nmap官网: https://nmap.org/
- 参考指南: https://nmap.org/book/
- NSE文档: https://nmap.org/nsedoc/

**学习资源：**
- Nmap Network Scanning (书籍)
- HackTricks Nmap: https://book.hacktricks.xyz/
- Nmap Cheat Sheet

**工具推荐：**
- Zenmap: Nmap图形界面
- Masscan: 超快速扫描
- RustScan: Rust编写的快速扫描器

---

> 💡 **提示**: Nmap是强大的工具，使用前务必获得授权。合理控制扫描速度，避免影响目标系统。
