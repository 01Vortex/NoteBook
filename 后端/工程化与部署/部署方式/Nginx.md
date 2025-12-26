

> Nginx 是一款高性能的 HTTP 和反向代理服务器，也是一个 IMAP/POP3/SMTP 代理服务器
> 本笔记基于 Nginx 1.24.x 版本

---

## 目录

1. [基础概念](#1-基础概念)
2. [安装与启动](#2-安装与启动)
3. [配置文件详解](#3-配置文件详解)
4. [静态资源服务](#4-静态资源服务)
5. [反向代理](#5-反向代理)
6. [负载均衡](#6-负载均衡)
7. [HTTPS 配置](#7-https-配置)
8. [Gzip 压缩](#8-gzip-压缩)
9. [缓存配置](#9-缓存配置)
10. [日志配置](#10-日志配置)
11. [安全配置](#11-安全配置)
12. [性能优化](#12-性能优化)
13. [高可用配置](#13-高可用配置)
14. [常见错误与解决方案](#14-常见错误与解决方案)
15. [最佳实践](#15-最佳实践)

---

## 1. 基础概念

### 1.1 什么是 Nginx？

Nginx（发音为 "engine-x"）是由俄罗斯程序员 Igor Sysoev 开发的一款轻量级、高性能的 Web 服务器/反向代理服务器。它以其高并发处理能力、低内存消耗和稳定性著称。

**Nginx 的主要功能：**
- **Web 服务器**：处理静态资源（HTML、CSS、JS、图片等）
- **反向代理**：将请求转发到后端服务器
- **负载均衡**：将请求分发到多个后端服务器
- **HTTP 缓存**：缓存后端响应，减少后端压力
- **SSL/TLS 终端**：处理 HTTPS 加密解密

### 1.2 Nginx vs Apache

| 特性 | Nginx | Apache |
|------|-------|--------|
| 架构 | 事件驱动、异步非阻塞 | 进程/线程驱动 |
| 并发能力 | 高（数万并发） | 中等 |
| 内存消耗 | 低 | 较高 |
| 静态资源 | 非常快 | 快 |
| 动态内容 | 需要配合后端 | 内置模块支持 |
| 配置复杂度 | 简单 | 较复杂 |
| 模块加载 | 编译时加载 | 运行时加载 |

### 1.3 Nginx 架构

```
                    ┌─────────────────┐
                    │   Master 进程    │
                    │  (读取配置、管理) │
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
        ▼                    ▼                    ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│  Worker 进程   │  │  Worker 进程   │  │  Worker 进程   │
│  (处理请求)    │  │  (处理请求)    │  │  (处理请求)    │
└───────────────┘  └───────────────┘  └───────────────┘
```

**进程模型说明：**
- **Master 进程**：读取配置文件、管理 Worker 进程、接收信号
- **Worker 进程**：实际处理请求，数量通常设置为 CPU 核心数
- **事件驱动**：使用 epoll（Linux）或 kqueue（BSD）处理并发连接

### 1.4 核心概念

| 概念 | 说明 |
|------|------|
| 连接（Connection） | 客户端与 Nginx 之间的 TCP 连接 |
| 请求（Request） | 一个连接上可以有多个请求（HTTP/1.1 Keep-Alive） |
| 上游（Upstream） | 后端服务器，Nginx 将请求转发到上游 |
| 下游（Downstream） | 客户端，向 Nginx 发送请求 |
| 虚拟主机（Server） | 一个 Nginx 可以配置多个虚拟主机 |
| 位置（Location） | URL 匹配规则，决定如何处理请求 |

---

## 2. 安装与启动

### 2.1 Linux 安装

#### CentOS/RHEL

```bash
# 安装 EPEL 仓库
sudo yum install epel-release

# 安装 Nginx
sudo yum install nginx

# 或使用官方仓库安装最新版
cat > /etc/yum.repos.d/nginx.repo << 'EOF'
[nginx-stable]
name=nginx stable repo
baseurl=http://nginx.org/packages/centos/$releasever/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
EOF

sudo yum install nginx
```

#### Ubuntu/Debian

```bash
# 更新包列表
sudo apt update

# 安装 Nginx
sudo apt install nginx

# 或使用官方仓库安装最新版
sudo apt install curl gnupg2 ca-certificates lsb-release
echo "deb http://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list
curl -fsSL https://nginx.org/keys/nginx_signing.key | sudo apt-key add -
sudo apt update
sudo apt install nginx
```

### 2.2 Docker 安装

```bash
# 拉取镜像
docker pull nginx:1.24

# 运行容器
docker run -d \
  --name nginx \
  -p 80:80 \
  -p 443:443 \
  -v /path/to/nginx.conf:/etc/nginx/nginx.conf:ro \
  -v /path/to/html:/usr/share/nginx/html:ro \
  -v /path/to/logs:/var/log/nginx \
  nginx:1.24
```

### 2.3 源码编译安装

```bash
# 安装依赖
sudo yum install gcc pcre-devel zlib-devel openssl-devel make

# 下载源码
wget http://nginx.org/download/nginx-1.24.0.tar.gz
tar -zxvf nginx-1.24.0.tar.gz
cd nginx-1.24.0

# 配置编译选项
./configure \
  --prefix=/usr/local/nginx \
  --with-http_ssl_module \
  --with-http_v2_module \
  --with-http_realip_module \
  --with-http_gzip_static_module \
  --with-http_stub_status_module \
  --with-stream \
  --with-stream_ssl_module

# 编译安装
make && sudo make install

# 创建软链接
sudo ln -s /usr/local/nginx/sbin/nginx /usr/bin/nginx
```


### 2.4 常用命令

```bash
# 启动 Nginx
nginx
# 或
systemctl start nginx

# 停止 Nginx
nginx -s stop      # 快速停止
nginx -s quit      # 优雅停止（等待请求处理完成）
# 或
systemctl stop nginx

# 重新加载配置（不停止服务）
nginx -s reload
# 或
systemctl reload nginx

# 重启 Nginx
systemctl restart nginx

# 测试配置文件语法
nginx -t
nginx -T  # 测试并打印配置

# 查看版本
nginx -v   # 简单版本
nginx -V   # 详细版本和编译参数

# 查看 Nginx 进程
ps aux | grep nginx

# 查看 Nginx 状态
systemctl status nginx

# 设置开机自启
systemctl enable nginx
```

### 2.5 目录结构

```
/etc/nginx/                    # 配置文件目录
├── nginx.conf                 # 主配置文件
├── conf.d/                    # 额外配置目录
│   └── default.conf           # 默认站点配置
├── sites-available/           # 可用站点配置（Ubuntu）
├── sites-enabled/             # 启用站点配置（Ubuntu）
├── mime.types                 # MIME 类型映射
├── fastcgi_params             # FastCGI 参数
├── proxy_params               # 代理参数
└── ssl/                       # SSL 证书目录

/var/log/nginx/                # 日志目录
├── access.log                 # 访问日志
└── error.log                  # 错误日志

/usr/share/nginx/html/         # 默认网站根目录
├── index.html
└── 50x.html

/var/cache/nginx/              # 缓存目录
/run/nginx.pid                 # PID 文件
```

---

## 3. 配置文件详解

### 3.1 配置文件结构

```nginx
# 全局块：配置影响 Nginx 全局的指令
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

# events 块：配置影响 Nginx 服务器与用户的网络连接
events {
    worker_connections 1024;
    use epoll;
}

# http 块：配置代理、缓存、日志等绝大多数功能
http {
    # http 全局块
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # server 块：配置虚拟主机
    server {
        listen 80;
        server_name localhost;
        
        # location 块：配置请求路由
        location / {
            root /usr/share/nginx/html;
            index index.html;
        }
    }
}

# stream 块：TCP/UDP 代理（可选）
stream {
    # ...
}
```

### 3.2 全局块配置

```nginx
# 运行 Nginx 的用户和用户组
user nginx nginx;

# Worker 进程数，通常设置为 CPU 核心数
# auto 表示自动检测
worker_processes auto;

# 绑定 Worker 进程到指定 CPU
worker_cpu_affinity auto;

# 错误日志路径和级别
# 级别：debug, info, notice, warn, error, crit, alert, emerg
error_log /var/log/nginx/error.log warn;

# PID 文件路径
pid /run/nginx.pid;

# Worker 进程可以打开的最大文件描述符数
worker_rlimit_nofile 65535;
```

### 3.3 events 块配置

```nginx
events {
    # 每个 Worker 进程的最大连接数
    worker_connections 10240;
    
    # 事件驱动模型
    # Linux: epoll, BSD: kqueue
    use epoll;
    
    # 是否允许一个 Worker 进程同时接受多个连接
    multi_accept on;
    
    # 是否开启 accept 互斥锁
    accept_mutex off;
}
```

### 3.4 http 块配置

```nginx
http {
    # 包含 MIME 类型映射
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # 字符集
    charset utf-8;
    
    # 日志格式
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    # 访问日志
    access_log /var/log/nginx/access.log main;
    
    # 高效文件传输
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    
    # 连接超时
    keepalive_timeout 65;
    
    # 请求体大小限制
    client_max_body_size 100m;
    
    # 隐藏 Nginx 版本号
    server_tokens off;
    
    # 包含其他配置文件
    include /etc/nginx/conf.d/*.conf;
}
```

### 3.5 server 块配置

```nginx
server {
    # 监听端口
    listen 80;
    listen [::]:80;  # IPv6
    
    # 服务器名称（域名）
    server_name example.com www.example.com;
    
    # 网站根目录
    root /var/www/html;
    
    # 默认首页
    index index.html index.htm;
    
    # 字符集
    charset utf-8;
    
    # 访问日志
    access_log /var/log/nginx/example.access.log main;
    error_log /var/log/nginx/example.error.log;
    
    # location 配置
    location / {
        try_files $uri $uri/ =404;
    }
}
```

### 3.6 location 块配置

location 用于匹配 URL，是 Nginx 配置中最重要的部分。

**匹配规则优先级（从高到低）：**

| 符号 | 说明 | 示例 |
|------|------|------|
| `=` | 精确匹配 | `location = /api` |
| `^~` | 前缀匹配，匹配后不再检查正则 | `location ^~ /static/` |
| `~` | 正则匹配（区分大小写） | `location ~ \.php$` |
| `~*` | 正则匹配（不区分大小写） | `location ~* \.(jpg|png)$` |
| `/` | 通用匹配 | `location /` |

```nginx
# 精确匹配
location = / {
    # 只匹配 /
}

# 前缀匹配（优先级高于正则）
location ^~ /static/ {
    # 匹配以 /static/ 开头的 URL
    alias /var/www/static/;
}

# 正则匹配（区分大小写）
location ~ \.php$ {
    # 匹配以 .php 结尾的 URL
    fastcgi_pass 127.0.0.1:9000;
}

# 正则匹配（不区分大小写）
location ~* \.(jpg|jpeg|png|gif|ico)$ {
    # 匹配图片文件
    expires 30d;
}

# 通用匹配
location / {
    # 匹配所有请求
    try_files $uri $uri/ /index.html;
}

# 命名 location（用于内部跳转）
location @fallback {
    proxy_pass http://backend;
}
```


---

## 4. 静态资源服务

### 4.1 基本配置

```nginx
server {
    listen 80;
    server_name static.example.com;
    
    # 网站根目录
    root /var/www/static;
    
    # 默认首页
    index index.html index.htm;
    
    # 静态资源处理
    location / {
        # 尝试查找文件，找不到返回 404
        try_files $uri $uri/ =404;
    }
    
    # 图片资源
    location ~* \.(jpg|jpeg|png|gif|ico|webp|svg)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    
    # CSS/JS 资源
    location ~* \.(css|js)$ {
        expires 7d;
        add_header Cache-Control "public";
    }
    
    # 字体资源
    location ~* \.(woff|woff2|ttf|eot)$ {
        expires 365d;
        add_header Cache-Control "public, immutable";
        add_header Access-Control-Allow-Origin "*";
    }
}
```

### 4.2 root 和 alias 的区别

```nginx
# root：将 location 路径拼接到 root 后面
location /images/ {
    root /var/www;
    # 请求 /images/logo.png -> /var/www/images/logo.png
}

# alias：用 alias 路径替换 location 路径
location /images/ {
    alias /var/www/static/;
    # 请求 /images/logo.png -> /var/www/static/logo.png
}

# 注意：alias 后面的路径要以 / 结尾
```

### 4.3 目录浏览

```nginx
location /download/ {
    alias /var/www/files/;
    
    # 开启目录浏览
    autoindex on;
    
    # 显示文件大小（on: 精确字节, off: 人性化显示）
    autoindex_exact_size off;
    
    # 显示时间格式（on: 服务器时间, off: GMT 时间）
    autoindex_localtime on;
    
    # 输出格式（html, xml, json, jsonp）
    autoindex_format html;
}
```

### 4.4 防盗链

```nginx
location ~* \.(jpg|jpeg|png|gif|webp)$ {
    # 允许的来源
    valid_referers none blocked server_names
                   *.example.com example.com
                   ~\.google\. ~\.baidu\.;
    
    # 非法来源返回 403 或显示防盗链图片
    if ($invalid_referer) {
        return 403;
        # 或返回防盗链图片
        # rewrite ^/ /images/hotlink-denied.png break;
    }
    
    expires 30d;
}
```

### 4.5 Vue/React 单页应用部署

```nginx
server {
    listen 80;
    server_name app.example.com;
    root /var/www/app/dist;
    index index.html;
    
    # 处理 HTML5 History 模式路由
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    # 静态资源缓存
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # 禁止缓存 HTML
    location ~* \.html$ {
        expires -1;
        add_header Cache-Control "no-store, no-cache, must-revalidate";
    }
    
    # API 代理
    location /api/ {
        proxy_pass http://localhost:8080/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## 5. 反向代理

### 5.1 基本反向代理

```nginx
server {
    listen 80;
    server_name api.example.com;
    
    location / {
        # 代理到后端服务
        proxy_pass http://localhost:8080;
        
        # 设置请求头
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # 超时设置
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

### 5.2 proxy_pass 路径处理

```nginx
# 情况1：proxy_pass 不带路径
location /api/ {
    proxy_pass http://localhost:8080;
    # 请求 /api/users -> http://localhost:8080/api/users
}

# 情况2：proxy_pass 带路径（以 / 结尾）
location /api/ {
    proxy_pass http://localhost:8080/;
    # 请求 /api/users -> http://localhost:8080/users
    # location 路径被替换
}

# 情况3：proxy_pass 带路径（不以 / 结尾）
location /api/ {
    proxy_pass http://localhost:8080/v1;
    # 请求 /api/users -> http://localhost:8080/v1users
    # 注意：路径直接拼接
}

# 情况4：proxy_pass 带路径（以 / 结尾）
location /api/ {
    proxy_pass http://localhost:8080/v1/;
    # 请求 /api/users -> http://localhost:8080/v1/users
}
```

### 5.3 WebSocket 代理

```nginx
# WebSocket 需要特殊的头部处理
map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
}

server {
    listen 80;
    server_name ws.example.com;
    
    location /ws/ {
        proxy_pass http://localhost:8080;
        
        # WebSocket 必需的头部
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        
        # 其他头部
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        
        # 超时设置（WebSocket 需要较长的超时）
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

### 5.4 代理缓冲

```nginx
location / {
    proxy_pass http://backend;
    
    # 开启代理缓冲
    proxy_buffering on;
    
    # 缓冲区大小
    proxy_buffer_size 4k;
    proxy_buffers 8 4k;
    proxy_busy_buffers_size 8k;
    
    # 临时文件
    proxy_temp_file_write_size 64k;
    proxy_max_temp_file_size 1024m;
}
```

### 5.5 错误处理

```nginx
server {
    listen 80;
    server_name api.example.com;
    
    location / {
        proxy_pass http://backend;
        
        # 后端错误时的处理
        proxy_intercept_errors on;
        
        # 自定义错误页面
        error_page 500 502 503 504 /50x.html;
    }
    
    location = /50x.html {
        root /usr/share/nginx/html;
        internal;
    }
}
```

---

## 6. 负载均衡

### 6.1 基本配置

```nginx
# 定义上游服务器组
upstream backend {
    server 192.168.1.101:8080;
    server 192.168.1.102:8080;
    server 192.168.1.103:8080;
}

server {
    listen 80;
    server_name api.example.com;
    
    location / {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 6.2 负载均衡策略

```nginx
# 1. 轮询（默认）
# 按顺序依次分配请求
upstream backend_round_robin {
    server 192.168.1.101:8080;
    server 192.168.1.102:8080;
    server 192.168.1.103:8080;
}

# 2. 加权轮询
# 权重越高，分配的请求越多
upstream backend_weighted {
    server 192.168.1.101:8080 weight=5;
    server 192.168.1.102:8080 weight=3;
    server 192.168.1.103:8080 weight=2;
}

# 3. IP Hash
# 同一 IP 的请求总是分配到同一服务器（会话保持）
upstream backend_ip_hash {
    ip_hash;
    server 192.168.1.101:8080;
    server 192.168.1.102:8080;
    server 192.168.1.103:8080;
}

# 4. 最少连接
# 将请求分配给连接数最少的服务器
upstream backend_least_conn {
    least_conn;
    server 192.168.1.101:8080;
    server 192.168.1.102:8080;
    server 192.168.1.103:8080;
}

# 5. URL Hash（需要第三方模块）
# 同一 URL 的请求总是分配到同一服务器
upstream backend_url_hash {
    hash $request_uri;
    server 192.168.1.101:8080;
    server 192.168.1.102:8080;
}

# 6. Fair（需要第三方模块）
# 根据响应时间分配，响应快的服务器优先
upstream backend_fair {
    fair;
    server 192.168.1.101:8080;
    server 192.168.1.102:8080;
}
```

### 6.3 服务器状态参数

```nginx
upstream backend {
    # weight: 权重，默认为 1
    # max_fails: 最大失败次数，默认为 1
    # fail_timeout: 失败超时时间，默认为 10s
    # backup: 备份服务器，只有主服务器都不可用时才启用
    # down: 标记服务器为不可用
    
    server 192.168.1.101:8080 weight=5 max_fails=3 fail_timeout=30s;
    server 192.168.1.102:8080 weight=3;
    server 192.168.1.103:8080 backup;
    server 192.168.1.104:8080 down;
}
```

### 6.4 健康检查

```nginx
# 被动健康检查（默认）
upstream backend {
    server 192.168.1.101:8080 max_fails=3 fail_timeout=30s;
    server 192.168.1.102:8080 max_fails=3 fail_timeout=30s;
}

# 主动健康检查（需要 nginx_upstream_check_module 或 Nginx Plus）
upstream backend {
    server 192.168.1.101:8080;
    server 192.168.1.102:8080;
    
    # 每 3 秒检查一次，连续 2 次成功认为健康，连续 5 次失败认为不健康
    check interval=3000 rise=2 fall=5 timeout=1000 type=http;
    check_http_send "HEAD /health HTTP/1.0\r\n\r\n";
    check_http_expect_alive http_2xx http_3xx;
}
```

### 6.5 会话保持

```nginx
# 方式1：IP Hash
upstream backend {
    ip_hash;
    server 192.168.1.101:8080;
    server 192.168.1.102:8080;
}

# 方式2：Cookie（需要 sticky 模块或 Nginx Plus）
upstream backend {
    sticky cookie srv_id expires=1h domain=.example.com path=/;
    server 192.168.1.101:8080;
    server 192.168.1.102:8080;
}

# 方式3：使用 map 根据 Cookie 路由
map $cookie_backend $backend_server {
    default backend;
    server1 backend1;
    server2 backend2;
}

upstream backend1 {
    server 192.168.1.101:8080;
}

upstream backend2 {
    server 192.168.1.102:8080;
}
```


---

## 7. HTTPS 配置

### 7.1 获取 SSL 证书

```bash
# 方式1：使用 Let's Encrypt 免费证书
# 安装 certbot
sudo apt install certbot python3-certbot-nginx  # Ubuntu
sudo yum install certbot python3-certbot-nginx  # CentOS

# 获取证书
sudo certbot --nginx -d example.com -d www.example.com

# 自动续期
sudo certbot renew --dry-run

# 方式2：使用 acme.sh
curl https://get.acme.sh | sh
acme.sh --issue -d example.com -d www.example.com --nginx
acme.sh --install-cert -d example.com \
    --key-file /etc/nginx/ssl/example.com.key \
    --fullchain-file /etc/nginx/ssl/example.com.crt \
    --reloadcmd "systemctl reload nginx"
```

### 7.2 基本 HTTPS 配置

```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name example.com www.example.com;
    
    # SSL 证书
    ssl_certificate /etc/nginx/ssl/example.com.crt;
    ssl_certificate_key /etc/nginx/ssl/example.com.key;
    
    # SSL 配置
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    
    # 协议版本
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # 加密套件
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # HSTS（强制 HTTPS）
    add_header Strict-Transport-Security "max-age=63072000" always;
    
    # 网站配置
    root /var/www/html;
    index index.html;
    
    location / {
        try_files $uri $uri/ =404;
    }
}

# HTTP 重定向到 HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name example.com www.example.com;
    
    # 301 永久重定向
    return 301 https://$server_name$request_uri;
}
```

### 7.3 SSL 优化配置

```nginx
# 在 http 块中配置（全局生效）
http {
    # SSL 会话缓存
    ssl_session_cache shared:SSL:50m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    
    # 协议版本（禁用不安全的 TLS 1.0 和 1.1）
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # 加密套件（推荐配置）
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
    
    # DH 参数（提高安全性）
    # 生成：openssl dhparam -out /etc/nginx/ssl/dhparam.pem 2048
    ssl_dhparam /etc/nginx/ssl/dhparam.pem;
}
```

### 7.4 双向 SSL 认证（mTLS）

```nginx
server {
    listen 443 ssl;
    server_name api.example.com;
    
    # 服务器证书
    ssl_certificate /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;
    
    # 客户端证书验证
    ssl_client_certificate /etc/nginx/ssl/ca.crt;
    ssl_verify_client on;
    ssl_verify_depth 2;
    
    location / {
        # 将客户端证书信息传递给后端
        proxy_set_header X-SSL-Client-Cert $ssl_client_cert;
        proxy_set_header X-SSL-Client-S-DN $ssl_client_s_dn;
        proxy_pass http://backend;
    }
}
```

---

## 8. Gzip 压缩

### 8.1 基本配置

```nginx
http {
    # 开启 Gzip
    gzip on;
    
    # 最小压缩文件大小
    gzip_min_length 1k;
    
    # 压缩缓冲区
    gzip_buffers 4 16k;
    
    # 压缩级别（1-9，越高压缩率越高，CPU 消耗越大）
    gzip_comp_level 5;
    
    # 压缩的 MIME 类型
    gzip_types text/plain text/css text/javascript application/javascript application/json application/xml application/xml+rss image/svg+xml;
    
    # 是否在响应头中添加 Vary: Accept-Encoding
    gzip_vary on;
    
    # 禁用 IE6 的 Gzip
    gzip_disable "MSIE [1-6]\.";
    
    # 代理请求的压缩
    gzip_proxied any;
    
    # HTTP 版本
    gzip_http_version 1.1;
}
```

### 8.2 预压缩（gzip_static）

```nginx
# 需要编译时添加 --with-http_gzip_static_module

location /static/ {
    # 优先使用预压缩的 .gz 文件
    gzip_static on;
    
    # 如果没有 .gz 文件，则动态压缩
    gzip on;
    gzip_types text/plain text/css application/javascript;
}
```

预压缩文件生成：

```bash
# 压缩静态文件
find /var/www/static -type f \( -name "*.js" -o -name "*.css" -o -name "*.html" \) -exec gzip -k {} \;
```

### 8.3 Brotli 压缩（更高压缩率）

```nginx
# 需要安装 ngx_brotli 模块

http {
    # Brotli 压缩
    brotli on;
    brotli_comp_level 6;
    brotli_types text/plain text/css text/javascript application/javascript application/json application/xml image/svg+xml;
    
    # 预压缩
    brotli_static on;
}
```

---

## 9. 缓存配置

### 9.1 浏览器缓存

```nginx
# 静态资源缓存
location ~* \.(jpg|jpeg|png|gif|ico|css|js|woff|woff2)$ {
    # 缓存 30 天
    expires 30d;
    
    # 或使用 Cache-Control
    add_header Cache-Control "public, max-age=2592000, immutable";
    
    # 关闭访问日志
    access_log off;
}

# HTML 不缓存
location ~* \.html$ {
    expires -1;
    add_header Cache-Control "no-store, no-cache, must-revalidate, proxy-revalidate";
}

# API 不缓存
location /api/ {
    add_header Cache-Control "no-store";
    proxy_pass http://backend;
}
```

### 9.2 代理缓存

```nginx
http {
    # 定义缓存路径
    proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=my_cache:100m max_size=10g inactive=60m use_temp_path=off;
    
    server {
        listen 80;
        server_name api.example.com;
        
        location / {
            proxy_pass http://backend;
            
            # 启用缓存
            proxy_cache my_cache;
            
            # 缓存键
            proxy_cache_key $scheme$proxy_host$request_uri;
            
            # 缓存有效期
            proxy_cache_valid 200 302 10m;
            proxy_cache_valid 404 1m;
            proxy_cache_valid any 5m;
            
            # 缓存状态头
            add_header X-Cache-Status $upstream_cache_status;
            
            # 后端不可用时使用过期缓存
            proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
            
            # 缓存锁（防止缓存击穿）
            proxy_cache_lock on;
            proxy_cache_lock_timeout 5s;
            
            # 最小使用次数后才缓存
            proxy_cache_min_uses 3;
            
            # 绕过缓存条件
            proxy_cache_bypass $cookie_nocache $arg_nocache;
            proxy_no_cache $cookie_nocache $arg_nocache;
        }
    }
}
```

### 9.3 FastCGI 缓存

```nginx
http {
    # 定义 FastCGI 缓存
    fastcgi_cache_path /var/cache/nginx/fastcgi levels=1:2 keys_zone=php_cache:100m max_size=10g inactive=60m;
    
    server {
        location ~ \.php$ {
            fastcgi_pass unix:/var/run/php/php-fpm.sock;
            fastcgi_index index.php;
            include fastcgi_params;
            
            # 启用缓存
            fastcgi_cache php_cache;
            fastcgi_cache_key $scheme$request_method$host$request_uri;
            fastcgi_cache_valid 200 10m;
            
            # 缓存状态头
            add_header X-FastCGI-Cache $upstream_cache_status;
        }
    }
}
```

### 9.4 缓存清理

```nginx
# 需要 ngx_cache_purge 模块

location ~ /purge(/.*) {
    # 限制访问
    allow 127.0.0.1;
    deny all;
    
    # 清理缓存
    proxy_cache_purge my_cache $scheme$proxy_host$1;
}
```

```bash
# 清理缓存
curl -X PURGE http://example.com/purge/api/users

# 手动清理缓存目录
rm -rf /var/cache/nginx/*
```


---

## 10. 日志配置

### 10.1 日志格式

```nginx
http {
    # 默认日志格式
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    # 详细日志格式
    log_format detailed '$remote_addr - $remote_user [$time_local] "$request" '
                        '$status $body_bytes_sent "$http_referer" '
                        '"$http_user_agent" "$http_x_forwarded_for" '
                        'rt=$request_time uct="$upstream_connect_time" '
                        'uht="$upstream_header_time" urt="$upstream_response_time"';
    
    # JSON 格式（便于日志分析）
    log_format json escape=json '{'
        '"time_local":"$time_local",'
        '"remote_addr":"$remote_addr",'
        '"remote_user":"$remote_user",'
        '"request":"$request",'
        '"status":"$status",'
        '"body_bytes_sent":"$body_bytes_sent",'
        '"request_time":"$request_time",'
        '"http_referer":"$http_referer",'
        '"http_user_agent":"$http_user_agent",'
        '"http_x_forwarded_for":"$http_x_forwarded_for",'
        '"upstream_addr":"$upstream_addr",'
        '"upstream_response_time":"$upstream_response_time"'
    '}';
    
    # 访问日志
    access_log /var/log/nginx/access.log main;
    
    # 错误日志
    error_log /var/log/nginx/error.log warn;
}
```

### 10.2 常用日志变量

| 变量 | 说明 |
|------|------|
| `$remote_addr` | 客户端 IP |
| `$remote_user` | 认证用户名 |
| `$time_local` | 本地时间 |
| `$request` | 请求行 |
| `$status` | 响应状态码 |
| `$body_bytes_sent` | 发送的字节数 |
| `$http_referer` | 来源页面 |
| `$http_user_agent` | 用户代理 |
| `$http_x_forwarded_for` | 代理链 IP |
| `$request_time` | 请求处理时间 |
| `$upstream_response_time` | 上游响应时间 |
| `$upstream_addr` | 上游服务器地址 |

### 10.3 日志切割

```bash
# 方式1：使用 logrotate
cat > /etc/logrotate.d/nginx << 'EOF'
/var/log/nginx/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 nginx adm
    sharedscripts
    postrotate
        [ -f /var/run/nginx.pid ] && kill -USR1 `cat /var/run/nginx.pid`
    endscript
}
EOF

# 方式2：手动切割脚本
#!/bin/bash
LOG_PATH=/var/log/nginx
DATE=$(date -d "yesterday" +%Y%m%d)

# 重命名日志文件
mv ${LOG_PATH}/access.log ${LOG_PATH}/access_${DATE}.log
mv ${LOG_PATH}/error.log ${LOG_PATH}/error_${DATE}.log

# 通知 Nginx 重新打开日志文件
kill -USR1 $(cat /var/run/nginx.pid)

# 压缩旧日志
gzip ${LOG_PATH}/access_${DATE}.log
gzip ${LOG_PATH}/error_${DATE}.log

# 删除 30 天前的日志
find ${LOG_PATH} -name "*.gz" -mtime +30 -delete
```

### 10.4 条件日志

```nginx
# 不记录静态资源访问日志
location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
    access_log off;
}

# 不记录健康检查日志
location /health {
    access_log off;
    return 200 "OK";
}

# 使用 map 条件记录
map $status $loggable {
    ~^[23] 0;  # 2xx 和 3xx 不记录
    default 1;
}

access_log /var/log/nginx/access.log main if=$loggable;

# 只记录慢请求
map $request_time $slow_request {
    ~^[0-1]\. 0;  # 小于 2 秒不记录
    default 1;
}

access_log /var/log/nginx/slow.log detailed if=$slow_request;
```

---

## 11. 安全配置

### 11.1 基本安全配置

```nginx
http {
    # 隐藏 Nginx 版本号
    server_tokens off;
    
    # 安全响应头
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # CSP（内容安全策略）
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';" always;
    
    # 禁止不安全的 HTTP 方法
    if ($request_method !~ ^(GET|HEAD|POST|PUT|DELETE|OPTIONS)$) {
        return 405;
    }
}
```

### 11.2 访问控制

```nginx
# IP 白名单/黑名单
location /admin/ {
    # 允许的 IP
    allow 192.168.1.0/24;
    allow 10.0.0.0/8;
    # 拒绝其他所有
    deny all;
}

# 基于 geo 模块的访问控制
geo $blocked_ip {
    default 0;
    10.0.0.0/8 1;
    192.168.0.0/16 1;
}

server {
    if ($blocked_ip) {
        return 403;
    }
}

# HTTP 基本认证
location /admin/ {
    auth_basic "Admin Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
}
```

```bash
# 生成密码文件
htpasswd -c /etc/nginx/.htpasswd admin
# 或使用 openssl
echo "admin:$(openssl passwd -apr1 'password')" >> /etc/nginx/.htpasswd
```

### 11.3 限流配置

```nginx
http {
    # 定义限流区域
    # 按 IP 限制请求速率
    limit_req_zone $binary_remote_addr zone=req_limit:10m rate=10r/s;
    
    # 按 IP 限制连接数
    limit_conn_zone $binary_remote_addr zone=conn_limit:10m;
    
    server {
        # 应用请求限流
        location /api/ {
            # burst: 允许突发请求数
            # nodelay: 不延迟处理突发请求
            limit_req zone=req_limit burst=20 nodelay;
            
            # 限流状态码
            limit_req_status 429;
            
            proxy_pass http://backend;
        }
        
        # 应用连接限流
        location /download/ {
            limit_conn conn_limit 5;  # 每 IP 最多 5 个连接
            limit_rate 100k;          # 每连接限速 100KB/s
        }
    }
}
```

### 11.4 防止 DDoS 攻击

```nginx
http {
    # 限制请求体大小
    client_max_body_size 10m;
    
    # 限制请求头大小
    client_header_buffer_size 1k;
    large_client_header_buffers 4 8k;
    
    # 超时设置
    client_body_timeout 10s;
    client_header_timeout 10s;
    send_timeout 10s;
    
    # 限制连接数
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    limit_conn addr 100;
    
    # 限制请求速率
    limit_req_zone $binary_remote_addr zone=one:10m rate=1r/s;
    limit_req zone=one burst=5;
}
```

### 11.5 防止常见攻击

```nginx
server {
    # 防止点击劫持
    add_header X-Frame-Options "SAMEORIGIN";
    
    # 防止 MIME 类型嗅探
    add_header X-Content-Type-Options "nosniff";
    
    # 防止 XSS 攻击
    add_header X-XSS-Protection "1; mode=block";
    
    # 禁止目录遍历
    autoindex off;
    
    # 禁止访问隐藏文件
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    # 禁止访问敏感文件
    location ~* \.(git|svn|env|htaccess|htpasswd|ini|log|sh|sql|conf)$ {
        deny all;
    }
    
    # 防止 SQL 注入（简单过滤）
    if ($query_string ~* "union.*select.*\(") {
        return 403;
    }
    
    if ($query_string ~* "concat.*\(") {
        return 403;
    }
}
```

---

## 12. 性能优化

### 12.1 Worker 进程优化

```nginx
# Worker 进程数（通常设置为 CPU 核心数）
worker_processes auto;

# 绑定 Worker 到 CPU
worker_cpu_affinity auto;

# 每个 Worker 的最大连接数
events {
    worker_connections 10240;
    use epoll;
    multi_accept on;
}

# 文件描述符限制
worker_rlimit_nofile 65535;
```

### 12.2 连接优化

```nginx
http {
    # 开启长连接
    keepalive_timeout 65;
    keepalive_requests 1000;
    
    # 上游长连接
    upstream backend {
        server 192.168.1.101:8080;
        keepalive 32;
    }
    
    server {
        location / {
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }
    }
}
```

### 12.3 文件传输优化

```nginx
http {
    # 开启 sendfile
    sendfile on;
    
    # 开启 tcp_nopush（配合 sendfile 使用）
    tcp_nopush on;
    
    # 开启 tcp_nodelay
    tcp_nodelay on;
    
    # 文件描述符缓存
    open_file_cache max=10000 inactive=20s;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;
}
```

### 12.4 缓冲区优化

```nginx
http {
    # 客户端请求体缓冲区
    client_body_buffer_size 128k;
    
    # 客户端请求头缓冲区
    client_header_buffer_size 1k;
    large_client_header_buffers 4 32k;
    
    # 代理缓冲区
    proxy_buffer_size 4k;
    proxy_buffers 8 32k;
    proxy_busy_buffers_size 64k;
    
    # FastCGI 缓冲区
    fastcgi_buffer_size 64k;
    fastcgi_buffers 4 64k;
    fastcgi_busy_buffers_size 128k;
}
```

### 12.5 超时优化

```nginx
http {
    # 客户端超时
    client_body_timeout 60s;
    client_header_timeout 60s;
    send_timeout 60s;
    
    # 代理超时
    proxy_connect_timeout 60s;
    proxy_send_timeout 60s;
    proxy_read_timeout 60s;
    
    # FastCGI 超时
    fastcgi_connect_timeout 60s;
    fastcgi_send_timeout 60s;
    fastcgi_read_timeout 60s;
}
```

### 12.6 系统内核优化

```bash
# /etc/sysctl.conf

# 最大文件描述符
fs.file-max = 65535

# TCP 连接优化
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535

# TCP 缓冲区
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# TIME_WAIT 优化
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30

# 应用配置
sysctl -p
```


---

## 13. 高可用配置

### 13.1 Keepalived + Nginx

使用 Keepalived 实现 Nginx 的高可用。

```bash
# 安装 Keepalived
yum install keepalived  # CentOS
apt install keepalived  # Ubuntu
```

**主节点配置（/etc/keepalived/keepalived.conf）：**

```
! Configuration File for keepalived

global_defs {
    router_id nginx_master
}

vrrp_script check_nginx {
    script "/etc/keepalived/check_nginx.sh"
    interval 2
    weight -20
}

vrrp_instance VI_1 {
    state MASTER
    interface eth0
    virtual_router_id 51
    priority 100
    advert_int 1
    
    authentication {
        auth_type PASS
        auth_pass 1234
    }
    
    virtual_ipaddress {
        192.168.1.100/24
    }
    
    track_script {
        check_nginx
    }
}
```

**备节点配置：**

```
! Configuration File for keepalived

global_defs {
    router_id nginx_backup
}

vrrp_script check_nginx {
    script "/etc/keepalived/check_nginx.sh"
    interval 2
    weight -20
}

vrrp_instance VI_1 {
    state BACKUP
    interface eth0
    virtual_router_id 51
    priority 90
    advert_int 1
    
    authentication {
        auth_type PASS
        auth_pass 1234
    }
    
    virtual_ipaddress {
        192.168.1.100/24
    }
    
    track_script {
        check_nginx
    }
}
```

**健康检查脚本（/etc/keepalived/check_nginx.sh）：**

```bash
#!/bin/bash
# 检查 Nginx 是否运行
if ! pidof nginx > /dev/null; then
    # 尝试启动 Nginx
    systemctl start nginx
    sleep 2
    if ! pidof nginx > /dev/null; then
        exit 1
    fi
fi
exit 0
```

```bash
chmod +x /etc/keepalived/check_nginx.sh
systemctl start keepalived
systemctl enable keepalived
```

### 13.2 Nginx 配置同步

```bash
# 使用 rsync 同步配置
rsync -avz --delete /etc/nginx/ backup_server:/etc/nginx/

# 使用 inotify 实时同步
#!/bin/bash
inotifywait -mrq --format '%w%f' -e modify,create,delete /etc/nginx/ | while read file; do
    rsync -avz --delete /etc/nginx/ backup_server:/etc/nginx/
    ssh backup_server "nginx -t && nginx -s reload"
done
```

### 13.3 多活架构

```nginx
# DNS 轮询 + Nginx 负载均衡

# 节点1 配置
upstream backend {
    server 192.168.1.101:8080;
    server 192.168.1.102:8080;
}

# 节点2 配置（相同）
upstream backend {
    server 192.168.1.101:8080;
    server 192.168.1.102:8080;
}

# DNS 配置
# example.com -> 192.168.1.10 (Nginx 节点1)
# example.com -> 192.168.1.11 (Nginx 节点2)
```

---

## 14. 常见错误与解决方案

### 14.1 502 Bad Gateway

**原因：**
1. 后端服务未启动
2. 后端服务响应超时
3. 代理配置错误

**解决方案：**

```bash
# 检查后端服务
curl http://localhost:8080/health

# 检查 Nginx 错误日志
tail -f /var/log/nginx/error.log
```

```nginx
# 增加超时时间
proxy_connect_timeout 300s;
proxy_send_timeout 300s;
proxy_read_timeout 300s;

# 增加缓冲区
proxy_buffer_size 64k;
proxy_buffers 4 64k;
proxy_busy_buffers_size 128k;
```

### 14.2 504 Gateway Timeout

**原因：** 后端服务响应时间过长

**解决方案：**

```nginx
# 增加超时时间
proxy_read_timeout 300s;
fastcgi_read_timeout 300s;

# 或优化后端服务性能
```

### 14.3 413 Request Entity Too Large

**原因：** 请求体超过限制

**解决方案：**

```nginx
# 增加请求体大小限制
client_max_body_size 100m;
```

### 14.4 403 Forbidden

**原因：**
1. 权限不足
2. 目录索引被禁用
3. IP 被拒绝

**解决方案：**

```bash
# 检查文件权限
ls -la /var/www/html/
chmod -R 755 /var/www/html/
chown -R nginx:nginx /var/www/html/

# 检查 SELinux
getenforce
setenforce 0  # 临时关闭
# 或设置正确的上下文
chcon -R -t httpd_sys_content_t /var/www/html/
```

```nginx
# 检查 location 配置
location / {
    root /var/www/html;
    index index.html;
    autoindex on;  # 如果需要目录浏览
}
```

### 14.5 404 Not Found

**原因：**
1. 文件不存在
2. root/alias 配置错误
3. try_files 配置错误

**解决方案：**

```nginx
# 检查 root 配置
location / {
    root /var/www/html;  # 确保路径正确
    try_files $uri $uri/ /index.html;
}

# 检查 alias 配置（注意结尾的 /）
location /static/ {
    alias /var/www/static/;  # 必须以 / 结尾
}
```

### 14.6 配置语法错误

**错误信息：**
```
nginx: [emerg] unknown directive "xxx" in /etc/nginx/nginx.conf:10
```

**解决方案：**

```bash
# 测试配置
nginx -t

# 检查配置语法
# 常见错误：
# 1. 缺少分号
# 2. 括号不匹配
# 3. 指令拼写错误
# 4. 模块未加载
```

### 14.7 端口被占用

**错误信息：**
```
nginx: [emerg] bind() to 0.0.0.0:80 failed (98: Address already in use)
```

**解决方案：**

```bash
# 查看端口占用
netstat -tlnp | grep :80
lsof -i :80

# 停止占用进程
kill -9 <PID>

# 或修改 Nginx 监听端口
listen 8080;
```

### 14.8 权限问题

**错误信息：**
```
nginx: [emerg] open() "/var/log/nginx/error.log" failed (13: Permission denied)
```

**解决方案：**

```bash
# 检查目录权限
ls -la /var/log/nginx/

# 修改权限
chown -R nginx:nginx /var/log/nginx/
chmod -R 755 /var/log/nginx/

# 检查 SELinux
ausearch -m avc -ts recent
setsebool -P httpd_can_network_connect 1
```

### 14.9 upstream 连接失败

**错误信息：**
```
connect() failed (111: Connection refused) while connecting to upstream
```

**解决方案：**

```bash
# 检查后端服务
telnet 192.168.1.101 8080

# 检查防火墙
firewall-cmd --list-all
iptables -L -n
```

```nginx
# 检查 upstream 配置
upstream backend {
    server 192.168.1.101:8080 max_fails=3 fail_timeout=30s;
    server 192.168.1.102:8080 backup;
}
```

### 14.10 SSL 证书错误

**错误信息：**
```
nginx: [emerg] cannot load certificate "/etc/nginx/ssl/cert.pem"
```

**解决方案：**

```bash
# 检查证书文件
ls -la /etc/nginx/ssl/
openssl x509 -in /etc/nginx/ssl/cert.pem -text -noout

# 检查证书链
openssl verify -CAfile /etc/nginx/ssl/ca.pem /etc/nginx/ssl/cert.pem

# 检查私钥
openssl rsa -in /etc/nginx/ssl/key.pem -check
```


---

## 15. 最佳实践

### 15.1 配置文件组织

```
/etc/nginx/
├── nginx.conf                 # 主配置（只包含全局配置）
├── conf.d/
│   ├── default.conf           # 默认站点
│   ├── example.com.conf       # 站点配置
│   └── api.example.com.conf   # API 站点配置
├── snippets/
│   ├── ssl-params.conf        # SSL 通用配置
│   ├── proxy-params.conf      # 代理通用配置
│   └── security-headers.conf  # 安全头配置
└── ssl/
    ├── example.com.crt
    └── example.com.key
```

**主配置文件（nginx.conf）：**

```nginx
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /run/nginx.pid;

events {
    worker_connections 10240;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # 日志格式
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for" '
                    'rt=$request_time';
    
    access_log /var/log/nginx/access.log main;
    
    # 基本优化
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    server_tokens off;
    
    # Gzip
    gzip on;
    gzip_vary on;
    gzip_min_length 1k;
    gzip_comp_level 5;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml;
    
    # 包含站点配置
    include /etc/nginx/conf.d/*.conf;
}
```

**通用配置片段（snippets/ssl-params.conf）：**

```nginx
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;

ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;

ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;

add_header Strict-Transport-Security "max-age=63072000" always;
```

**通用配置片段（snippets/proxy-params.conf）：**

```nginx
proxy_http_version 1.1;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header Connection "";

proxy_connect_timeout 60s;
proxy_send_timeout 60s;
proxy_read_timeout 60s;

proxy_buffer_size 4k;
proxy_buffers 8 32k;
proxy_busy_buffers_size 64k;
```

**站点配置示例（conf.d/example.com.conf）：**

```nginx
upstream backend {
    server 192.168.1.101:8080 weight=5;
    server 192.168.1.102:8080 weight=3;
    keepalive 32;
}

server {
    listen 80;
    server_name example.com www.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name example.com www.example.com;
    
    # SSL 证书
    ssl_certificate /etc/nginx/ssl/example.com.crt;
    ssl_certificate_key /etc/nginx/ssl/example.com.key;
    include /etc/nginx/snippets/ssl-params.conf;
    
    # 日志
    access_log /var/log/nginx/example.com.access.log main;
    error_log /var/log/nginx/example.com.error.log;
    
    # 静态资源
    root /var/www/example.com;
    index index.html;
    
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    # API 代理
    location /api/ {
        include /etc/nginx/snippets/proxy-params.conf;
        proxy_pass http://backend/;
    }
    
    # 静态资源缓存
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        access_log off;
    }
}
```

### 15.2 安全检查清单

```nginx
# 1. 隐藏版本号
server_tokens off;

# 2. 安全响应头
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# 3. HTTPS 配置
ssl_protocols TLSv1.2 TLSv1.3;
add_header Strict-Transport-Security "max-age=63072000" always;

# 4. 禁止访问敏感文件
location ~ /\. {
    deny all;
}

# 5. 限流
limit_req_zone $binary_remote_addr zone=req_limit:10m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

# 6. 请求大小限制
client_max_body_size 10m;

# 7. 超时设置
client_body_timeout 10s;
client_header_timeout 10s;
```

### 15.3 性能检查清单

```nginx
# 1. Worker 进程
worker_processes auto;
worker_cpu_affinity auto;
worker_rlimit_nofile 65535;

# 2. 连接数
events {
    worker_connections 10240;
    use epoll;
    multi_accept on;
}

# 3. 文件传输
sendfile on;
tcp_nopush on;
tcp_nodelay on;

# 4. 长连接
keepalive_timeout 65;
keepalive_requests 1000;

# 5. Gzip 压缩
gzip on;
gzip_comp_level 5;
gzip_min_length 1k;

# 6. 缓存
open_file_cache max=10000 inactive=20s;
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=cache:100m;

# 7. 缓冲区
proxy_buffer_size 4k;
proxy_buffers 8 32k;
```

### 15.4 监控指标

```nginx
# 启用状态页面
location /nginx_status {
    stub_status on;
    allow 127.0.0.1;
    allow 192.168.1.0/24;
    deny all;
}
```

```bash
# 查看状态
curl http://localhost/nginx_status

# 输出示例：
# Active connections: 291
# server accepts handled requests
#  16630948 16630948 31070465
# Reading: 6 Writing: 179 Waiting: 106

# 指标说明：
# Active connections: 当前活动连接数
# accepts: 接受的连接总数
# handled: 处理的连接总数
# requests: 处理的请求总数
# Reading: 正在读取请求头的连接数
# Writing: 正在发送响应的连接数
# Waiting: 等待请求的空闲连接数
```

### 15.5 常用命令速查

```bash
# 配置管理
nginx -t                    # 测试配置
nginx -T                    # 测试并打印配置
nginx -s reload             # 重新加载配置
nginx -s stop               # 快速停止
nginx -s quit               # 优雅停止
nginx -s reopen             # 重新打开日志文件

# 日志分析
# 统计访问量最多的 IP
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -20

# 统计访问量最多的 URL
awk '{print $7}' access.log | sort | uniq -c | sort -rn | head -20

# 统计状态码分布
awk '{print $9}' access.log | sort | uniq -c | sort -rn

# 统计慢请求（响应时间 > 1s）
awk '$NF > 1' access.log | wc -l

# 实时监控
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log

# 性能测试
ab -n 10000 -c 100 http://localhost/
wrk -t12 -c400 -d30s http://localhost/
```

---

## 总结

Nginx 是一款功能强大的 Web 服务器和反向代理服务器，通过本笔记的学习，你应该能够：

1. **掌握基础**：理解 Nginx 的架构和核心概念
2. **熟练安装**：在各种环境下安装和配置 Nginx
3. **配置文件**：理解配置文件结构，熟练编写配置
4. **静态资源**：配置静态资源服务，包括缓存、防盗链等
5. **反向代理**：配置反向代理，处理 WebSocket、路径重写等
6. **负载均衡**：配置多种负载均衡策略，实现高可用
7. **HTTPS**：配置 SSL/TLS，优化 HTTPS 性能
8. **性能优化**：从 Worker、连接、缓冲区等多方面优化性能
9. **安全配置**：配置访问控制、限流、防攻击等安全措施
10. **问题排查**：识别和解决常见的 Nginx 问题

**推荐资源：**
- [Nginx 官方文档](https://nginx.org/en/docs/)
- [Nginx 中文文档](https://www.nginx.cn/doc/)
- [Nginx 配置生成器](https://www.digitalocean.com/community/tools/nginx)
- [Mozilla SSL 配置生成器](https://ssl-config.mozilla.org/)