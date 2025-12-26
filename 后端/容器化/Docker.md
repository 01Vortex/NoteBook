

> Docker 是一个开源的容器化平台，用于开发、部署和运行应用程序
> 本笔记涵盖 Docker 从入门到进阶的完整知识体系

---

## 目录

1. [基础概念](#1-基础概念)
2. [安装与配置](#2-安装与配置)
3. [镜像管理](#3-镜像管理)
4. [容器操作](#4-容器操作)
5. [Dockerfile 详解](#5-dockerfile-详解)
6. [数据管理](#6-数据管理)
7. [网络配置](#7-网络配置)
8. [Docker Compose](#8-docker-compose)
9. [Docker Swarm](#9-docker-swarm)
10. [安全最佳实践](#10-安全最佳实践)
11. [性能优化](#11-性能优化)
12. [CI/CD 集成](#12-cicd-集成)
13. [常见错误与解决方案](#13-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Docker？

Docker 是一种容器化技术，它允许你将应用程序及其所有依赖项打包到一个标准化的单元中，称为"容器"。
想象一下，你要搬家，与其一件一件搬东西，不如把所有东西装进一个集装箱，整体搬运——Docker 就是这个"集装箱"。

**核心优势：**
- **一致性**：开发、测试、生产环境完全一致，告别"在我电脑上能跑"的问题
- **隔离性**：每个容器相互独立，互不干扰
- **轻量级**：相比虚拟机，容器启动快、资源占用少
- **可移植性**：一次构建，到处运行

### 1.2 Docker vs 虚拟机

| 特性 | Docker 容器 | 虚拟机 |
|------|------------|--------|
| 启动时间 | 秒级 | 分钟级 |
| 硬盘占用 | MB 级别 | GB 级别 |
| 性能 | 接近原生 | 有损耗 |
| 系统支持量 | 单机支持上千容器 | 一般几十个 |
| 隔离级别 | 进程级别 | 系统级别 |

### 1.3 核心概念

**镜像（Image）**
镜像是一个只读的模板，包含了运行应用所需的所有内容：代码、运行时、库、环境变量和配置文件。
可以把镜像理解为"类"，而容器就是"实例"。

**容器（Container）**
容器是镜像的运行实例。你可以创建、启动、停止、删除容器。
每个容器都是相互隔离的，拥有自己的文件系统、网络和进程空间。

**仓库（Registry）**
仓库是存放镜像的地方。Docker Hub 是最大的公共仓库，你也可以搭建私有仓库。

**Dockerfile**
Dockerfile 是一个文本文件，包含了构建镜像所需的所有指令。

```
┌─────────────────────────────────────────────────────┐
│                    Docker 架构                       │
├─────────────────────────────────────────────────────┤
│  ┌─────────┐  ┌─────────┐  ┌─────────┐             │
│  │ 容器 A  │  │ 容器 B  │  │ 容器 C  │  ← 容器层   │
│  └────┬────┘  └────┬────┘  └────┬────┘             │
│       │            │            │                   │
│  ┌────┴────────────┴────────────┴────┐             │
│  │           Docker Engine           │  ← 引擎层   │
│  └───────────────┬───────────────────┘             │
│                  │                                  │
│  ┌───────────────┴───────────────────┐             │
│  │           Host OS (Linux)         │  ← 宿主机   │
│  └───────────────────────────────────┘             │
└─────────────────────────────────────────────────────┘
```

---

## 2. 安装与配置

### 2.1 Linux 安装（Ubuntu/Debian）

```bash
# 1. 更新包索引
sudo apt-get update

# 2. 安装必要的依赖
sudo apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

# 3. 添加 Docker 官方 GPG 密钥
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# 4. 设置稳定版仓库
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# 5. 安装 Docker Engine
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io

# 6. 验证安装
sudo docker run hello-world
```

### 2.2 CentOS/RHEL 安装

```bash
# 1. 卸载旧版本
sudo yum remove docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine

# 2. 安装依赖
sudo yum install -y yum-utils

# 3. 设置仓库
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

# 4. 安装 Docker
sudo yum install -y docker-ce docker-ce-cli containerd.io

# 5. 启动 Docker
sudo systemctl start docker
sudo systemctl enable docker
```

### 2.3 Windows/Mac 安装

直接下载 Docker Desktop：
- Windows: https://docs.docker.com/desktop/install/windows-install/
- Mac: https://docs.docker.com/desktop/install/mac-install/

### 2.4 配置非 root 用户运行 Docker

```bash
# 创建 docker 组（通常安装时已创建）
sudo groupadd docker

# 将当前用户添加到 docker 组
sudo usermod -aG docker $USER

# 重新登录或执行以下命令使更改生效
newgrp docker

# 验证
docker run hello-world
```

### 2.5 配置镜像加速器

国内访问 Docker Hub 较慢，建议配置镜像加速器：

```bash
# 创建或编辑配置文件
sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json <<-'EOF'
{
  "registry-mirrors": [
    "https://mirror.ccs.tencentyun.com",
    "https://hub-mirror.c.163.com",
    "https://docker.mirrors.ustc.edu.cn"
  ]
}
EOF

# 重启 Docker
sudo systemctl daemon-reload
sudo systemctl restart docker

# 验证配置
docker info | grep -A 5 "Registry Mirrors"
```

---

## 3. 镜像管理

### 3.1 镜像基本操作

```bash
# 搜索镜像
docker search nginx

# 拉取镜像（默认 latest 标签）
docker pull nginx

# 拉取指定版本
docker pull nginx:1.21.0

# 查看本地镜像
docker images
docker image ls

# 查看镜像详细信息
docker inspect nginx

# 查看镜像历史（构建层）
docker history nginx

# 删除镜像
docker rmi nginx
docker image rm nginx

# 强制删除（即使有容器在使用）
docker rmi -f nginx

# 删除所有未使用的镜像
docker image prune

# 删除所有镜像
docker rmi $(docker images -q)
```

### 3.2 镜像标签管理

```bash
# 给镜像打标签
docker tag nginx:latest myregistry.com/nginx:v1.0

# 推送到仓库
docker push myregistry.com/nginx:v1.0

# 登录私有仓库
docker login myregistry.com

# 登出
docker logout myregistry.com
```

### 3.3 镜像导入导出

```bash
# 导出镜像为 tar 文件
docker save -o nginx.tar nginx:latest

# 导出多个镜像
docker save -o images.tar nginx:latest redis:latest

# 导入镜像
docker load -i nginx.tar

# 从容器创建镜像
docker commit container_id myimage:v1.0
```

---

## 4. 容器操作

### 4.1 容器生命周期

```bash
# 创建容器（不启动）
docker create --name mynginx nginx

# 启动容器
docker start mynginx

# 创建并启动容器（最常用）
docker run --name mynginx -d nginx

# 停止容器
docker stop mynginx

# 强制停止
docker kill mynginx

# 重启容器
docker restart mynginx

# 暂停容器
docker pause mynginx

# 恢复容器
docker unpause mynginx

# 删除容器
docker rm mynginx

# 强制删除运行中的容器
docker rm -f mynginx

# 删除所有停止的容器
docker container prune

# 删除所有容器
docker rm -f $(docker ps -aq)
```

### 4.2 docker run 详解

`docker run` 是最常用的命令，参数众多：

```bash
docker run [OPTIONS] IMAGE [COMMAND] [ARG...]

# 常用参数说明：
# -d, --detach          后台运行
# -i, --interactive     保持 STDIN 打开
# -t, --tty             分配伪终端
# --name                指定容器名称
# -p, --publish         端口映射 宿主机端口:容器端口
# -P                    随机端口映射
# -v, --volume          挂载卷 宿主机路径:容器路径
# -e, --env             设置环境变量
# --env-file            从文件读取环境变量
# -w, --workdir         设置工作目录
# --network             指定网络
# --restart             重启策略
# --rm                  容器退出后自动删除
# --privileged          特权模式
# -u, --user            指定用户
# --cpus                限制 CPU
# -m, --memory          限制内存
```

### 4.3 实际运行示例

```bash
# 运行 Nginx 并映射端口
docker run -d --name web -p 80:80 nginx

# 运行 MySQL 并设置环境变量
docker run -d --name mysql \
  -p 3306:3306 \
  -e MYSQL_ROOT_PASSWORD=123456 \
  -e MYSQL_DATABASE=mydb \
  -v mysql_data:/var/lib/mysql \
  mysql:8.0

# 运行 Redis
docker run -d --name redis \
  -p 6379:6379 \
  -v redis_data:/data \
  redis:latest \
  redis-server --appendonly yes

# 交互式运行 Ubuntu
docker run -it --name ubuntu ubuntu:20.04 /bin/bash

# 运行后自动删除（适合临时任务）
docker run --rm alpine echo "Hello Docker"

# 限制资源
docker run -d --name limited \
  --cpus="1.5" \
  --memory="512m" \
  nginx
```

### 4.4 容器查看与监控

```bash
# 查看运行中的容器
docker ps

# 查看所有容器（包括停止的）
docker ps -a

# 只显示容器 ID
docker ps -q

# 查看容器详细信息
docker inspect container_name

# 查看容器日志
docker logs container_name

# 实时查看日志
docker logs -f container_name

# 查看最后 100 行日志
docker logs --tail 100 container_name

# 查看带时间戳的日志
docker logs -t container_name

# 查看容器资源使用情况
docker stats

# 查看指定容器的资源使用
docker stats container_name

# 查看容器内进程
docker top container_name

# 查看容器端口映射
docker port container_name
```

### 4.5 容器交互

```bash
# 进入运行中的容器
docker exec -it container_name /bin/bash

# 如果容器没有 bash，使用 sh
docker exec -it container_name /bin/sh

# 在容器中执行命令
docker exec container_name ls -la

# 以 root 用户进入容器
docker exec -it -u root container_name /bin/bash

# 附加到容器（不推荐，Ctrl+C 会停止容器）
docker attach container_name

# 从容器复制文件到宿主机
docker cp container_name:/path/to/file /host/path

# 从宿主机复制文件到容器
docker cp /host/path container_name:/path/to/file
```

---

## 5. Dockerfile 详解

### 5.1 Dockerfile 基础

Dockerfile 是构建镜像的蓝图，每条指令都会创建一个新的镜像层。

```dockerfile
# 基础镜像
FROM ubuntu:20.04

# 维护者信息（已废弃，建议用 LABEL）
LABEL maintainer="your@email.com"
LABEL version="1.0"
LABEL description="My custom image"

# 设置环境变量
ENV APP_HOME=/app
ENV NODE_ENV=production

# 设置工作目录
WORKDIR $APP_HOME

# 复制文件
COPY package*.json ./
COPY . .

# 添加文件（支持 URL 和自动解压）
ADD https://example.com/file.tar.gz /tmp/
ADD archive.tar.gz /app/

# 运行命令（构建时执行）
RUN apt-get update && apt-get install -y \
    curl \
    vim \
    && rm -rf /var/lib/apt/lists/*

# 暴露端口（文档作用，实际映射需要 -p）
EXPOSE 80 443

# 创建挂载点
VOLUME ["/data", "/logs"]

# 设置用户
USER appuser

# 容器启动命令
CMD ["nginx", "-g", "daemon off;"]

# 入口点（与 CMD 配合使用）
ENTRYPOINT ["docker-entrypoint.sh"]
```

### 5.2 指令详解

**FROM - 基础镜像**
```dockerfile
# 单阶段构建
FROM node:16-alpine

# 多阶段构建
FROM node:16 AS builder
FROM nginx:alpine AS production
```

**RUN - 执行命令**
```dockerfile
# Shell 格式
RUN apt-get update && apt-get install -y curl

# Exec 格式（推荐）
RUN ["apt-get", "update"]

# 多行命令（减少层数）
RUN apt-get update \
    && apt-get install -y \
        curl \
        wget \
        vim \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
```

**COPY vs ADD**
```dockerfile
# COPY - 简单复制（推荐）
COPY src/ /app/src/
COPY --chown=user:group file.txt /app/

# ADD - 支持 URL 和自动解压
ADD https://example.com/file /app/
ADD archive.tar.gz /app/  # 自动解压
```

**CMD vs ENTRYPOINT**
```dockerfile
# CMD - 容器启动默认命令（可被覆盖）
CMD ["nginx", "-g", "daemon off;"]
CMD nginx -g "daemon off;"  # Shell 格式

# ENTRYPOINT - 容器入口点（不易被覆盖）
ENTRYPOINT ["docker-entrypoint.sh"]

# 组合使用（最佳实践）
ENTRYPOINT ["python"]
CMD ["app.py"]
# 运行时：docker run myimage          → python app.py
# 运行时：docker run myimage test.py  → python test.py
```

**ARG - 构建参数**
```dockerfile
# 定义构建参数
ARG VERSION=latest
ARG BUILD_DATE

# 使用参数
FROM node:${VERSION}

# 构建时传入
# docker build --build-arg VERSION=16 .
```

**HEALTHCHECK - 健康检查**
```dockerfile
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost/ || exit 1

# 禁用健康检查
HEALTHCHECK NONE
```

### 5.3 多阶段构建

多阶段构建可以显著减小镜像体积，是生产环境的最佳实践：

```dockerfile
# ============ 构建阶段 ============
FROM node:16 AS builder

WORKDIR /app

# 先复制依赖文件（利用缓存）
COPY package*.json ./
RUN npm ci --only=production

# 复制源码并构建
COPY . .
RUN npm run build

# ============ 生产阶段 ============
FROM node:16-alpine AS production

WORKDIR /app

# 只复制必要文件
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

# 创建非 root 用户
RUN addgroup -g 1001 -S nodejs \
    && adduser -S nextjs -u 1001
USER nextjs

EXPOSE 3000
CMD ["node", "dist/main.js"]
```

**Go 应用多阶段构建示例：**
```dockerfile
# 构建阶段
FROM golang:1.19 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# 生产阶段（使用 scratch 最小镜像）
FROM scratch

COPY --from=builder /app/main /main
EXPOSE 8080
ENTRYPOINT ["/main"]
```

### 5.4 .dockerignore 文件

类似 .gitignore，用于排除不需要的文件：

```plaintext
# .dockerignore
node_modules
npm-debug.log
Dockerfile*
docker-compose*
.git
.gitignore
.env
*.md
!README.md
.DS_Store
coverage
.nyc_output
```

### 5.5 构建镜像

```bash
# 基本构建
docker build -t myapp:v1.0 .

# 指定 Dockerfile
docker build -f Dockerfile.prod -t myapp:prod .

# 不使用缓存
docker build --no-cache -t myapp:v1.0 .

# 传入构建参数
docker build --build-arg VERSION=1.0 -t myapp:v1.0 .

# 多平台构建
docker buildx build --platform linux/amd64,linux/arm64 -t myapp:v1.0 .

# 查看构建过程
docker build --progress=plain -t myapp:v1.0 .
```

---

## 6. 数据管理

Docker 容器是临时的，数据持久化需要使用卷（Volume）或绑定挂载（Bind Mount）。

### 6.1 数据卷（Volume）

数据卷是 Docker 管理的持久化存储，推荐用于生产环境：

```bash
# 创建卷
docker volume create mydata

# 查看所有卷
docker volume ls

# 查看卷详情
docker volume inspect mydata

# 删除卷
docker volume rm mydata

# 删除所有未使用的卷
docker volume prune

# 使用卷运行容器
docker run -d --name mysql \
  -v mydata:/var/lib/mysql \
  mysql:8.0

# 匿名卷（Docker 自动命名）
docker run -d -v /var/lib/mysql mysql:8.0
```

### 6.2 绑定挂载（Bind Mount）

直接挂载宿主机目录，适合开发环境：

```bash
# 绑定挂载
docker run -d --name web \
  -v /host/path:/container/path \
  nginx

# 只读挂载
docker run -d --name web \
  -v /host/path:/container/path:ro \
  nginx

# 使用 --mount 语法（更清晰）
docker run -d --name web \
  --mount type=bind,source=/host/path,target=/container/path \
  nginx

# 开发环境示例：实时同步代码
docker run -d --name dev \
  -v $(pwd):/app \
  -w /app \
  node:16 npm run dev
```

### 6.3 tmpfs 挂载

将数据存储在内存中，容器停止后数据消失：

```bash
docker run -d --name temp \
  --tmpfs /app/cache \
  --mount type=tmpfs,destination=/app/temp,tmpfs-size=100m \
  myapp
```

### 6.4 数据卷容器

用于在多个容器间共享数据：

```bash
# 创建数据卷容器
docker create --name data-container \
  -v /data \
  busybox

# 其他容器使用该卷
docker run -d --name app1 --volumes-from data-container myapp
docker run -d --name app2 --volumes-from data-container myapp
```

### 6.5 备份与恢复

```bash
# 备份卷数据
docker run --rm \
  -v mydata:/source:ro \
  -v $(pwd):/backup \
  alpine tar czf /backup/mydata-backup.tar.gz -C /source .

# 恢复卷数据
docker run --rm \
  -v mydata:/target \
  -v $(pwd):/backup \
  alpine tar xzf /backup/mydata-backup.tar.gz -C /target
```

---

## 7. 网络配置

### 7.1 网络类型

Docker 提供多种网络驱动：

| 网络类型 | 说明 | 使用场景 |
|---------|------|---------|
| bridge | 默认网络，容器通过虚拟网桥通信 | 单机容器通信 |
| host | 容器使用宿主机网络 | 需要高性能网络 |
| none | 无网络 | 安全隔离场景 |
| overlay | 跨主机网络 | Docker Swarm |
| macvlan | 容器拥有独立 MAC 地址 | 需要直接接入物理网络 |

### 7.2 网络基本操作

```bash
# 查看网络列表
docker network ls

# 创建网络
docker network create mynetwork

# 创建指定子网的网络
docker network create --subnet=172.20.0.0/16 mynetwork

# 查看网络详情
docker network inspect mynetwork

# 删除网络
docker network rm mynetwork

# 删除所有未使用的网络
docker network prune
```

### 7.3 容器网络连接

```bash
# 创建容器时指定网络
docker run -d --name web --network mynetwork nginx

# 将运行中的容器连接到网络
docker network connect mynetwork container_name

# 断开网络连接
docker network disconnect mynetwork container_name

# 指定 IP 地址
docker run -d --name web \
  --network mynetwork \
  --ip 172.20.0.10 \
  nginx

# 使用 host 网络
docker run -d --name web --network host nginx

# 禁用网络
docker run -d --name isolated --network none alpine
```

### 7.4 容器间通信

```bash
# 创建自定义网络
docker network create app-network

# 启动数据库容器
docker run -d --name mysql \
  --network app-network \
  -e MYSQL_ROOT_PASSWORD=123456 \
  mysql:8.0

# 启动应用容器（可通过容器名访问数据库）
docker run -d --name app \
  --network app-network \
  -e DB_HOST=mysql \
  -e DB_PORT=3306 \
  myapp

# 在同一网络中，容器可以通过名称互相访问
# app 容器可以使用 mysql:3306 连接数据库
```

### 7.5 端口映射详解

```bash
# 映射到指定端口
docker run -d -p 8080:80 nginx

# 映射到随机端口
docker run -d -P nginx

# 映射多个端口
docker run -d -p 80:80 -p 443:443 nginx

# 指定绑定 IP
docker run -d -p 127.0.0.1:8080:80 nginx

# 映射 UDP 端口
docker run -d -p 53:53/udp dns-server

# 查看端口映射
docker port container_name
```

---

## 8. Docker Compose

Docker Compose 用于定义和运行多容器应用，通过 YAML 文件配置服务。

### 8.1 安装 Docker Compose

```bash
# Linux 安装
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# 验证安装
docker-compose --version

# Docker Desktop 已内置 docker compose（注意没有横杠）
docker compose version
```

### 8.2 docker-compose.yml 基础

```yaml
version: '3.8'

services:
  # Web 应用服务
  web:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - DB_HOST=db
    depends_on:
      - db
      - redis
    volumes:
      - ./src:/app/src
    networks:
      - app-network
    restart: unless-stopped

  # 数据库服务
  db:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: ${DB_PASSWORD:-123456}
      MYSQL_DATABASE: myapp
    volumes:
      - mysql_data:/var/lib/mysql
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - app-network
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      interval: 10s
      timeout: 5s
      retries: 5

  # Redis 缓存服务
  redis:
    image: redis:alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    networks:
      - app-network

  # Nginx 反向代理
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - web
    networks:
      - app-network

volumes:
  mysql_data:
  redis_data:

networks:
  app-network:
    driver: bridge
```

### 8.3 Compose 常用命令

```bash
# 启动所有服务（后台运行）
docker-compose up -d

# 启动并重新构建
docker-compose up -d --build

# 查看服务状态
docker-compose ps

# 查看服务日志
docker-compose logs
docker-compose logs -f web  # 实时查看指定服务

# 停止服务
docker-compose stop

# 停止并删除容器、网络
docker-compose down

# 停止并删除卷
docker-compose down -v

# 重启服务
docker-compose restart

# 进入服务容器
docker-compose exec web bash

# 运行一次性命令
docker-compose run --rm web npm test

# 扩展服务实例
docker-compose up -d --scale web=3

# 查看服务配置
docker-compose config
```

### 8.4 Compose 高级配置

**环境变量**
```yaml
services:
  web:
    image: myapp
    environment:
      # 直接设置
      - NODE_ENV=production
      # 从宿主机环境变量读取
      - API_KEY
      # 带默认值
      - DB_HOST=${DB_HOST:-localhost}
    env_file:
      - .env
      - .env.production
```

**健康检查与依赖**
```yaml
services:
  web:
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_started

  db:
    image: mysql:8.0
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
```

**资源限制**
```yaml
services:
  web:
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M
```

**多配置文件**
```bash
# 基础配置 + 开发配置
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up

# 基础配置 + 生产配置
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### 8.5 完整项目示例

```yaml
# docker-compose.yml - 完整的 Web 应用栈
version: '3.8'

services:
  # 前端应用
  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    environment:
      - REACT_APP_API_URL=http://localhost:8080
    depends_on:
      - backend

  # 后端 API
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    environment:
      - SPRING_PROFILES_ACTIVE=docker
      - DB_URL=jdbc:mysql://db:3306/myapp
      - DB_USERNAME=root
      - DB_PASSWORD=${DB_PASSWORD}
      - REDIS_HOST=redis
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_started
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/actuator/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # MySQL 数据库
  db:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: ${DB_PASSWORD}
      MYSQL_DATABASE: myapp
    volumes:
      - mysql_data:/var/lib/mysql
      - ./sql:/docker-entrypoint-initdb.d
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      interval: 10s
      timeout: 5s
      retries: 5

  # Redis 缓存
  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data

  # Nginx 反向代理
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - frontend
      - backend

volumes:
  mysql_data:
  redis_data:
```

---

## 9. Docker Swarm

Docker Swarm 是 Docker 原生的集群管理和编排工具，适合中小规模集群。

### 9.1 Swarm 基础概念

- **Manager 节点**：管理集群状态，调度服务
- **Worker 节点**：运行容器任务
- **Service**：定义要运行的任务
- **Task**：Service 的实例，运行在节点上
- **Stack**：一组相关服务的集合

### 9.2 初始化集群

```bash
# 初始化 Swarm（当前节点成为 Manager）
docker swarm init --advertise-addr <MANAGER-IP>

# 获取加入 Worker 的 token
docker swarm join-token worker

# 获取加入 Manager 的 token
docker swarm join-token manager

# Worker 节点加入集群
docker swarm join --token <TOKEN> <MANAGER-IP>:2377

# 查看节点
docker node ls

# 离开集群
docker swarm leave
docker swarm leave --force  # Manager 节点
```

### 9.3 服务管理

```bash
# 创建服务
docker service create --name web --replicas 3 -p 80:80 nginx

# 查看服务
docker service ls

# 查看服务详情
docker service inspect web

# 查看服务任务
docker service ps web

# 扩缩容
docker service scale web=5

# 更新服务
docker service update --image nginx:1.21 web

# 滚动更新配置
docker service update \
  --update-parallelism 2 \
  --update-delay 10s \
  --image nginx:1.21 \
  web

# 回滚服务
docker service rollback web

# 删除服务
docker service rm web
```

### 9.4 Stack 部署

```yaml
# docker-stack.yml
version: '3.8'

services:
  web:
    image: nginx:alpine
    deploy:
      replicas: 3
      update_config:
        parallelism: 1
        delay: 10s
      restart_policy:
        condition: on-failure
      placement:
        constraints:
          - node.role == worker
    ports:
      - "80:80"
    networks:
      - webnet

  visualizer:
    image: dockersamples/visualizer
    ports:
      - "8080:8080"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    deploy:
      placement:
        constraints:
          - node.role == manager

networks:
  webnet:
```

```bash
# 部署 Stack
docker stack deploy -c docker-stack.yml myapp

# 查看 Stack
docker stack ls

# 查看 Stack 服务
docker stack services myapp

# 删除 Stack
docker stack rm myapp
```

---

## 10. 安全最佳实践

### 10.1 镜像安全

```dockerfile
# 1. 使用官方基础镜像
FROM node:16-alpine

# 2. 使用特定版本，避免 latest
FROM nginx:1.21.0

# 3. 使用最小化镜像
FROM alpine:3.14
FROM gcr.io/distroless/nodejs:16

# 4. 扫描镜像漏洞
# docker scan myimage:latest
```

```bash
# 扫描镜像安全漏洞
docker scan nginx:latest

# 使用 Trivy 扫描
trivy image nginx:latest
```

### 10.2 运行时安全

```bash
# 1. 不使用 root 用户运行
docker run -u 1000:1000 myapp

# 2. 只读文件系统
docker run --read-only myapp

# 3. 限制权限
docker run --cap-drop ALL --cap-add NET_BIND_SERVICE myapp

# 4. 禁用特权模式
# 避免使用 --privileged

# 5. 限制资源
docker run --memory="512m" --cpus="1" myapp

# 6. 使用安全选项
docker run --security-opt no-new-privileges myapp
```

### 10.3 Dockerfile 安全实践

```dockerfile
# 创建非 root 用户
FROM node:16-alpine

# 创建应用用户
RUN addgroup -g 1001 -S appgroup \
    && adduser -u 1001 -S appuser -G appgroup

WORKDIR /app

# 复制文件并设置权限
COPY --chown=appuser:appgroup . .

# 切换到非 root 用户
USER appuser

# 使用 HEALTHCHECK
HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget --quiet --tries=1 --spider http://localhost:3000/health || exit 1

EXPOSE 3000
CMD ["node", "server.js"]
```

### 10.4 网络安全

```bash
# 1. 使用自定义网络隔离
docker network create --internal internal-network

# 2. 限制容器间通信
docker network create --opt com.docker.network.bridge.enable_icc=false isolated

# 3. 不暴露不必要的端口
# 只映射需要的端口，使用 127.0.0.1 绑定本地
docker run -p 127.0.0.1:3000:3000 myapp
```

### 10.5 敏感信息管理

```bash
# 使用 Docker Secrets（Swarm 模式）
echo "my_password" | docker secret create db_password -

# 在服务中使用
docker service create \
  --name web \
  --secret db_password \
  myapp

# 在 Compose 中使用
# docker-compose.yml
services:
  web:
    secrets:
      - db_password

secrets:
  db_password:
    external: true
```

```yaml
# 使用环境变量文件（开发环境）
services:
  web:
    env_file:
      - .env.local  # 不要提交到版本控制
```

---

## 11. 性能优化

### 11.1 镜像优化

```dockerfile
# 1. 使用多阶段构建减小体积
FROM node:16 AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:16-alpine
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
CMD ["node", "dist/main.js"]

# 2. 合并 RUN 指令减少层数
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 3. 利用构建缓存（先复制依赖文件）
COPY package*.json ./
RUN npm ci
COPY . .

# 4. 使用 .dockerignore 排除无用文件
```

### 11.2 构建优化

```bash
# 使用 BuildKit（更快的构建）
DOCKER_BUILDKIT=1 docker build -t myapp .

# 启用全局 BuildKit
# /etc/docker/daemon.json
{
  "features": {
    "buildkit": true
  }
}

# 并行构建多个镜像
docker buildx bake

# 使用缓存挂载加速依赖安装
# syntax=docker/dockerfile:1.4
RUN --mount=type=cache,target=/root/.npm \
    npm ci
```

### 11.3 运行时优化

```bash
# 1. 合理分配资源
docker run -d \
  --cpus="2" \
  --memory="1g" \
  --memory-swap="2g" \
  myapp

# 2. 使用 tmpfs 加速临时文件
docker run -d \
  --tmpfs /tmp:rw,noexec,nosuid,size=100m \
  myapp

# 3. 优化日志驱动
docker run -d \
  --log-driver json-file \
  --log-opt max-size=10m \
  --log-opt max-file=3 \
  myapp

# 4. 使用 host 网络提升性能（适用场景有限）
docker run -d --network host myapp
```

### 11.4 存储优化

```bash
# 1. 使用 volume 而非 bind mount（生产环境）
docker run -v mydata:/data myapp

# 2. 定期清理
docker system prune -a --volumes

# 3. 使用存储驱动优化
# /etc/docker/daemon.json
{
  "storage-driver": "overlay2"
}
```

---

## 12. CI/CD 集成

### 12.1 GitHub Actions 示例

```yaml
# .github/workflows/docker.yml
name: Docker Build and Push

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v2

      - name: Login to Docker Hub
        uses: docker/login-action@v2
        with:
          username: ${{ secrets.DOCKER_USERNAME }}
          password: ${{ secrets.DOCKER_PASSWORD }}

      - name: Build and push
        uses: docker/build-push-action@v4
        with:
          context: .
          push: true
          tags: |
            myuser/myapp:latest
            myuser/myapp:${{ github.sha }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

### 12.2 GitLab CI 示例

```yaml
# .gitlab-ci.yml
stages:
  - build
  - test
  - deploy

variables:
  DOCKER_IMAGE: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA

build:
  stage: build
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
    - docker build -t $DOCKER_IMAGE .
    - docker push $DOCKER_IMAGE

test:
  stage: test
  image: $DOCKER_IMAGE
  script:
    - npm test

deploy:
  stage: deploy
  script:
    - docker pull $DOCKER_IMAGE
    - docker-compose up -d
  only:
    - main
```

### 12.3 Jenkins Pipeline 示例

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    environment {
        DOCKER_IMAGE = "myapp:${BUILD_NUMBER}"
        REGISTRY = "registry.example.com"
    }
    
    stages {
        stage('Build') {
            steps {
                script {
                    docker.build("${REGISTRY}/${DOCKER_IMAGE}")
                }
            }
        }
        
        stage('Test') {
            steps {
                script {
                    docker.image("${REGISTRY}/${DOCKER_IMAGE}").inside {
                        sh 'npm test'
                    }
                }
            }
        }
        
        stage('Push') {
            steps {
                script {
                    docker.withRegistry("https://${REGISTRY}", 'docker-credentials') {
                        docker.image("${REGISTRY}/${DOCKER_IMAGE}").push()
                        docker.image("${REGISTRY}/${DOCKER_IMAGE}").push('latest')
                    }
                }
            }
        }
        
        stage('Deploy') {
            steps {
                sh 'docker-compose pull && docker-compose up -d'
            }
        }
    }
}
```

---

## 13. 常见错误与解决方案

### 13.1 镜像相关错误

**错误：Cannot connect to the Docker daemon**
```bash
# 原因：Docker 服务未启动或权限不足
# 解决方案：
sudo systemctl start docker
sudo usermod -aG docker $USER
newgrp docker
```

**错误：no space left on device**
```bash
# 原因：磁盘空间不足
# 解决方案：
docker system prune -a --volumes
docker image prune -a
df -h  # 检查磁盘空间
```

**错误：pull access denied / repository does not exist**
```bash
# 原因：镜像名称错误或需要登录
# 解决方案：
docker login
docker pull correct-image-name:tag
```

**错误：manifest unknown / manifest not found**
```bash
# 原因：指定的标签不存在
# 解决方案：
# 检查可用标签：https://hub.docker.com
docker pull nginx:1.21.0  # 使用正确的标签
```

### 13.2 容器相关错误

**错误：container is already in use**
```bash
# 原因：容器名称已存在
# 解决方案：
docker rm existing_container
# 或使用不同名称
docker run --name new_name image
```

**错误：port is already allocated**
```bash
# 原因：端口被占用
# 解决方案：
# 查找占用端口的进程
netstat -tlnp | grep :80
lsof -i :80
# 使用其他端口
docker run -p 8080:80 nginx
```

**错误：OCI runtime create failed**
```bash
# 原因：容器配置错误或资源问题
# 解决方案：
# 检查容器日志
docker logs container_name
# 检查系统资源
docker system info
# 重启 Docker
sudo systemctl restart docker
```

**错误：exec format error**
```bash
# 原因：镜像架构与主机不匹配（如 ARM vs x86）
# 解决方案：
# 使用正确架构的镜像
docker pull --platform linux/amd64 image_name
# 或使用多架构镜像
docker buildx build --platform linux/amd64,linux/arm64 -t myimage .
```

**错误：container exited with code 137**
```bash
# 原因：容器被 OOM Killer 杀死（内存不足）
# 解决方案：
# 增加内存限制
docker run -m 1g myapp
# 检查应用内存使用
docker stats container_name
```

**错误：container exited with code 1**
```bash
# 原因：应用程序错误
# 解决方案：
# 查看日志
docker logs container_name
# 交互式调试
docker run -it myimage /bin/sh
```

### 13.3 网络相关错误

**错误：network not found**
```bash
# 原因：指定的网络不存在
# 解决方案：
docker network create mynetwork
docker network ls  # 查看可用网络
```

**错误：could not resolve host**
```bash
# 原因：DNS 解析失败
# 解决方案：
# 检查 DNS 配置
docker run --dns 8.8.8.8 myapp
# 或配置 daemon.json
{
  "dns": ["8.8.8.8", "8.8.4.4"]
}
```

**错误：connection refused between containers**
```bash
# 原因：容器不在同一网络或服务未启动
# 解决方案：
# 确保容器在同一网络
docker network connect mynetwork container1
docker network connect mynetwork container2
# 使用容器名称而非 localhost
# 正确：mysql:3306
# 错误：localhost:3306
```

### 13.4 Dockerfile 相关错误

**错误：COPY failed: file not found**
```dockerfile
# 原因：文件路径错误或被 .dockerignore 排除
# 解决方案：
# 检查文件是否存在
# 检查 .dockerignore
# 使用正确的相对路径（相对于构建上下文）
COPY ./src /app/src  # 正确
COPY /absolute/path /app  # 错误
```

**错误：returned a non-zero code: 1**
```dockerfile
# 原因：RUN 命令执行失败
# 解决方案：
# 添加 -y 参数避免交互
RUN apt-get install -y package
# 检查命令是否正确
# 使用 || true 忽略非关键错误
RUN command || true
```

**错误：invalid reference format**
```bash
# 原因：镜像名称格式错误
# 解决方案：
# 镜像名称只能包含小写字母、数字、点、横杠、下划线
docker build -t my-app:v1.0 .  # 正确
docker build -t My_App:V1.0 .  # 错误
```

### 13.5 Docker Compose 相关错误

**错误：yaml: line X: did not find expected key**
```yaml
# 原因：YAML 格式错误（缩进问题）
# 解决方案：
# 使用空格而非 Tab
# 保持一致的缩进（2 或 4 空格）
services:
  web:
    image: nginx  # 正确缩进
```

**错误：service "web" depends on undefined service**
```yaml
# 原因：依赖的服务未定义
# 解决方案：
services:
  web:
    depends_on:
      - db  # 确保 db 服务已定义
  db:
    image: mysql
```

**错误：Bind for 0.0.0.0:80 failed: port is already allocated**
```bash
# 原因：端口被其他容器或进程占用
# 解决方案：
docker-compose down  # 停止旧容器
docker ps -a  # 检查运行中的容器
# 修改端口映射
ports:
  - "8080:80"
```

### 13.6 数据卷相关错误

**错误：volume is in use**
```bash
# 原因：卷正被容器使用
# 解决方案：
# 停止使用该卷的容器
docker stop $(docker ps -q --filter volume=myvolume)
docker volume rm myvolume
```

**错误：permission denied on mounted volume**
```bash
# 原因：容器用户无权访问挂载目录
# 解决方案：
# 方法1：修改宿主机目录权限
chmod -R 777 /host/path

# 方法2：使用相同 UID 运行容器
docker run -u $(id -u):$(id -g) -v /host/path:/container/path myapp

# 方法3：在 Dockerfile 中设置权限
RUN chown -R appuser:appgroup /app
```

### 13.7 性能相关问题

**问题：容器启动很慢**
```bash
# 可能原因：镜像太大、健康检查配置不当
# 解决方案：
# 1. 使用更小的基础镜像
FROM alpine:3.14

# 2. 优化健康检查
healthcheck:
  start_period: 30s  # 给应用启动时间
  interval: 30s

# 3. 使用多阶段构建减小镜像
```

**问题：容器内存占用过高**
```bash
# 解决方案：
# 1. 设置内存限制
docker run -m 512m myapp

# 2. 监控内存使用
docker stats

# 3. 检查应用内存泄漏
```

**问题：构建缓存失效**
```dockerfile
# 解决方案：优化 Dockerfile 指令顺序
# 将不常变化的指令放前面
FROM node:16-alpine
WORKDIR /app

# 先复制依赖文件（变化少）
COPY package*.json ./
RUN npm ci

# 再复制源码（变化多）
COPY . .
RUN npm run build
```

---

## 附录：常用命令速查表

```bash
# ========== 镜像操作 ==========
docker images                    # 列出镜像
docker pull <image>              # 拉取镜像
docker push <image>              # 推送镜像
docker rmi <image>               # 删除镜像
docker build -t <name> .         # 构建镜像
docker save -o file.tar <image>  # 导出镜像
docker load -i file.tar          # 导入镜像

# ========== 容器操作 ==========
docker ps                        # 列出运行中容器
docker ps -a                     # 列出所有容器
docker run -d <image>            # 后台运行容器
docker start/stop/restart <c>    # 启动/停止/重启
docker rm <container>            # 删除容器
docker logs <container>          # 查看日志
docker exec -it <c> bash         # 进入容器

# ========== 网络操作 ==========
docker network ls                # 列出网络
docker network create <name>     # 创建网络
docker network connect <n> <c>   # 连接容器到网络

# ========== 数据卷操作 ==========
docker volume ls                 # 列出卷
docker volume create <name>      # 创建卷
docker volume rm <name>          # 删除卷

# ========== 系统操作 ==========
docker system df                 # 查看磁盘使用
docker system prune              # 清理未使用资源
docker info                      # 系统信息
docker version                   # 版本信息

# ========== Compose 操作 ==========
docker-compose up -d             # 启动服务
docker-compose down              # 停止并删除
docker-compose logs              # 查看日志
docker-compose ps                # 查看状态
docker-compose exec <s> bash     # 进入服务容器
```

---

> 💡 **学习建议**：
> 1. 从基础命令开始，多动手实践
> 2. 理解镜像分层机制，优化 Dockerfile
> 3. 掌握 Docker Compose，提升开发效率
> 4. 关注安全最佳实践，养成良好习惯
> 5. 遇到问题先看日志：`docker logs` 是你的好朋友
