# PostgreSQL 完全指南

> PostgreSQL 是一个功能强大的开源对象关系型数据库系统，以可靠性、功能健壮性和性能著称
> 本笔记基于 PostgreSQL 14，涵盖从入门到高级的完整知识体系

---

## 目录

1. [基础概念](#1-基础概念)
2. [安装与配置](#2-安装与配置)
3. [数据库与表操作](#3-数据库与表操作)
4. [数据类型](#4-数据类型)
5. [CRUD 操作](#5-crud-操作)
6. [约束与索引](#6-约束与索引)
7. [高级查询](#7-高级查询)
8. [函数与存储过程](#8-函数与存储过程)
9. [触发器](#9-触发器)
10. [视图与物化视图](#10-视图与物化视图)
11. [事务与并发控制](#11-事务与并发控制)
12. [JSON 操作](#12-json-操作)
13. [全文搜索](#13-全文搜索)
14. [分区表](#14-分区表)
15. [性能优化](#15-性能优化)
16. [备份与恢复](#16-备份与恢复)
17. [安全管理](#17-安全管理)
18. [常见错误与解决方案](#18-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 PostgreSQL？

PostgreSQL（简称 PG）是世界上最先进的开源关系型数据库。它起源于 1986 年加州大学伯克利分校的 POSTGRES 项目，经过 30 多年的发展，已成为企业级应用的首选数据库之一。

**核心特点：**
- **ACID 完全支持**：保证数据的原子性、一致性、隔离性和持久性
- **丰富的数据类型**：支持 JSON、数组、范围类型、几何类型等
- **强大的扩展性**：支持自定义函数、数据类型、操作符
- **高级功能**：全文搜索、地理信息处理（PostGIS）、时序数据等
- **开源免费**：BSD 许可证，可自由使用和修改

### 1.2 PostgreSQL vs MySQL

| 特性 | PostgreSQL | MySQL |
|------|------------|-------|
| 许可证 | BSD（更自由） | GPL/商业双许可 |
| ACID 支持 | 完全支持 | InnoDB 引擎支持 |
| JSON 支持 | 原生 JSONB（更强大） | JSON 类型 |
| 全文搜索 | 内置支持 | 需要插件 |
| 复杂查询 | 更优秀 | 简单查询更快 |
| 扩展性 | 非常强 | 一般 |
| 学习曲线 | 稍陡峭 | 较平缓 |

### 1.3 核心架构

PostgreSQL 采用客户端/服务器模型，主要组件包括：

```
┌─────────────────────────────────────────────────────────┐
│                    客户端应用                            │
│         (psql, pgAdmin, 应用程序等)                      │
└─────────────────────┬───────────────────────────────────┘
                      │ TCP/IP 或 Unix Socket
┌─────────────────────▼───────────────────────────────────┐
│                  Postmaster 进程                         │
│            (主进程，负责监听和派生)                        │
└─────────────────────┬───────────────────────────────────┘
                      │
    ┌─────────────────┼─────────────────┐
    ▼                 ▼                 ▼
┌────────┐      ┌────────┐       ┌────────────┐
│Backend │      │Backend │       │ 后台进程    │
│ 进程1  │      │ 进程2  │       │(WAL/Vacuum) │
└────────┘      └────────┘       └────────────┘
    │                 │                 │
    └─────────────────┼─────────────────┘
                      ▼
            ┌─────────────────┐
            │   共享内存       │
            │ (缓冲区/锁等)    │
            └─────────────────┘
                      │
                      ▼
            ┌─────────────────┐
            │   数据文件       │
            │ (表/索引/WAL)   │
            └─────────────────┘
```

**关键进程说明：**
- **Postmaster**：主进程，负责监听连接请求，为每个客户端派生独立的 Backend 进程
- **Backend**：处理客户端的 SQL 请求，每个连接对应一个进程
- **Background Writer**：将脏页写入磁盘
- **WAL Writer**：写入预写日志，保证数据持久性
- **Autovacuum**：自动清理死元组，维护表健康

---

## 2. 安装与配置

### 2.1 各平台安装

**Ubuntu/Debian：**
```bash
# 添加官方仓库
sudo sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -

# 安装 PostgreSQL 14
sudo apt update
sudo apt install postgresql-14 postgresql-contrib-14

# 启动服务
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

**CentOS/RHEL：**
```bash
# 安装官方仓库
sudo dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-8-x86_64/pgdg-redhat-repo-latest.noarch.rpm

# 禁用内置模块
sudo dnf -qy module disable postgresql

# 安装 PostgreSQL 14
sudo dnf install -y postgresql14-server postgresql14-contrib

# 初始化数据库
sudo /usr/pgsql-14/bin/postgresql-14-setup initdb

# 启动服务
sudo systemctl start postgresql-14
sudo systemctl enable postgresql-14
```

**Windows：**
1. 从官网下载安装包：https://www.postgresql.org/download/windows/
2. 运行安装程序，按向导完成安装
3. 记住设置的超级用户密码

**Docker（推荐开发环境）：**
```bash
# 拉取镜像
docker pull postgres:14

# 运行容器
docker run -d \
  --name postgres14 \
  -e POSTGRES_PASSWORD=your_password \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_DB=mydb \
  -p 5432:5432 \
  -v pgdata:/var/lib/postgresql/data \
  postgres:14

# 进入容器
docker exec -it postgres14 psql -U postgres
```

### 2.2 初始连接

安装完成后，PostgreSQL 会创建一个名为 `postgres` 的系统用户和同名数据库。

```bash
# Linux 下切换到 postgres 用户
sudo -i -u postgres

# 进入 psql 命令行
psql

# 或者直接一步到位
sudo -u postgres psql
```

**psql 常用命令：**
```sql
-- 查看帮助
\?              -- psql 命令帮助
\h              -- SQL 命令帮助
\h SELECT       -- 查看 SELECT 语法

-- 连接与数据库
\c dbname       -- 切换数据库
\l              -- 列出所有数据库
\dt             -- 列出当前数据库的表
\dt+            -- 列出表的详细信息
\d tablename    -- 查看表结构
\d+ tablename   -- 查看表详细结构（含注释）

-- 用户与权限
\du             -- 列出所有用户/角色
\dp             -- 列出表权限

-- 其他
\timing         -- 开启/关闭执行时间显示
\x              -- 切换扩展显示模式（竖向显示）
\i filename     -- 执行 SQL 文件
\o filename     -- 将输出重定向到文件
\q              -- 退出 psql
```

### 2.3 核心配置文件

PostgreSQL 的配置文件通常位于数据目录下（如 `/var/lib/postgresql/14/main/` 或 `/etc/postgresql/14/main/`）。

**postgresql.conf - 主配置文件：**
```ini
# 连接设置
listen_addresses = '*'          # 监听地址，'*' 表示所有
port = 5432                     # 端口号
max_connections = 100           # 最大连接数

# 内存设置（重要！）
shared_buffers = 256MB          # 共享缓冲区，建议设为内存的 25%
effective_cache_size = 1GB      # 查询优化器估算的可用缓存
work_mem = 4MB                  # 每个操作的工作内存
maintenance_work_mem = 64MB     # 维护操作的内存

# WAL 设置
wal_level = replica             # WAL 级别
max_wal_size = 1GB              # WAL 最大大小
min_wal_size = 80MB             # WAL 最小大小

# 日志设置
logging_collector = on          # 开启日志收集
log_directory = 'log'           # 日志目录
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_statement = 'all'           # 记录所有 SQL（开发环境）
log_min_duration_statement = 1000  # 记录超过 1 秒的慢查询
```

**pg_hba.conf - 客户端认证配置：**

这个文件控制谁可以连接到数据库，以及如何认证。格式为：
```
# TYPE  DATABASE  USER  ADDRESS       METHOD
```

```ini
# 本地连接（Unix socket）
local   all       all                 peer

# IPv4 本地连接
host    all       all   127.0.0.1/32  scram-sha-256

# IPv4 局域网连接
host    all       all   192.168.1.0/24  scram-sha-256

# IPv6 本地连接
host    all       all   ::1/128       scram-sha-256

# 允许所有 IP（生产环境慎用！）
host    all       all   0.0.0.0/0     scram-sha-256
```

**认证方法说明：**
- `trust`：无需密码（仅限本地开发）
- `peer`：使用操作系统用户名认证（仅限本地 socket）
- `scram-sha-256`：推荐的密码认证方式（PG 14 默认）
- `md5`：旧版密码认证
- `reject`：拒绝连接

**修改配置后重载：**
```sql
-- 方法1：SQL 命令
SELECT pg_reload_conf();

-- 方法2：系统命令
sudo systemctl reload postgresql
```

> ⚠️ **注意**：某些参数（如 `shared_buffers`、`max_connections`）修改后需要重启服务才能生效。

---

## 3. 数据库与表操作

### 3.1 数据库管理

**创建数据库：**
```sql
-- 基本创建
CREATE DATABASE mydb;

-- 完整语法
CREATE DATABASE mydb
    WITH 
    OWNER = postgres           -- 所有者
    ENCODING = 'UTF8'          -- 字符编码
    LC_COLLATE = 'en_US.UTF-8' -- 排序规则
    LC_CTYPE = 'en_US.UTF-8'   -- 字符分类
    TABLESPACE = pg_default    -- 表空间
    CONNECTION LIMIT = -1      -- 连接限制，-1 表示无限制
    TEMPLATE = template0;      -- 模板数据库

-- 从现有数据库复制
CREATE DATABASE newdb WITH TEMPLATE existingdb;
```

**修改数据库：**
```sql
-- 重命名（需要断开所有连接）
ALTER DATABASE oldname RENAME TO newname;

-- 修改所有者
ALTER DATABASE mydb OWNER TO newuser;

-- 修改连接限制
ALTER DATABASE mydb CONNECTION LIMIT 50;

-- 设置数据库级别参数
ALTER DATABASE mydb SET timezone TO 'Asia/Shanghai';
```

**删除数据库：**
```sql
-- 删除数据库（必须先断开所有连接）
DROP DATABASE mydb;

-- 如果存在才删除
DROP DATABASE IF EXISTS mydb;

-- 强制断开连接后删除（PG 13+）
DROP DATABASE mydb WITH (FORCE);
```

### 3.2 Schema（模式）

Schema 是数据库内的命名空间，用于组织和隔离数据库对象。可以把它理解为"文件夹"。

```sql
-- 创建 schema
CREATE SCHEMA sales;
CREATE SCHEMA hr AUTHORIZATION hr_admin;  -- 指定所有者

-- 在 schema 中创建表
CREATE TABLE sales.orders (
    id SERIAL PRIMARY KEY,
    amount DECIMAL(10,2)
);

-- 设置搜索路径（决定默认使用哪个 schema）
SET search_path TO sales, public;

-- 查看当前搜索路径
SHOW search_path;

-- 永久设置用户的搜索路径
ALTER USER username SET search_path TO sales, public;

-- 删除 schema
DROP SCHEMA sales;                    -- 必须为空
DROP SCHEMA sales CASCADE;            -- 级联删除所有对象
```

### 3.3 表操作

**创建表：**
```sql
-- 基本创建
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    age INTEGER CHECK (age >= 0 AND age <= 150),
    balance DECIMAL(10,2) DEFAULT 0.00,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 添加表注释（非常推荐！）
COMMENT ON TABLE users IS '用户表，存储系统用户信息';
COMMENT ON COLUMN users.username IS '用户名，唯一标识';
COMMENT ON COLUMN users.password_hash IS '密码哈希值，使用 bcrypt 加密';

-- 创建带外键的表
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    total_amount DECIMAL(10,2) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 创建临时表（会话结束自动删除）
CREATE TEMP TABLE temp_results (
    id INTEGER,
    value TEXT
);

-- 如果不存在才创建
CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    message TEXT
);
```

**修改表结构：**
```sql
-- 添加列
ALTER TABLE users ADD COLUMN phone VARCHAR(20);
ALTER TABLE users ADD COLUMN address TEXT DEFAULT '';

-- 删除列
ALTER TABLE users DROP COLUMN phone;
ALTER TABLE users DROP COLUMN IF EXISTS phone;  -- 安全删除

-- 修改列类型
ALTER TABLE users ALTER COLUMN username TYPE VARCHAR(100);

-- 修改列类型（需要转换）
ALTER TABLE users ALTER COLUMN age TYPE BIGINT USING age::BIGINT;

-- 设置/删除默认值
ALTER TABLE users ALTER COLUMN is_active SET DEFAULT false;
ALTER TABLE users ALTER COLUMN is_active DROP DEFAULT;

-- 设置/删除 NOT NULL
ALTER TABLE users ALTER COLUMN email SET NOT NULL;
ALTER TABLE users ALTER COLUMN email DROP NOT NULL;

-- 重命名列
ALTER TABLE users RENAME COLUMN username TO user_name;

-- 重命名表
ALTER TABLE users RENAME TO app_users;

-- 修改表所有者
ALTER TABLE users OWNER TO new_owner;
```

**删除表：**
```sql
-- 删除表
DROP TABLE users;

-- 安全删除
DROP TABLE IF EXISTS users;

-- 级联删除（同时删除依赖对象）
DROP TABLE users CASCADE;

-- 清空表数据（保留结构）
TRUNCATE TABLE users;
TRUNCATE TABLE users RESTART IDENTITY;  -- 重置序列
TRUNCATE TABLE users, orders CASCADE;   -- 级联清空
```

---

## 4. 数据类型

PostgreSQL 提供了丰富的数据类型，选择合适的类型对性能和存储都很重要。

### 4.1 数值类型

```sql
-- 整数类型
SMALLINT        -- 2 字节，-32768 到 32767
INTEGER / INT   -- 4 字节，-2147483648 到 2147483647
BIGINT          -- 8 字节，-9223372036854775808 到 9223372036854775807

-- 自增类型（本质是整数 + 序列）
SMALLSERIAL     -- 2 字节自增
SERIAL          -- 4 字节自增（最常用）
BIGSERIAL       -- 8 字节自增

-- 精确小数（金融计算必用！）
DECIMAL(p,s)    -- p 是总位数，s 是小数位数
NUMERIC(p,s)    -- 与 DECIMAL 相同

-- 浮点数（有精度损失，慎用于金融）
REAL            -- 4 字节，6 位精度
DOUBLE PRECISION -- 8 字节，15 位精度

-- 示例
CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    quantity INTEGER NOT NULL DEFAULT 0,
    price DECIMAL(10,2) NOT NULL,      -- 最大 99999999.99
    weight REAL,
    rating DOUBLE PRECISION
);
```

> ⚠️ **重要**：涉及金钱的字段一定要用 `DECIMAL` 或 `NUMERIC`，不要用 `REAL` 或 `DOUBLE PRECISION`！

### 4.2 字符类型

```sql
-- 定长字符串（不足会用空格填充）
CHAR(n)         -- 固定 n 个字符

-- 变长字符串（最常用）
VARCHAR(n)      -- 最多 n 个字符
VARCHAR         -- 无限制（等同于 TEXT）

-- 无限长度文本
TEXT            -- 无长度限制

-- 示例与选择建议
CREATE TABLE articles (
    id SERIAL PRIMARY KEY,
    code CHAR(10),           -- 固定长度编码
    title VARCHAR(200),      -- 有明确长度限制的字段
    content TEXT,            -- 长文本内容
    summary TEXT             -- VARCHAR 和 TEXT 性能相同
);
```

**选择建议：**
- `CHAR(n)`：仅用于固定长度的数据（如国家代码 'CN'）
- `VARCHAR(n)`：有明确长度限制时使用
- `TEXT`：长度不确定或很长的文本

> 💡 **提示**：在 PostgreSQL 中，`VARCHAR` 和 `TEXT` 的性能几乎相同，`VARCHAR(n)` 的 n 只是约束，不影响存储。

### 4.3 日期时间类型

```sql
-- 日期类型
DATE            -- 日期，4 字节，'2024-01-15'

-- 时间类型
TIME            -- 时间（无时区），8 字节，'14:30:00'
TIME WITH TIME ZONE  -- 时间（带时区），12 字节

-- 日期时间类型
TIMESTAMP       -- 日期时间（无时区），8 字节
TIMESTAMPTZ     -- 日期时间（带时区），8 字节，推荐使用！

-- 时间间隔
INTERVAL        -- 时间间隔，'1 year 2 months 3 days'

-- 示例
CREATE TABLE events (
    id SERIAL PRIMARY KEY,
    event_date DATE NOT NULL,
    start_time TIME,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    duration INTERVAL
);

-- 插入示例
INSERT INTO events (event_date, start_time, duration) 
VALUES ('2024-06-15', '09:00:00', '2 hours 30 minutes');

-- 日期时间函数
SELECT 
    CURRENT_DATE,                    -- 当前日期
    CURRENT_TIME,                    -- 当前时间
    CURRENT_TIMESTAMP,               -- 当前时间戳
    NOW(),                           -- 同上
    EXTRACT(YEAR FROM NOW()),        -- 提取年份
    DATE_TRUNC('month', NOW()),      -- 截断到月
    NOW() + INTERVAL '1 day',        -- 加一天
    AGE(NOW(), '2000-01-01');        -- 计算年龄
```

> ⚠️ **最佳实践**：始终使用 `TIMESTAMPTZ`（带时区）存储时间戳，避免时区问题！

### 4.4 布尔类型

```sql
BOOLEAN / BOOL  -- true, false, null

-- 有效的布尔值
-- TRUE: true, 't', 'true', 'y', 'yes', 'on', '1'
-- FALSE: false, 'f', 'false', 'n', 'no', 'off', '0'

CREATE TABLE settings (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50),
    is_enabled BOOLEAN DEFAULT false
);

-- 查询示例
SELECT * FROM settings WHERE is_enabled;        -- 等同于 is_enabled = true
SELECT * FROM settings WHERE NOT is_enabled;    -- 等同于 is_enabled = false
SELECT * FROM settings WHERE is_enabled IS NULL;
```

### 4.5 UUID 类型

UUID（通用唯一标识符）是分布式系统中常用的主键类型。

```sql
-- 启用 uuid 扩展
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 或使用 PG 14 内置的 gen_random_uuid()
CREATE TABLE documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(200)
);

-- 插入
INSERT INTO documents (title) VALUES ('My Document');
INSERT INTO documents (id, title) VALUES ('550e8400-e29b-41d4-a716-446655440000', 'Another Doc');

-- 使用 uuid-ossp 扩展的函数
SELECT uuid_generate_v4();  -- 随机 UUID
SELECT uuid_generate_v1();  -- 基于时间的 UUID
```

**UUID vs SERIAL 作为主键：**
| 特性 | UUID | SERIAL |
|------|------|--------|
| 唯一性 | 全局唯一 | 仅表内唯一 |
| 分布式 | 适合 | 需要额外处理 |
| 存储空间 | 16 字节 | 4/8 字节 |
| 索引性能 | 较差（随机） | 较好（顺序） |
| 可预测性 | 不可预测 | 可预测 |

### 4.6 数组类型

PostgreSQL 原生支持数组，这是它的一大特色。

```sql
-- 定义数组列
CREATE TABLE posts (
    id SERIAL PRIMARY KEY,
    title VARCHAR(200),
    tags TEXT[],                    -- 文本数组
    scores INTEGER[],               -- 整数数组
    matrix INTEGER[][]              -- 二维数组
);

-- 插入数组数据
INSERT INTO posts (title, tags, scores) VALUES 
    ('PostgreSQL 入门', ARRAY['database', 'postgresql', 'tutorial'], ARRAY[95, 88, 92]),
    ('Vue3 教程', '{vue,frontend,javascript}', '{90,85}');  -- 另一种语法

-- 数组查询
SELECT * FROM posts WHERE 'postgresql' = ANY(tags);     -- 包含某元素
SELECT * FROM posts WHERE tags @> ARRAY['database'];    -- 包含子数组
SELECT * FROM posts WHERE tags && ARRAY['vue', 'react']; -- 有交集

-- 数组操作
SELECT 
    tags[1],                        -- 访问第一个元素（从 1 开始！）
    tags[1:2],                      -- 切片
    array_length(tags, 1),          -- 数组长度
    array_append(tags, 'new'),      -- 追加元素
    array_remove(tags, 'old'),      -- 删除元素
    array_cat(tags, ARRAY['a','b']), -- 连接数组
    unnest(tags)                    -- 展开为行
FROM posts;

-- 更新数组
UPDATE posts SET tags[1] = 'DB' WHERE id = 1;
UPDATE posts SET tags = array_append(tags, 'advanced') WHERE id = 1;
```

### 4.7 JSON 和 JSONB 类型

PostgreSQL 提供两种 JSON 类型：`JSON` 和 `JSONB`。

```sql
-- JSON vs JSONB
-- JSON: 存储原始文本，保留格式和顺序，写入快
-- JSONB: 二进制存储，支持索引，查询快（推荐！）

CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    attributes JSONB,               -- 推荐使用 JSONB
    raw_data JSON                   -- 需要保留原始格式时用 JSON
);

-- 插入 JSON 数据
INSERT INTO products (name, attributes) VALUES 
    ('iPhone 15', '{"color": "black", "storage": 256, "features": ["5G", "USB-C"]}'),
    ('MacBook Pro', '{"color": "silver", "ram": 16, "cpu": "M3"}');

-- JSON 查询操作符
SELECT 
    attributes->'color',            -- 获取 JSON 对象（返回 JSON）
    attributes->>'color',           -- 获取文本值（返回 TEXT）
    attributes->'features'->0,      -- 获取数组元素
    attributes#>'{features,0}',     -- 路径访问
    attributes#>>'{features,0}'     -- 路径访问（返回文本）
FROM products;

-- JSONB 特有操作符
SELECT * FROM products WHERE attributes ? 'color';           -- 存在键
SELECT * FROM products WHERE attributes ?| ARRAY['color','size']; -- 存在任一键
SELECT * FROM products WHERE attributes ?& ARRAY['color','storage']; -- 存在所有键
SELECT * FROM products WHERE attributes @> '{"color":"black"}';  -- 包含

-- JSON 函数
SELECT 
    jsonb_typeof(attributes),                    -- 类型
    jsonb_object_keys(attributes),               -- 所有键
    jsonb_each(attributes),                      -- 展开为键值对
    jsonb_array_elements(attributes->'features'), -- 展开数组
    jsonb_set(attributes, '{color}', '"red"'),   -- 设置值
    attributes || '{"new_key": "value"}',        -- 合并
    attributes - 'color'                         -- 删除键
FROM products;

-- 为 JSONB 创建索引（重要！）
CREATE INDEX idx_products_attributes ON products USING GIN (attributes);
CREATE INDEX idx_products_color ON products USING BTREE ((attributes->>'color'));
```

### 4.8 其他常用类型

```sql
-- 网络地址类型
INET            -- IP 地址（支持 IPv4 和 IPv6）
CIDR            -- 网络地址
MACADDR         -- MAC 地址

CREATE TABLE servers (
    id SERIAL PRIMARY KEY,
    ip_address INET,
    network CIDR
);

INSERT INTO servers (ip_address, network) VALUES 
    ('192.168.1.100', '192.168.1.0/24');

SELECT * FROM servers WHERE ip_address << '192.168.1.0/24';  -- 在网段内

-- 范围类型
INT4RANGE       -- 整数范围
INT8RANGE       -- 大整数范围
NUMRANGE        -- 数值范围
TSRANGE         -- 时间戳范围
DATERANGE       -- 日期范围

CREATE TABLE reservations (
    id SERIAL PRIMARY KEY,
    room_id INTEGER,
    during DATERANGE,
    EXCLUDE USING GIST (room_id WITH =, during WITH &&)  -- 防止重叠
);

INSERT INTO reservations (room_id, during) VALUES 
    (1, '[2024-01-01, 2024-01-05)');  -- [ 包含，) 不包含

-- 枚举类型
CREATE TYPE mood AS ENUM ('sad', 'ok', 'happy');

CREATE TABLE person (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50),
    current_mood mood
);

INSERT INTO person (name, current_mood) VALUES ('John', 'happy');
```

---

## 5. CRUD 操作

### 5.1 INSERT（插入）

```sql
-- 基本插入
INSERT INTO users (username, email, password_hash) 
VALUES ('john', 'john@example.com', 'hash123');

-- 插入多行
INSERT INTO users (username, email, password_hash) VALUES 
    ('alice', 'alice@example.com', 'hash456'),
    ('bob', 'bob@example.com', 'hash789'),
    ('charlie', 'charlie@example.com', 'hash012');

-- 插入并返回数据（非常有用！）
INSERT INTO users (username, email, password_hash) 
VALUES ('david', 'david@example.com', 'hash345')
RETURNING id, username, created_at;

-- 从查询结果插入
INSERT INTO user_backup (id, username, email)
SELECT id, username, email FROM users WHERE created_at < '2024-01-01';

-- 插入或忽略冲突（UPSERT）
INSERT INTO users (username, email, password_hash) 
VALUES ('john', 'john_new@example.com', 'newhash')
ON CONFLICT (username) DO NOTHING;

-- 插入或更新（UPSERT）
INSERT INTO users (username, email, password_hash) 
VALUES ('john', 'john_new@example.com', 'newhash')
ON CONFLICT (username) 
DO UPDATE SET 
    email = EXCLUDED.email,
    password_hash = EXCLUDED.password_hash,
    updated_at = CURRENT_TIMESTAMP;

-- 使用 CTE 插入
WITH new_user AS (
    INSERT INTO users (username, email, password_hash)
    VALUES ('eve', 'eve@example.com', 'hash999')
    RETURNING id
)
INSERT INTO user_profiles (user_id, bio)
SELECT id, 'New user bio' FROM new_user;
```

### 5.2 SELECT（查询）

```sql
-- 基本查询
SELECT * FROM users;
SELECT id, username, email FROM users;

-- 条件查询
SELECT * FROM users WHERE is_active = true;
SELECT * FROM users WHERE age BETWEEN 18 AND 30;
SELECT * FROM users WHERE username IN ('john', 'alice', 'bob');
SELECT * FROM users WHERE email LIKE '%@gmail.com';
SELECT * FROM users WHERE email ILIKE '%@GMAIL.COM';  -- 不区分大小写

-- NULL 处理
SELECT * FROM users WHERE phone IS NULL;
SELECT * FROM users WHERE phone IS NOT NULL;
SELECT COALESCE(phone, 'N/A') AS phone FROM users;  -- NULL 替换
SELECT NULLIF(status, 'unknown') FROM users;        -- 相等则返回 NULL

-- 排序
SELECT * FROM users ORDER BY created_at DESC;
SELECT * FROM users ORDER BY age ASC NULLS LAST;    -- NULL 放最后
SELECT * FROM users ORDER BY is_active DESC, username ASC;

-- 分页
SELECT * FROM users ORDER BY id LIMIT 10 OFFSET 20;  -- 第 3 页，每页 10 条

-- 更高效的分页（大数据量时）
SELECT * FROM users 
WHERE id > 1000  -- 上一页最后一条的 id
ORDER BY id 
LIMIT 10;

-- 去重
SELECT DISTINCT status FROM orders;
SELECT DISTINCT ON (user_id) * FROM orders ORDER BY user_id, created_at DESC;

-- 聚合函数
SELECT 
    COUNT(*) AS total_users,
    COUNT(DISTINCT status) AS status_count,
    AVG(age) AS avg_age,
    MAX(age) AS max_age,
    MIN(age) AS min_age,
    SUM(balance) AS total_balance
FROM users;

-- 分组
SELECT 
    status,
    COUNT(*) AS count,
    AVG(total_amount) AS avg_amount
FROM orders
GROUP BY status
HAVING COUNT(*) > 10  -- 分组后过滤
ORDER BY count DESC;

-- 字符串函数
SELECT 
    UPPER(username),
    LOWER(email),
    LENGTH(username),
    CONCAT(first_name, ' ', last_name),
    first_name || ' ' || last_name,     -- 连接
    SUBSTRING(email FROM 1 FOR 5),
    TRIM(username),
    REPLACE(email, '@', ' AT '),
    SPLIT_PART(email, '@', 1)           -- 分割取部分
FROM users;
```

### 5.3 UPDATE（更新）

```sql
-- 基本更新
UPDATE users SET is_active = false WHERE id = 1;

-- 更新多列
UPDATE users 
SET 
    email = 'new@example.com',
    updated_at = CURRENT_TIMESTAMP
WHERE id = 1;

-- 基于计算更新
UPDATE products SET price = price * 1.1 WHERE category = 'electronics';

-- 使用子查询更新
UPDATE orders 
SET status = 'vip_order'
WHERE user_id IN (SELECT id FROM users WHERE is_vip = true);

-- 使用 FROM 子句更新（PostgreSQL 特有）
UPDATE orders o
SET status = 'vip_order'
FROM users u
WHERE o.user_id = u.id AND u.is_vip = true;

-- 更新并返回
UPDATE users 
SET balance = balance + 100 
WHERE id = 1
RETURNING id, username, balance;

-- 条件更新
UPDATE users 
SET status = CASE 
    WHEN age < 18 THEN 'minor'
    WHEN age < 60 THEN 'adult'
    ELSE 'senior'
END;

-- 使用 CTE 更新
WITH inactive_users AS (
    SELECT id FROM users 
    WHERE last_login < CURRENT_DATE - INTERVAL '90 days'
)
UPDATE users 
SET is_active = false 
WHERE id IN (SELECT id FROM inactive_users);
```

### 5.4 DELETE（删除）

```sql
-- 基本删除
DELETE FROM users WHERE id = 1;

-- 删除多条
DELETE FROM users WHERE is_active = false;

-- 删除并返回
DELETE FROM users WHERE id = 1 RETURNING *;

-- 使用子查询删除
DELETE FROM orders 
WHERE user_id IN (SELECT id FROM users WHERE is_deleted = true);

-- 使用 USING 子句删除（PostgreSQL 特有）
DELETE FROM orders o
USING users u
WHERE o.user_id = u.id AND u.is_deleted = true;

-- 删除所有数据（保留表结构）
DELETE FROM logs;  -- 慢，会记录日志
TRUNCATE TABLE logs;  -- 快，不记录日志

-- 使用 CTE 删除
WITH old_orders AS (
    SELECT id FROM orders 
    WHERE created_at < CURRENT_DATE - INTERVAL '1 year'
)
DELETE FROM order_items 
WHERE order_id IN (SELECT id FROM old_orders);
```

> ⚠️ **警告**：`DELETE` 和 `UPDATE` 不带 `WHERE` 会影响所有行！生产环境务必先用 `SELECT` 验证条件。

---

## 6. 约束与索引

### 6.1 约束类型

约束用于保证数据的完整性和一致性。

```sql
-- 主键约束
CREATE TABLE users (
    id SERIAL PRIMARY KEY,  -- 单列主键
    -- 或
    id INTEGER,
    CONSTRAINT pk_users PRIMARY KEY (id)
);

-- 复合主键
CREATE TABLE order_items (
    order_id INTEGER,
    product_id INTEGER,
    quantity INTEGER,
    PRIMARY KEY (order_id, product_id)
);

-- 唯一约束
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(100) UNIQUE,
    -- 或
    CONSTRAINT uq_users_email UNIQUE (email)
);

-- 复合唯一约束
ALTER TABLE users ADD CONSTRAINT uq_name_email UNIQUE (first_name, last_name, email);

-- 非空约束
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL
);

-- 检查约束
CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    price DECIMAL(10,2) CHECK (price > 0),
    quantity INTEGER CHECK (quantity >= 0),
    -- 复杂检查
    CONSTRAINT chk_price_quantity CHECK (price * quantity < 1000000)
);

-- 外键约束
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    CONSTRAINT fk_orders_user 
        FOREIGN KEY (user_id) 
        REFERENCES users(id)
        ON DELETE CASCADE      -- 删除用户时级联删除订单
        ON UPDATE CASCADE      -- 更新用户 ID 时级联更新
);

-- 外键动作选项
-- ON DELETE/UPDATE:
--   CASCADE: 级联操作
--   SET NULL: 设为 NULL
--   SET DEFAULT: 设为默认值
--   RESTRICT: 阻止操作（默认）
--   NO ACTION: 延迟检查，事务结束时阻止

-- 默认值约束
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 排除约束（防止重叠）
CREATE EXTENSION IF NOT EXISTS btree_gist;

CREATE TABLE room_reservations (
    id SERIAL PRIMARY KEY,
    room_id INTEGER,
    during TSRANGE,
    EXCLUDE USING GIST (room_id WITH =, during WITH &&)
);
```

**管理约束：**
```sql
-- 添加约束
ALTER TABLE users ADD CONSTRAINT chk_age CHECK (age >= 0);
ALTER TABLE orders ADD CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id);

-- 删除约束
ALTER TABLE users DROP CONSTRAINT chk_age;

-- 临时禁用约束（导入数据时有用）
ALTER TABLE orders DISABLE TRIGGER ALL;  -- 禁用所有触发器和外键检查
-- 导入数据...
ALTER TABLE orders ENABLE TRIGGER ALL;

-- 验证现有数据
ALTER TABLE users VALIDATE CONSTRAINT chk_age;
```

### 6.2 索引

索引是提升查询性能的关键，但也会增加写入开销和存储空间。

**B-Tree 索引（默认）：**
```sql
-- 创建索引
CREATE INDEX idx_users_email ON users(email);

-- 唯一索引
CREATE UNIQUE INDEX idx_users_username ON users(username);

-- 复合索引（注意列顺序！）
CREATE INDEX idx_orders_user_date ON orders(user_id, created_at DESC);

-- 部分索引（只索引部分数据）
CREATE INDEX idx_active_users ON users(email) WHERE is_active = true;

-- 表达式索引
CREATE INDEX idx_users_lower_email ON users(LOWER(email));
CREATE INDEX idx_orders_year ON orders(EXTRACT(YEAR FROM created_at));

-- 并发创建索引（不锁表，生产环境推荐）
CREATE INDEX CONCURRENTLY idx_users_phone ON users(phone);
```

**其他索引类型：**
```sql
-- Hash 索引（仅等值查询）
CREATE INDEX idx_users_hash_email ON users USING HASH (email);

-- GIN 索引（全文搜索、数组、JSONB）
CREATE INDEX idx_posts_tags ON posts USING GIN (tags);
CREATE INDEX idx_products_attrs ON products USING GIN (attributes);
CREATE INDEX idx_articles_search ON articles USING GIN (to_tsvector('english', content));

-- GiST 索引（几何、范围、全文搜索）
CREATE INDEX idx_locations_point ON locations USING GIST (coordinates);
CREATE INDEX idx_reservations_during ON reservations USING GIST (during);

-- BRIN 索引（大表、有序数据）
CREATE INDEX idx_logs_created ON logs USING BRIN (created_at);
```

**索引管理：**
```sql
-- 查看表的索引
\di+ tablename
SELECT * FROM pg_indexes WHERE tablename = 'users';

-- 查看索引大小
SELECT 
    indexrelname AS index_name,
    pg_size_pretty(pg_relation_size(indexrelid)) AS size
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
ORDER BY pg_relation_size(indexrelid) DESC;

-- 查看索引使用情况
SELECT 
    indexrelname,
    idx_scan,           -- 索引扫描次数
    idx_tup_read,       -- 通过索引读取的行数
    idx_tup_fetch       -- 通过索引获取的行数
FROM pg_stat_user_indexes
WHERE schemaname = 'public';

-- 删除索引
DROP INDEX idx_users_email;
DROP INDEX CONCURRENTLY idx_users_email;  -- 不锁表

-- 重建索引
REINDEX INDEX idx_users_email;
REINDEX TABLE users;
REINDEX DATABASE mydb;
```

**索引最佳实践：**
```sql
-- 1. 为外键创建索引
CREATE INDEX idx_orders_user_id ON orders(user_id);

-- 2. 为常用查询条件创建索引
CREATE INDEX idx_orders_status ON orders(status) WHERE status != 'completed';

-- 3. 复合索引遵循最左前缀原则
-- 索引 (a, b, c) 可用于: WHERE a=1, WHERE a=1 AND b=2, WHERE a=1 AND b=2 AND c=3
-- 不能用于: WHERE b=2, WHERE c=3

-- 4. 覆盖索引（包含查询所需的所有列）
CREATE INDEX idx_users_covering ON users(status) INCLUDE (username, email);

-- 5. 定期分析表以更新统计信息
ANALYZE users;
```

---

## 7. 高级查询

### 7.1 JOIN 连接

```sql
-- 准备示例数据
CREATE TABLE departments (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50)
);

CREATE TABLE employees (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50),
    department_id INTEGER REFERENCES departments(id),
    salary DECIMAL(10,2)
);

-- INNER JOIN（内连接，只返回匹配的行）
SELECT e.name, d.name AS department
FROM employees e
INNER JOIN departments d ON e.department_id = d.id;

-- LEFT JOIN（左连接，返回左表所有行）
SELECT e.name, d.name AS department
FROM employees e
LEFT JOIN departments d ON e.department_id = d.id;

-- RIGHT JOIN（右连接，返回右表所有行）
SELECT e.name, d.name AS department
FROM employees e
RIGHT JOIN departments d ON e.department_id = d.id;

-- FULL OUTER JOIN（全外连接，返回两表所有行）
SELECT e.name, d.name AS department
FROM employees e
FULL OUTER JOIN departments d ON e.department_id = d.id;

-- CROSS JOIN（笛卡尔积）
SELECT e.name, d.name
FROM employees e
CROSS JOIN departments d;

-- 自连接
SELECT e1.name AS employee, e2.name AS manager
FROM employees e1
LEFT JOIN employees e2 ON e1.manager_id = e2.id;

-- 多表连接
SELECT 
    o.id AS order_id,
    u.username,
    p.name AS product,
    oi.quantity
FROM orders o
JOIN users u ON o.user_id = u.id
JOIN order_items oi ON o.id = oi.order_id
JOIN products p ON oi.product_id = p.id;

-- LATERAL JOIN（相关子查询作为表）
SELECT d.name, top_emp.name, top_emp.salary
FROM departments d
LEFT JOIN LATERAL (
    SELECT name, salary
    FROM employees
    WHERE department_id = d.id
    ORDER BY salary DESC
    LIMIT 3
) top_emp ON true;
```

### 7.2 子查询

```sql
-- 标量子查询（返回单个值）
SELECT 
    name,
    salary,
    (SELECT AVG(salary) FROM employees) AS avg_salary
FROM employees;

-- WHERE 中的子查询
SELECT * FROM employees
WHERE salary > (SELECT AVG(salary) FROM employees);

SELECT * FROM employees
WHERE department_id IN (SELECT id FROM departments WHERE name LIKE 'Sales%');

-- EXISTS 子查询
SELECT * FROM departments d
WHERE EXISTS (
    SELECT 1 FROM employees e WHERE e.department_id = d.id
);

-- NOT EXISTS
SELECT * FROM departments d
WHERE NOT EXISTS (
    SELECT 1 FROM employees e WHERE e.department_id = d.id
);

-- FROM 中的子查询（派生表）
SELECT dept_name, avg_salary
FROM (
    SELECT d.name AS dept_name, AVG(e.salary) AS avg_salary
    FROM departments d
    JOIN employees e ON d.id = e.department_id
    GROUP BY d.name
) AS dept_stats
WHERE avg_salary > 50000;

-- ANY/ALL
SELECT * FROM employees
WHERE salary > ANY (SELECT salary FROM employees WHERE department_id = 1);

SELECT * FROM employees
WHERE salary > ALL (SELECT salary FROM employees WHERE department_id = 1);
```

### 7.3 CTE（公共表表达式）

CTE 使复杂查询更易读、更易维护，还支持递归查询。

```sql
-- 基本 CTE
WITH active_users AS (
    SELECT * FROM users WHERE is_active = true
),
recent_orders AS (
    SELECT * FROM orders WHERE created_at > CURRENT_DATE - INTERVAL '30 days'
)
SELECT u.username, COUNT(o.id) AS order_count
FROM active_users u
LEFT JOIN recent_orders o ON u.id = o.user_id
GROUP BY u.username;

-- 多个 CTE
WITH 
monthly_sales AS (
    SELECT 
        DATE_TRUNC('month', created_at) AS month,
        SUM(total_amount) AS total
    FROM orders
    GROUP BY DATE_TRUNC('month', created_at)
),
avg_sales AS (
    SELECT AVG(total) AS avg_total FROM monthly_sales
)
SELECT 
    ms.month,
    ms.total,
    a.avg_total,
    ms.total - a.avg_total AS diff
FROM monthly_sales ms, avg_sales a;

-- 递归 CTE（处理层级数据）
-- 示例：组织架构树
CREATE TABLE org_chart (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50),
    parent_id INTEGER REFERENCES org_chart(id)
);

INSERT INTO org_chart (name, parent_id) VALUES
    ('CEO', NULL),
    ('CTO', 1),
    ('CFO', 1),
    ('Dev Manager', 2),
    ('Developer 1', 4),
    ('Developer 2', 4);

-- 查询某人的所有下属
WITH RECURSIVE subordinates AS (
    -- 基础查询（锚点）
    SELECT id, name, parent_id, 1 AS level
    FROM org_chart
    WHERE name = 'CEO'
    
    UNION ALL
    
    -- 递归查询
    SELECT o.id, o.name, o.parent_id, s.level + 1
    FROM org_chart o
    INNER JOIN subordinates s ON o.parent_id = s.id
)
SELECT * FROM subordinates;

-- 查询某人的所有上级（向上遍历）
WITH RECURSIVE managers AS (
    SELECT id, name, parent_id, 1 AS level
    FROM org_chart
    WHERE name = 'Developer 1'
    
    UNION ALL
    
    SELECT o.id, o.name, o.parent_id, m.level + 1
    FROM org_chart o
    INNER JOIN managers m ON o.id = m.parent_id
)
SELECT * FROM managers;

-- 生成序列
WITH RECURSIVE numbers AS (
    SELECT 1 AS n
    UNION ALL
    SELECT n + 1 FROM numbers WHERE n < 100
)
SELECT * FROM numbers;

-- 生成日期序列
WITH RECURSIVE dates AS (
    SELECT DATE '2024-01-01' AS date
    UNION ALL
    SELECT date + 1 FROM dates WHERE date < '2024-01-31'
)
SELECT * FROM dates;
```

### 7.4 窗口函数

窗口函数是 PostgreSQL 的强大特性，可以在不改变行数的情况下进行聚合计算。

```sql
-- 基本语法
-- function() OVER (PARTITION BY ... ORDER BY ... ROWS/RANGE ...)

-- ROW_NUMBER：行号
SELECT 
    name,
    department_id,
    salary,
    ROW_NUMBER() OVER (ORDER BY salary DESC) AS rank
FROM employees;

-- 分组行号
SELECT 
    name,
    department_id,
    salary,
    ROW_NUMBER() OVER (PARTITION BY department_id ORDER BY salary DESC) AS dept_rank
FROM employees;

-- RANK 和 DENSE_RANK
SELECT 
    name,
    salary,
    RANK() OVER (ORDER BY salary DESC) AS rank,        -- 有间隔：1,2,2,4
    DENSE_RANK() OVER (ORDER BY salary DESC) AS dense_rank  -- 无间隔：1,2,2,3
FROM employees;

-- NTILE：分桶
SELECT 
    name,
    salary,
    NTILE(4) OVER (ORDER BY salary DESC) AS quartile  -- 分成 4 组
FROM employees;

-- LAG 和 LEAD：访问前后行
SELECT 
    name,
    salary,
    LAG(salary, 1) OVER (ORDER BY salary) AS prev_salary,   -- 前一行
    LEAD(salary, 1) OVER (ORDER BY salary) AS next_salary,  -- 后一行
    salary - LAG(salary, 1) OVER (ORDER BY salary) AS diff
FROM employees;

-- FIRST_VALUE 和 LAST_VALUE
SELECT 
    name,
    department_id,
    salary,
    FIRST_VALUE(name) OVER (PARTITION BY department_id ORDER BY salary DESC) AS top_earner,
    LAST_VALUE(name) OVER (
        PARTITION BY department_id 
        ORDER BY salary DESC
        ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
    ) AS lowest_earner
FROM employees;

-- 聚合函数作为窗口函数
SELECT 
    name,
    department_id,
    salary,
    SUM(salary) OVER (PARTITION BY department_id) AS dept_total,
    AVG(salary) OVER (PARTITION BY department_id) AS dept_avg,
    COUNT(*) OVER (PARTITION BY department_id) AS dept_count,
    salary::DECIMAL / SUM(salary) OVER (PARTITION BY department_id) * 100 AS pct_of_dept
FROM employees;

-- 累计计算
SELECT 
    created_at::DATE AS date,
    total_amount,
    SUM(total_amount) OVER (ORDER BY created_at) AS running_total,
    AVG(total_amount) OVER (ORDER BY created_at ROWS BETWEEN 6 PRECEDING AND CURRENT ROW) AS moving_avg_7day
FROM orders;

-- 窗口帧定义
-- ROWS BETWEEN ... AND ...
--   UNBOUNDED PRECEDING: 分区第一行
--   n PRECEDING: 前 n 行
--   CURRENT ROW: 当前行
--   n FOLLOWING: 后 n 行
--   UNBOUNDED FOLLOWING: 分区最后一行

-- 命名窗口（避免重复）
SELECT 
    name,
    salary,
    ROW_NUMBER() OVER w AS row_num,
    RANK() OVER w AS rank,
    SUM(salary) OVER w AS running_total
FROM employees
WINDOW w AS (ORDER BY salary DESC);
```

### 7.5 集合操作

```sql
-- UNION（合并去重）
SELECT username FROM users
UNION
SELECT name FROM admins;

-- UNION ALL（合并不去重，更快）
SELECT username FROM users
UNION ALL
SELECT name FROM admins;

-- INTERSECT（交集）
SELECT user_id FROM orders
INTERSECT
SELECT user_id FROM reviews;

-- EXCEPT（差集）
SELECT user_id FROM users
EXCEPT
SELECT user_id FROM orders;  -- 没有下过单的用户
```

---

## 8. 函数与存储过程

### 8.1 内置函数

```sql
-- 数学函数
SELECT 
    ABS(-5),                    -- 绝对值: 5
    CEIL(4.2),                  -- 向上取整: 5
    FLOOR(4.8),                 -- 向下取整: 4
    ROUND(4.567, 2),            -- 四舍五入: 4.57
    TRUNC(4.567, 2),            -- 截断: 4.56
    MOD(10, 3),                 -- 取模: 1
    POWER(2, 10),               -- 幂: 1024
    SQRT(16),                   -- 平方根: 4
    RANDOM(),                   -- 随机数 0-1
    GREATEST(1, 5, 3),          -- 最大值: 5
    LEAST(1, 5, 3);             -- 最小值: 1

-- 字符串函数
SELECT 
    LENGTH('Hello'),            -- 长度: 5
    CHAR_LENGTH('你好'),        -- 字符数: 2
    UPPER('hello'),             -- 大写
    LOWER('HELLO'),             -- 小写
    INITCAP('hello world'),     -- 首字母大写
    CONCAT('a', 'b', 'c'),      -- 连接
    CONCAT_WS('-', 'a', 'b'),   -- 带分隔符连接
    SUBSTRING('Hello' FROM 2 FOR 3),  -- 子串: ell
    LEFT('Hello', 2),           -- 左取: He
    RIGHT('Hello', 2),          -- 右取: lo
    TRIM('  hello  '),          -- 去空格
    LTRIM('  hello'),           -- 去左空格
    RTRIM('hello  '),           -- 去右空格
    LPAD('5', 3, '0'),          -- 左填充: 005
    RPAD('5', 3, '0'),          -- 右填充: 500
    REPLACE('hello', 'l', 'L'), -- 替换: heLLo
    REVERSE('hello'),           -- 反转: olleh
    SPLIT_PART('a,b,c', ',', 2), -- 分割取部分: b
    POSITION('l' IN 'hello'),   -- 位置: 3
    REGEXP_REPLACE('hello123', '[0-9]', '', 'g');  -- 正则替换

-- 日期时间函数
SELECT 
    CURRENT_DATE,               -- 当前日期
    CURRENT_TIME,               -- 当前时间
    CURRENT_TIMESTAMP,          -- 当前时间戳
    NOW(),                      -- 同上
    LOCALTIME,                  -- 本地时间
    LOCALTIMESTAMP,             -- 本地时间戳
    EXTRACT(YEAR FROM NOW()),   -- 提取年
    EXTRACT(MONTH FROM NOW()),  -- 提取月
    EXTRACT(DOW FROM NOW()),    -- 星期几 (0=周日)
    DATE_PART('hour', NOW()),   -- 提取小时
    DATE_TRUNC('month', NOW()), -- 截断到月初
    TO_CHAR(NOW(), 'YYYY-MM-DD HH24:MI:SS'),  -- 格式化
    TO_DATE('2024-01-15', 'YYYY-MM-DD'),      -- 字符串转日期
    TO_TIMESTAMP('2024-01-15 10:30:00', 'YYYY-MM-DD HH24:MI:SS'),
    AGE(NOW(), '2000-01-01'),   -- 年龄间隔
    NOW() + INTERVAL '1 day',   -- 加一天
    NOW() - INTERVAL '1 month'; -- 减一月

-- 条件函数
SELECT 
    CASE 
        WHEN score >= 90 THEN 'A'
        WHEN score >= 80 THEN 'B'
        WHEN score >= 60 THEN 'C'
        ELSE 'F'
    END AS grade,
    COALESCE(phone, email, 'N/A'),  -- 返回第一个非 NULL
    NULLIF(a, b),                    -- 相等返回 NULL
    GREATEST(a, b, c),               -- 最大值
    LEAST(a, b, c);                  -- 最小值
```

### 8.2 自定义函数

PostgreSQL 支持多种语言编写函数，最常用的是 SQL 和 PL/pgSQL。

**SQL 函数：**
```sql
-- 简单 SQL 函数
CREATE OR REPLACE FUNCTION get_user_count()
RETURNS INTEGER AS $$
    SELECT COUNT(*)::INTEGER FROM users;
$$ LANGUAGE SQL;

-- 带参数的函数
CREATE OR REPLACE FUNCTION get_user_by_id(user_id INTEGER)
RETURNS TABLE(id INTEGER, username VARCHAR, email VARCHAR) AS $$
    SELECT id, username, email FROM users WHERE id = user_id;
$$ LANGUAGE SQL;

-- 调用
SELECT get_user_count();
SELECT * FROM get_user_by_id(1);
```

**PL/pgSQL 函数：**
```sql
-- 基本函数
CREATE OR REPLACE FUNCTION calculate_tax(amount DECIMAL, rate DECIMAL DEFAULT 0.1)
RETURNS DECIMAL AS $$
BEGIN
    RETURN amount * rate;
END;
$$ LANGUAGE plpgsql;

-- 带变量和逻辑的函数
CREATE OR REPLACE FUNCTION get_user_status(user_id INTEGER)
RETURNS VARCHAR AS $$
DECLARE
    user_record RECORD;
    status VARCHAR;
BEGIN
    -- 查询用户
    SELECT * INTO user_record FROM users WHERE id = user_id;
    
    -- 检查是否存在
    IF NOT FOUND THEN
        RETURN 'NOT_FOUND';
    END IF;
    
    -- 判断状态
    IF user_record.is_active THEN
        IF user_record.is_vip THEN
            status := 'VIP_ACTIVE';
        ELSE
            status := 'ACTIVE';
        END IF;
    ELSE
        status := 'INACTIVE';
    END IF;
    
    RETURN status;
END;
$$ LANGUAGE plpgsql;

-- 返回表的函数
CREATE OR REPLACE FUNCTION get_department_employees(dept_id INTEGER)
RETURNS TABLE(
    employee_id INTEGER,
    employee_name VARCHAR,
    salary DECIMAL
) AS $$
BEGIN
    RETURN QUERY
    SELECT id, name, salary
    FROM employees
    WHERE department_id = dept_id
    ORDER BY salary DESC;
END;
$$ LANGUAGE plpgsql;

-- 使用循环
CREATE OR REPLACE FUNCTION generate_report()
RETURNS TABLE(month DATE, total DECIMAL) AS $$
DECLARE
    current_month DATE;
BEGIN
    current_month := DATE_TRUNC('month', CURRENT_DATE - INTERVAL '11 months');
    
    WHILE current_month <= DATE_TRUNC('month', CURRENT_DATE) LOOP
        RETURN QUERY
        SELECT 
            current_month,
            COALESCE(SUM(total_amount), 0)
        FROM orders
        WHERE DATE_TRUNC('month', created_at) = current_month;
        
        current_month := current_month + INTERVAL '1 month';
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- 异常处理
CREATE OR REPLACE FUNCTION safe_divide(a DECIMAL, b DECIMAL)
RETURNS DECIMAL AS $$
BEGIN
    RETURN a / b;
EXCEPTION
    WHEN division_by_zero THEN
        RAISE NOTICE 'Division by zero, returning NULL';
        RETURN NULL;
    WHEN OTHERS THEN
        RAISE NOTICE 'Error: %', SQLERRM;
        RETURN NULL;
END;
$$ LANGUAGE plpgsql;
```

### 8.3 存储过程（PostgreSQL 11+）

存储过程与函数的主要区别是：存储过程可以管理事务，没有返回值。

```sql
-- 创建存储过程
CREATE OR REPLACE PROCEDURE transfer_money(
    from_account INTEGER,
    to_account INTEGER,
    amount DECIMAL
)
LANGUAGE plpgsql
AS $$
BEGIN
    -- 扣款
    UPDATE accounts SET balance = balance - amount WHERE id = from_account;
    
    -- 检查余额
    IF (SELECT balance FROM accounts WHERE id = from_account) < 0 THEN
        RAISE EXCEPTION 'Insufficient funds';
    END IF;
    
    -- 入账
    UPDATE accounts SET balance = balance + amount WHERE id = to_account;
    
    -- 记录日志
    INSERT INTO transfer_log (from_id, to_id, amount, created_at)
    VALUES (from_account, to_account, amount, NOW());
    
    -- 提交事务
    COMMIT;
END;
$$;

-- 调用存储过程
CALL transfer_money(1, 2, 100.00);

-- 带事务控制的存储过程
CREATE OR REPLACE PROCEDURE batch_process()
LANGUAGE plpgsql
AS $$
DECLARE
    batch_size INTEGER := 1000;
    processed INTEGER := 0;
BEGIN
    LOOP
        -- 处理一批数据
        UPDATE large_table 
        SET processed = true 
        WHERE id IN (
            SELECT id FROM large_table 
            WHERE processed = false 
            LIMIT batch_size
        );
        
        GET DIAGNOSTICS processed = ROW_COUNT;
        
        -- 每批提交一次
        COMMIT;
        
        -- 没有更多数据时退出
        EXIT WHEN processed = 0;
        
        RAISE NOTICE 'Processed % rows', processed;
    END LOOP;
END;
$$;
```

**函数管理：**
```sql
-- 查看函数
\df                              -- 列出所有函数
\df+ function_name               -- 查看函数详情
SELECT prosrc FROM pg_proc WHERE proname = 'function_name';  -- 查看源码

-- 删除函数
DROP FUNCTION function_name(parameter_types);
DROP FUNCTION IF EXISTS function_name(INTEGER);

-- 删除存储过程
DROP PROCEDURE procedure_name(parameter_types);
```

---

## 9. 触发器

触发器是在特定事件（INSERT、UPDATE、DELETE）发生时自动执行的函数。

### 9.1 创建触发器

```sql
-- 首先创建触发器函数（必须返回 TRIGGER）
CREATE OR REPLACE FUNCTION update_modified_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 创建触发器
CREATE TRIGGER trg_users_update_timestamp
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_timestamp();

-- 审计日志触发器
CREATE TABLE audit_log (
    id SERIAL PRIMARY KEY,
    table_name VARCHAR(50),
    operation VARCHAR(10),
    old_data JSONB,
    new_data JSONB,
    changed_by VARCHAR(50),
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE OR REPLACE FUNCTION audit_trigger_func()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO audit_log (table_name, operation, new_data, changed_by)
        VALUES (TG_TABLE_NAME, 'INSERT', to_jsonb(NEW), current_user);
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO audit_log (table_name, operation, old_data, new_data, changed_by)
        VALUES (TG_TABLE_NAME, 'UPDATE', to_jsonb(OLD), to_jsonb(NEW), current_user);
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO audit_log (table_name, operation, old_data, changed_by)
        VALUES (TG_TABLE_NAME, 'DELETE', to_jsonb(OLD), current_user);
        RETURN OLD;
    END IF;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_audit
    AFTER INSERT OR UPDATE OR DELETE ON users
    FOR EACH ROW
    EXECUTE FUNCTION audit_trigger_func();

-- 条件触发器
CREATE TRIGGER trg_high_value_order
    AFTER INSERT ON orders
    FOR EACH ROW
    WHEN (NEW.total_amount > 10000)
    EXECUTE FUNCTION notify_high_value_order();

-- 语句级触发器（每个语句执行一次，而非每行）
CREATE TRIGGER trg_orders_statement
    AFTER INSERT ON orders
    FOR EACH STATEMENT
    EXECUTE FUNCTION log_bulk_insert();
```

### 9.2 触发器变量

```sql
-- 在触发器函数中可用的特殊变量
CREATE OR REPLACE FUNCTION trigger_example()
RETURNS TRIGGER AS $$
BEGIN
    -- NEW: INSERT/UPDATE 时的新行数据
    -- OLD: UPDATE/DELETE 时的旧行数据
    -- TG_NAME: 触发器名称
    -- TG_TABLE_NAME: 表名
    -- TG_TABLE_SCHEMA: 模式名
    -- TG_OP: 操作类型 ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')
    -- TG_WHEN: 触发时机 ('BEFORE', 'AFTER', 'INSTEAD OF')
    -- TG_LEVEL: 触发级别 ('ROW', 'STATEMENT')
    
    RAISE NOTICE 'Trigger % fired on table % for %', TG_NAME, TG_TABLE_NAME, TG_OP;
    
    IF TG_OP = 'UPDATE' THEN
        -- 只有特定列变化时才执行
        IF OLD.status IS DISTINCT FROM NEW.status THEN
            -- 状态变化的处理逻辑
            INSERT INTO status_history (user_id, old_status, new_status)
            VALUES (NEW.id, OLD.status, NEW.status);
        END IF;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
```

### 9.3 管理触发器

```sql
-- 查看触发器
SELECT * FROM information_schema.triggers WHERE trigger_schema = 'public';

-- 禁用触发器
ALTER TABLE users DISABLE TRIGGER trg_users_audit;
ALTER TABLE users DISABLE TRIGGER ALL;  -- 禁用所有触发器

-- 启用触发器
ALTER TABLE users ENABLE TRIGGER trg_users_audit;
ALTER TABLE users ENABLE TRIGGER ALL;

-- 删除触发器
DROP TRIGGER trg_users_audit ON users;
DROP TRIGGER IF EXISTS trg_users_audit ON users;
```

---

## 10. 视图与物化视图

### 10.1 普通视图

视图是存储的查询，不存储数据，每次访问时执行查询。

```sql
-- 创建视图
CREATE VIEW active_users AS
SELECT id, username, email, created_at
FROM users
WHERE is_active = true;

-- 使用视图
SELECT * FROM active_users WHERE created_at > '2024-01-01';

-- 复杂视图
CREATE VIEW order_summary AS
SELECT 
    o.id AS order_id,
    u.username,
    u.email,
    o.total_amount,
    o.status,
    o.created_at,
    COUNT(oi.id) AS item_count
FROM orders o
JOIN users u ON o.user_id = u.id
LEFT JOIN order_items oi ON o.id = oi.order_id
GROUP BY o.id, u.username, u.email;

-- 创建或替换视图
CREATE OR REPLACE VIEW active_users AS
SELECT id, username, email, created_at, last_login
FROM users
WHERE is_active = true;

-- 可更新视图（简单视图可以直接更新）
UPDATE active_users SET email = 'new@example.com' WHERE id = 1;

-- 带 CHECK OPTION 的视图（防止插入不符合条件的数据）
CREATE VIEW premium_users AS
SELECT * FROM users WHERE is_premium = true
WITH CHECK OPTION;

-- 这会失败，因为 is_premium = false 不符合视图条件
INSERT INTO premium_users (username, email, is_premium) 
VALUES ('test', 'test@example.com', false);

-- 删除视图
DROP VIEW active_users;
DROP VIEW IF EXISTS active_users CASCADE;
```

### 10.2 物化视图

物化视图存储查询结果，适合复杂查询和报表场景。

```sql
-- 创建物化视图
CREATE MATERIALIZED VIEW monthly_sales_report AS
SELECT 
    DATE_TRUNC('month', created_at) AS month,
    COUNT(*) AS order_count,
    SUM(total_amount) AS total_sales,
    AVG(total_amount) AS avg_order_value
FROM orders
WHERE status = 'completed'
GROUP BY DATE_TRUNC('month', created_at)
ORDER BY month;

-- 创建时不填充数据
CREATE MATERIALIZED VIEW mv_name AS
SELECT ... 
WITH NO DATA;

-- 为物化视图创建索引（重要！）
CREATE UNIQUE INDEX idx_monthly_sales_month ON monthly_sales_report(month);
CREATE INDEX idx_monthly_sales_total ON monthly_sales_report(total_sales);

-- 刷新物化视图
REFRESH MATERIALIZED VIEW monthly_sales_report;

-- 并发刷新（不锁表，需要唯一索引）
REFRESH MATERIALIZED VIEW CONCURRENTLY monthly_sales_report;

-- 查看物化视图
\dm                              -- 列出所有物化视图
SELECT * FROM pg_matviews;       -- 查看详情

-- 删除物化视图
DROP MATERIALIZED VIEW monthly_sales_report;
```

**自动刷新物化视图：**
```sql
-- 方法1：使用 pg_cron 扩展定时刷新
CREATE EXTENSION pg_cron;

SELECT cron.schedule('refresh_mv', '0 * * * *',  -- 每小时
    'REFRESH MATERIALIZED VIEW CONCURRENTLY monthly_sales_report');

-- 方法2：使用触发器在数据变化时刷新（小数据量）
CREATE OR REPLACE FUNCTION refresh_mv_on_change()
RETURNS TRIGGER AS $$
BEGIN
    REFRESH MATERIALIZED VIEW monthly_sales_report;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_refresh_mv
    AFTER INSERT OR UPDATE OR DELETE ON orders
    FOR EACH STATEMENT
    EXECUTE FUNCTION refresh_mv_on_change();
```

---

## 11. 事务与并发控制

### 11.1 事务基础

事务是一组操作的逻辑单元，要么全部成功，要么全部失败。

```sql
-- 基本事务
BEGIN;  -- 或 START TRANSACTION;
    UPDATE accounts SET balance = balance - 100 WHERE id = 1;
    UPDATE accounts SET balance = balance + 100 WHERE id = 2;
COMMIT;  -- 提交

-- 回滚事务
BEGIN;
    UPDATE accounts SET balance = balance - 100 WHERE id = 1;
    -- 发现问题，回滚
ROLLBACK;

-- 保存点（部分回滚）
BEGIN;
    INSERT INTO orders (user_id, total_amount) VALUES (1, 100);
    SAVEPOINT sp1;
    
    INSERT INTO order_items (order_id, product_id) VALUES (1, 999);  -- 可能失败
    -- 如果失败，回滚到保存点
    ROLLBACK TO SAVEPOINT sp1;
    
    -- 继续其他操作
    INSERT INTO order_items (order_id, product_id) VALUES (1, 1);
COMMIT;

-- 只读事务
BEGIN READ ONLY;
    SELECT * FROM accounts;
    -- UPDATE 会失败
COMMIT;

-- 设置事务特性
BEGIN ISOLATION LEVEL SERIALIZABLE;
    -- ...
COMMIT;
```

### 11.2 隔离级别

PostgreSQL 支持四种隔离级别，默认是 `READ COMMITTED`。

```sql
-- 查看当前隔离级别
SHOW transaction_isolation;

-- 设置隔离级别
SET TRANSACTION ISOLATION LEVEL READ COMMITTED;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;
SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;

-- 全局设置（postgresql.conf）
-- default_transaction_isolation = 'read committed'
```

**隔离级别对比：**

| 隔离级别 | 脏读 | 不可重复读 | 幻读 | 说明 |
|---------|------|-----------|------|------|
| READ UNCOMMITTED | ❌ | ✅ | ✅ | PG 中等同于 READ COMMITTED |
| READ COMMITTED | ❌ | ✅ | ✅ | 默认级别，每条语句看到已提交数据 |
| REPEATABLE READ | ❌ | ❌ | ❌* | 事务内看到一致快照 |
| SERIALIZABLE | ❌ | ❌ | ❌ | 最严格，可能导致序列化失败 |

> 💡 PostgreSQL 的 REPEATABLE READ 实际上也防止了幻读（使用 MVCC 实现）。

```sql
-- READ COMMITTED 示例
-- 事务 A
BEGIN;
SELECT balance FROM accounts WHERE id = 1;  -- 返回 1000

-- 事务 B（同时）
BEGIN;
UPDATE accounts SET balance = 500 WHERE id = 1;
COMMIT;

-- 事务 A（继续）
SELECT balance FROM accounts WHERE id = 1;  -- 返回 500（看到 B 的提交）
COMMIT;

-- REPEATABLE READ 示例
-- 事务 A
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT balance FROM accounts WHERE id = 1;  -- 返回 1000

-- 事务 B（同时）
BEGIN;
UPDATE accounts SET balance = 500 WHERE id = 1;
COMMIT;

-- 事务 A（继续）
SELECT balance FROM accounts WHERE id = 1;  -- 仍然返回 1000（快照隔离）
COMMIT;
```

### 11.3 锁机制

```sql
-- 表级锁
LOCK TABLE users IN ACCESS SHARE MODE;        -- 最弱，只阻止 DROP/ALTER
LOCK TABLE users IN ROW SHARE MODE;           -- SELECT FOR UPDATE 使用
LOCK TABLE users IN ROW EXCLUSIVE MODE;       -- UPDATE/DELETE/INSERT 使用
LOCK TABLE users IN SHARE MODE;               -- 阻止写入
LOCK TABLE users IN EXCLUSIVE MODE;           -- 阻止读写
LOCK TABLE users IN ACCESS EXCLUSIVE MODE;    -- 最强，阻止一切

-- 行级锁
SELECT * FROM accounts WHERE id = 1 FOR UPDATE;           -- 排他锁
SELECT * FROM accounts WHERE id = 1 FOR NO KEY UPDATE;    -- 弱排他锁
SELECT * FROM accounts WHERE id = 1 FOR SHARE;            -- 共享锁
SELECT * FROM accounts WHERE id = 1 FOR KEY SHARE;        -- 弱共享锁

-- 跳过已锁定的行
SELECT * FROM tasks WHERE status = 'pending' 
FOR UPDATE SKIP LOCKED 
LIMIT 1;

-- 不等待锁
SELECT * FROM accounts WHERE id = 1 FOR UPDATE NOWAIT;

-- 查看当前锁
SELECT 
    l.locktype,
    l.relation::regclass,
    l.mode,
    l.granted,
    a.usename,
    a.query
FROM pg_locks l
JOIN pg_stat_activity a ON l.pid = a.pid
WHERE l.relation IS NOT NULL;

-- 查看锁等待
SELECT 
    blocked.pid AS blocked_pid,
    blocked.query AS blocked_query,
    blocking.pid AS blocking_pid,
    blocking.query AS blocking_query
FROM pg_stat_activity blocked
JOIN pg_locks blocked_locks ON blocked.pid = blocked_locks.pid
JOIN pg_locks blocking_locks ON blocked_locks.locktype = blocking_locks.locktype
    AND blocked_locks.relation = blocking_locks.relation
    AND blocked_locks.pid != blocking_locks.pid
JOIN pg_stat_activity blocking ON blocking_locks.pid = blocking.pid
WHERE NOT blocked_locks.granted;
```

### 11.4 死锁处理

```sql
-- 死锁示例
-- 事务 A
BEGIN;
UPDATE accounts SET balance = balance - 100 WHERE id = 1;
-- 等待事务 B 释放 id=2 的锁

-- 事务 B
BEGIN;
UPDATE accounts SET balance = balance - 100 WHERE id = 2;
UPDATE accounts SET balance = balance + 100 WHERE id = 1;  -- 等待事务 A
-- 死锁！PostgreSQL 会自动检测并回滚其中一个事务

-- 避免死锁的方法
-- 1. 按固定顺序访问资源
BEGIN;
UPDATE accounts SET balance = balance - 100 WHERE id = LEAST(1, 2);
UPDATE accounts SET balance = balance + 100 WHERE id = GREATEST(1, 2);
COMMIT;

-- 2. 使用 NOWAIT 或超时
SET lock_timeout = '5s';
SELECT * FROM accounts WHERE id = 1 FOR UPDATE NOWAIT;

-- 3. 减少事务持有锁的时间
-- 4. 使用更低的隔离级别
```

### 11.5 MVCC（多版本并发控制）

PostgreSQL 使用 MVCC 实现高并发，每个事务看到数据的一个快照。

```sql
-- 查看行的系统列
SELECT xmin, xmax, ctid, * FROM users LIMIT 5;
-- xmin: 创建该行版本的事务 ID
-- xmax: 删除该行版本的事务 ID（0 表示未删除）
-- ctid: 行的物理位置 (页号, 行号)

-- 查看当前事务 ID
SELECT txid_current();

-- 查看事务快照
SELECT txid_current_snapshot();
-- 返回格式: xmin:xmax:xip_list
-- xmin: 最小活跃事务 ID
-- xmax: 下一个将分配的事务 ID
-- xip_list: 活跃事务 ID 列表

-- VACUUM 清理死元组
VACUUM users;                    -- 普通清理
VACUUM FULL users;               -- 完全清理（会锁表）
VACUUM ANALYZE users;            -- 清理并更新统计信息
VACUUM (VERBOSE) users;          -- 显示详细信息

-- 自动 VACUUM 配置（postgresql.conf）
-- autovacuum = on
-- autovacuum_vacuum_threshold = 50
-- autovacuum_vacuum_scale_factor = 0.2
-- autovacuum_analyze_threshold = 50
-- autovacuum_analyze_scale_factor = 0.1
```

---

## 12. JSON 操作

PostgreSQL 的 JSON 支持是其一大亮点，特别是 JSONB 类型。

### 12.1 JSON 查询

```sql
-- 创建测试表
CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    data JSONB
);

INSERT INTO products (name, data) VALUES 
('iPhone', '{
    "brand": "Apple",
    "price": 999,
    "specs": {
        "storage": 256,
        "color": "black",
        "features": ["5G", "Face ID", "USB-C"]
    },
    "reviews": [
        {"user": "john", "rating": 5, "comment": "Great!"},
        {"user": "jane", "rating": 4, "comment": "Good"}
    ]
}');

-- 基本访问
SELECT 
    data->'brand' AS brand_json,           -- 返回 JSON: "Apple"
    data->>'brand' AS brand_text,          -- 返回文本: Apple
    data->'specs'->'storage' AS storage,   -- 嵌套访问
    data->'specs'->>'color' AS color,
    data#>'{specs,features,0}' AS first_feature,  -- 路径访问
    data#>>'{reviews,0,user}' AS first_reviewer
FROM products;

-- 数组操作
SELECT 
    jsonb_array_length(data->'specs'->'features') AS feature_count,
    data->'specs'->'features'->0 AS first_feature,
    data->'specs'->'features'->>-1 AS last_feature  -- 负索引
FROM products;

-- 条件查询
SELECT * FROM products WHERE data->>'brand' = 'Apple';
SELECT * FROM products WHERE (data->'price')::INTEGER > 500;
SELECT * FROM products WHERE data->'specs'->>'color' = 'black';

-- 包含查询（JSONB 特有）
SELECT * FROM products WHERE data @> '{"brand": "Apple"}';
SELECT * FROM products WHERE data->'specs' @> '{"storage": 256}';

-- 存在性检查
SELECT * FROM products WHERE data ? 'brand';                    -- 存在键
SELECT * FROM products WHERE data->'specs' ?| ARRAY['color', 'size'];  -- 存在任一
SELECT * FROM products WHERE data->'specs' ?& ARRAY['color', 'storage']; -- 存在所有
```

### 12.2 JSON 修改

```sql
-- 设置/更新值
UPDATE products 
SET data = jsonb_set(data, '{price}', '1099')
WHERE id = 1;

-- 设置嵌套值
UPDATE products 
SET data = jsonb_set(data, '{specs,storage}', '512')
WHERE id = 1;

-- 添加新键
UPDATE products 
SET data = jsonb_set(data, '{discount}', '0.1', true)  -- true 表示创建不存在的路径
WHERE id = 1;

-- 合并 JSON
UPDATE products 
SET data = data || '{"warranty": "2 years", "inStock": true}'
WHERE id = 1;

-- 删除键
UPDATE products 
SET data = data - 'discount'
WHERE id = 1;

-- 删除嵌套键
UPDATE products 
SET data = data #- '{specs,color}'
WHERE id = 1;

-- 删除数组元素
UPDATE products 
SET data = jsonb_set(
    data, 
    '{specs,features}', 
    (data->'specs'->'features') - 0  -- 删除第一个元素
)
WHERE id = 1;

-- 追加数组元素
UPDATE products 
SET data = jsonb_set(
    data,
    '{specs,features}',
    (data->'specs'->'features') || '"Wireless Charging"'
)
WHERE id = 1;
```

### 12.3 JSON 函数

```sql
-- 构建 JSON
SELECT 
    jsonb_build_object('name', 'John', 'age', 30),
    jsonb_build_array(1, 2, 3, 'four'),
    to_jsonb(ROW('John', 30)),
    row_to_json(ROW('John', 30));

-- 从表构建 JSON
SELECT jsonb_agg(to_jsonb(u) - 'password_hash') 
FROM users u 
WHERE is_active = true;

-- 展开 JSON
SELECT * FROM jsonb_each(data) FROM products WHERE id = 1;
SELECT * FROM jsonb_each_text(data) FROM products WHERE id = 1;

-- 展开数组
SELECT jsonb_array_elements(data->'specs'->'features') FROM products;
SELECT jsonb_array_elements_text(data->'specs'->'features') FROM products;

-- 获取所有键
SELECT jsonb_object_keys(data) FROM products WHERE id = 1;

-- JSON 类型
SELECT jsonb_typeof(data->'price') FROM products;  -- number
SELECT jsonb_typeof(data->'specs') FROM products;  -- object
SELECT jsonb_typeof(data->'specs'->'features') FROM products;  -- array

-- 格式化输出
SELECT jsonb_pretty(data) FROM products WHERE id = 1;

-- 聚合为 JSON
SELECT 
    department_id,
    jsonb_agg(jsonb_build_object('name', name, 'salary', salary)) AS employees
FROM employees
GROUP BY department_id;

-- JSON 路径查询（PostgreSQL 12+）
SELECT jsonb_path_query(data, '$.specs.features[*]') FROM products;
SELECT jsonb_path_query_first(data, '$.reviews[*].rating') FROM products;
SELECT jsonb_path_exists(data, '$.specs.features[*] ? (@ == "5G")') FROM products;
```

### 12.4 JSON 索引

```sql
-- GIN 索引（支持 @>, ?, ?|, ?& 操作符）
CREATE INDEX idx_products_data ON products USING GIN (data);

-- 针对特定路径的 GIN 索引
CREATE INDEX idx_products_features ON products USING GIN ((data->'specs'->'features'));

-- B-Tree 索引（针对特定字段的等值/范围查询）
CREATE INDEX idx_products_brand ON products ((data->>'brand'));
CREATE INDEX idx_products_price ON products (((data->>'price')::INTEGER));

-- 表达式索引
CREATE INDEX idx_products_lower_brand ON products (LOWER(data->>'brand'));

-- 查询时使用索引
EXPLAIN ANALYZE SELECT * FROM products WHERE data @> '{"brand": "Apple"}';
EXPLAIN ANALYZE SELECT * FROM products WHERE data->>'brand' = 'Apple';
```

---

## 13. 全文搜索

PostgreSQL 内置强大的全文搜索功能，无需额外安装 Elasticsearch 等工具。

### 13.1 基本概念

```sql
-- tsvector: 文档的词汇表示
SELECT to_tsvector('english', 'The quick brown fox jumps over the lazy dog');
-- 结果: 'brown':3 'dog':9 'fox':4 'jump':5 'lazi':8 'quick':2

-- tsquery: 搜索查询
SELECT to_tsquery('english', 'quick & fox');
-- 结果: 'quick' & 'fox'

-- 匹配操作符 @@
SELECT to_tsvector('english', 'The quick brown fox') @@ to_tsquery('english', 'quick & fox');
-- 结果: true

-- 中文支持（需要安装扩展）
CREATE EXTENSION pg_jieba;  -- 或 zhparser
SELECT to_tsvector('jiebacfg', '我爱北京天安门');
```

### 13.2 实际应用

```sql
-- 创建文章表
CREATE TABLE articles (
    id SERIAL PRIMARY KEY,
    title VARCHAR(200),
    content TEXT,
    search_vector TSVECTOR,  -- 存储预计算的向量
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 创建 GIN 索引
CREATE INDEX idx_articles_search ON articles USING GIN (search_vector);

-- 创建触发器自动更新 search_vector
CREATE OR REPLACE FUNCTION articles_search_trigger()
RETURNS TRIGGER AS $$
BEGIN
    NEW.search_vector := 
        setweight(to_tsvector('english', COALESCE(NEW.title, '')), 'A') ||
        setweight(to_tsvector('english', COALESCE(NEW.content, '')), 'B');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_articles_search
    BEFORE INSERT OR UPDATE ON articles
    FOR EACH ROW
    EXECUTE FUNCTION articles_search_trigger();

-- 插入测试数据
INSERT INTO articles (title, content) VALUES 
('PostgreSQL Full Text Search', 'PostgreSQL provides powerful full text search capabilities...'),
('Introduction to Databases', 'A database is an organized collection of data...');

-- 基本搜索
SELECT * FROM articles 
WHERE search_vector @@ to_tsquery('english', 'postgresql & search');

-- 使用 plainto_tsquery（更宽松的语法）
SELECT * FROM articles 
WHERE search_vector @@ plainto_tsquery('english', 'full text search');

-- 使用 websearch_to_tsquery（类似 Google 语法，PG 11+）
SELECT * FROM articles 
WHERE search_vector @@ websearch_to_tsquery('english', 'postgresql -mysql');
-- 支持: AND, OR, NOT(-), "phrase"

-- 搜索排名
SELECT 
    id,
    title,
    ts_rank(search_vector, query) AS rank,
    ts_rank_cd(search_vector, query) AS rank_cd  -- 考虑词距
FROM articles, to_tsquery('english', 'postgresql | database') AS query
WHERE search_vector @@ query
ORDER BY rank DESC;

-- 高亮显示
SELECT 
    id,
    ts_headline('english', title, to_tsquery('english', 'postgresql'),
        'StartSel=<b>, StopSel=</b>, MaxWords=50, MinWords=25') AS highlighted_title,
    ts_headline('english', content, to_tsquery('english', 'postgresql'),
        'StartSel=<b>, StopSel=</b>, MaxFragments=3') AS highlighted_content
FROM articles
WHERE search_vector @@ to_tsquery('english', 'postgresql');
```

### 13.3 高级搜索

```sql
-- 短语搜索
SELECT * FROM articles 
WHERE search_vector @@ phraseto_tsquery('english', 'full text search');

-- 前缀搜索
SELECT * FROM articles 
WHERE search_vector @@ to_tsquery('english', 'post:*');

-- 模糊搜索（结合 pg_trgm）
CREATE EXTENSION pg_trgm;

CREATE INDEX idx_articles_title_trgm ON articles USING GIN (title gin_trgm_ops);

SELECT * FROM articles 
WHERE title % 'postgre'  -- 相似度匹配
ORDER BY similarity(title, 'postgre') DESC;

-- 组合搜索
SELECT * FROM articles
WHERE search_vector @@ to_tsquery('english', 'database')
   OR title ILIKE '%database%'
ORDER BY 
    CASE WHEN search_vector @@ to_tsquery('english', 'database') THEN 0 ELSE 1 END,
    ts_rank(search_vector, to_tsquery('english', 'database')) DESC;
```

---

## 14. 分区表

分区表将大表分割成多个小表，提高查询性能和管理效率。

### 14.1 范围分区

```sql
-- 创建分区主表
CREATE TABLE orders (
    id SERIAL,
    user_id INTEGER NOT NULL,
    total_amount DECIMAL(10,2),
    status VARCHAR(20),
    created_at TIMESTAMP NOT NULL,
    PRIMARY KEY (id, created_at)  -- 分区键必须包含在主键中
) PARTITION BY RANGE (created_at);

-- 创建分区
CREATE TABLE orders_2024_q1 PARTITION OF orders
    FOR VALUES FROM ('2024-01-01') TO ('2024-04-01');

CREATE TABLE orders_2024_q2 PARTITION OF orders
    FOR VALUES FROM ('2024-04-01') TO ('2024-07-01');

CREATE TABLE orders_2024_q3 PARTITION OF orders
    FOR VALUES FROM ('2024-07-01') TO ('2024-10-01');

CREATE TABLE orders_2024_q4 PARTITION OF orders
    FOR VALUES FROM ('2024-10-01') TO ('2025-01-01');

-- 创建默认分区（接收不匹配任何分区的数据）
CREATE TABLE orders_default PARTITION OF orders DEFAULT;

-- 为分区创建索引（会自动应用到所有分区）
CREATE INDEX idx_orders_user_id ON orders(user_id);
CREATE INDEX idx_orders_created_at ON orders(created_at);

-- 插入数据（自动路由到正确分区）
INSERT INTO orders (user_id, total_amount, status, created_at)
VALUES (1, 100.00, 'completed', '2024-03-15');

-- 查询（自动分区裁剪）
EXPLAIN ANALYZE
SELECT * FROM orders WHERE created_at BETWEEN '2024-01-01' AND '2024-03-31';
```

### 14.2 列表分区

```sql
-- 按地区分区
CREATE TABLE customers (
    id SERIAL,
    name VARCHAR(100),
    region VARCHAR(20) NOT NULL,
    PRIMARY KEY (id, region)
) PARTITION BY LIST (region);

CREATE TABLE customers_asia PARTITION OF customers
    FOR VALUES IN ('CN', 'JP', 'KR', 'SG');

CREATE TABLE customers_europe PARTITION OF customers
    FOR VALUES IN ('UK', 'DE', 'FR', 'IT');

CREATE TABLE customers_americas PARTITION OF customers
    FOR VALUES IN ('US', 'CA', 'BR', 'MX');

CREATE TABLE customers_other PARTITION OF customers DEFAULT;
```

### 14.3 哈希分区

```sql
-- 按用户 ID 哈希分区（均匀分布）
CREATE TABLE user_activities (
    id SERIAL,
    user_id INTEGER NOT NULL,
    activity_type VARCHAR(50),
    created_at TIMESTAMP,
    PRIMARY KEY (id, user_id)
) PARTITION BY HASH (user_id);

-- 创建 4 个分区
CREATE TABLE user_activities_0 PARTITION OF user_activities
    FOR VALUES WITH (MODULUS 4, REMAINDER 0);
CREATE TABLE user_activities_1 PARTITION OF user_activities
    FOR VALUES WITH (MODULUS 4, REMAINDER 1);
CREATE TABLE user_activities_2 PARTITION OF user_activities
    FOR VALUES WITH (MODULUS 4, REMAINDER 2);
CREATE TABLE user_activities_3 PARTITION OF user_activities
    FOR VALUES WITH (MODULUS 4, REMAINDER 3);
```

### 14.4 分区管理

```sql
-- 查看分区信息
SELECT 
    parent.relname AS parent_table,
    child.relname AS partition_name,
    pg_get_expr(child.relpartbound, child.oid) AS partition_expression
FROM pg_inherits
JOIN pg_class parent ON pg_inherits.inhparent = parent.oid
JOIN pg_class child ON pg_inherits.inhrelid = child.oid
WHERE parent.relname = 'orders';

-- 添加新分区
CREATE TABLE orders_2025_q1 PARTITION OF orders
    FOR VALUES FROM ('2025-01-01') TO ('2025-04-01');

-- 分离分区（不删除数据）
ALTER TABLE orders DETACH PARTITION orders_2024_q1;

-- 重新附加分区
ALTER TABLE orders ATTACH PARTITION orders_2024_q1
    FOR VALUES FROM ('2024-01-01') TO ('2024-04-01');

-- 删除分区
DROP TABLE orders_2024_q1;

-- 自动创建分区（使用 pg_partman 扩展）
CREATE EXTENSION pg_partman;

SELECT partman.create_parent(
    p_parent_table := 'public.orders',
    p_control := 'created_at',
    p_type := 'native',
    p_interval := '1 month',
    p_premake := 3
);
```

---

## 15. 性能优化

### 15.1 EXPLAIN 分析

```sql
-- 基本执行计划
EXPLAIN SELECT * FROM users WHERE email = 'test@example.com';

-- 实际执行（包含真实时间和行数）
EXPLAIN ANALYZE SELECT * FROM users WHERE email = 'test@example.com';

-- 详细信息
EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) 
SELECT * FROM users WHERE email = 'test@example.com';

-- JSON 格式（便于程序解析）
EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) 
SELECT * FROM users WHERE email = 'test@example.com';
```

**执行计划解读：**
```
Seq Scan on users  (cost=0.00..155.00 rows=1 width=100) (actual time=0.015..1.234 rows=1 loops=1)
  Filter: (email = 'test@example.com'::text)
  Rows Removed by Filter: 9999
Planning Time: 0.123 ms
Execution Time: 1.456 ms
```

- `Seq Scan`：顺序扫描（全表扫描）
- `Index Scan`：索引扫描
- `Index Only Scan`：仅索引扫描（覆盖索引）
- `Bitmap Index Scan`：位图索引扫描
- `cost=0.00..155.00`：启动成本..总成本
- `rows=1`：预估行数
- `actual time`：实际执行时间
- `Rows Removed by Filter`：被过滤掉的行数

### 15.2 查询优化

```sql
-- 1. 使用索引
-- 不好：函数导致索引失效
SELECT * FROM users WHERE LOWER(email) = 'test@example.com';
-- 好：创建表达式索引
CREATE INDEX idx_users_lower_email ON users (LOWER(email));

-- 2. 避免 SELECT *
-- 不好
SELECT * FROM users WHERE id = 1;
-- 好
SELECT id, username, email FROM users WHERE id = 1;

-- 3. 使用 EXISTS 代替 IN（大数据集）
-- 不好
SELECT * FROM orders WHERE user_id IN (SELECT id FROM users WHERE is_vip = true);
-- 好
SELECT * FROM orders o WHERE EXISTS (
    SELECT 1 FROM users u WHERE u.id = o.user_id AND u.is_vip = true
);

-- 4. 分页优化
-- 不好（大偏移量性能差）
SELECT * FROM orders ORDER BY id LIMIT 10 OFFSET 100000;
-- 好（使用游标分页）
SELECT * FROM orders WHERE id > 100000 ORDER BY id LIMIT 10;

-- 5. 批量操作
-- 不好（多次往返）
INSERT INTO logs (message) VALUES ('log1');
INSERT INTO logs (message) VALUES ('log2');
-- 好（单次往返）
INSERT INTO logs (message) VALUES ('log1'), ('log2'), ('log3');

-- 6. 使用 COPY 批量导入
COPY users (username, email) FROM '/path/to/data.csv' WITH CSV HEADER;

-- 7. 避免 N+1 查询
-- 不好：先查用户，再循环查订单
-- 好：使用 JOIN 一次查询
SELECT u.*, o.* FROM users u LEFT JOIN orders o ON u.id = o.user_id;
```

### 15.3 配置优化

```ini
# postgresql.conf 关键参数

# 内存配置
shared_buffers = 4GB              # 建议为内存的 25%
effective_cache_size = 12GB       # 建议为内存的 75%
work_mem = 64MB                   # 每个操作的内存，复杂查询可调高
maintenance_work_mem = 512MB      # 维护操作内存

# 连接配置
max_connections = 200             # 最大连接数
# 建议使用连接池（如 PgBouncer）而非增加此值

# WAL 配置
wal_buffers = 64MB
checkpoint_completion_target = 0.9
max_wal_size = 4GB

# 查询优化器
random_page_cost = 1.1            # SSD 设为 1.1，HDD 保持 4.0
effective_io_concurrency = 200    # SSD 设为 200，HDD 设为 2

# 并行查询
max_parallel_workers_per_gather = 4
max_parallel_workers = 8
max_parallel_maintenance_workers = 4

# 日志
log_min_duration_statement = 1000  # 记录超过 1 秒的查询
log_checkpoints = on
log_lock_waits = on
```

### 15.4 监控与诊断

```sql
-- 查看当前活动连接
SELECT 
    pid,
    usename,
    application_name,
    client_addr,
    state,
    query_start,
    query
FROM pg_stat_activity
WHERE state != 'idle'
ORDER BY query_start;

-- 查看长时间运行的查询
SELECT 
    pid,
    NOW() - query_start AS duration,
    query
FROM pg_stat_activity
WHERE state = 'active'
  AND NOW() - query_start > INTERVAL '5 minutes';

-- 终止查询
SELECT pg_cancel_backend(pid);     -- 取消查询
SELECT pg_terminate_backend(pid);  -- 终止连接

-- 表统计信息
SELECT 
    relname,
    n_live_tup,           -- 活跃行数
    n_dead_tup,           -- 死行数
    last_vacuum,          -- 上次 VACUUM
    last_autovacuum,      -- 上次自动 VACUUM
    last_analyze          -- 上次 ANALYZE
FROM pg_stat_user_tables
ORDER BY n_dead_tup DESC;

-- 索引使用情况
SELECT 
    schemaname,
    tablename,
    indexname,
    idx_scan,             -- 索引扫描次数
    idx_tup_read,         -- 通过索引读取的行
    idx_tup_fetch         -- 通过索引获取的行
FROM pg_stat_user_indexes
ORDER BY idx_scan DESC;

-- 未使用的索引
SELECT 
    schemaname,
    tablename,
    indexname,
    pg_size_pretty(pg_relation_size(indexrelid)) AS size
FROM pg_stat_user_indexes
WHERE idx_scan = 0
  AND indexrelname NOT LIKE '%_pkey';

-- 缓存命中率
SELECT 
    sum(heap_blks_read) AS heap_read,
    sum(heap_blks_hit) AS heap_hit,
    sum(heap_blks_hit) / (sum(heap_blks_hit) + sum(heap_blks_read)) AS ratio
FROM pg_statio_user_tables;
-- 目标：> 99%

-- 数据库大小
SELECT 
    pg_database.datname,
    pg_size_pretty(pg_database_size(pg_database.datname)) AS size
FROM pg_database
ORDER BY pg_database_size(pg_database.datname) DESC;

-- 表大小
SELECT 
    relname AS table_name,
    pg_size_pretty(pg_total_relation_size(relid)) AS total_size,
    pg_size_pretty(pg_relation_size(relid)) AS table_size,
    pg_size_pretty(pg_indexes_size(relid)) AS index_size
FROM pg_catalog.pg_statio_user_tables
ORDER BY pg_total_relation_size(relid) DESC;
```

---

## 16. 备份与恢复

### 16.1 逻辑备份（pg_dump）

```bash
# 备份单个数据库
pg_dump -U postgres -d mydb > mydb_backup.sql
pg_dump -U postgres -d mydb -F c -f mydb_backup.dump  # 自定义格式（推荐）
pg_dump -U postgres -d mydb -F t -f mydb_backup.tar   # tar 格式
pg_dump -U postgres -d mydb -F d -f mydb_backup_dir   # 目录格式（支持并行）

# 常用选项
pg_dump -U postgres -d mydb \
    --no-owner \              # 不包含所有者信息
    --no-privileges \         # 不包含权限信息
    --schema=public \         # 只备份特定 schema
    --table=users \           # 只备份特定表
    --exclude-table=logs \    # 排除特定表
    --data-only \             # 只备份数据
    --schema-only \           # 只备份结构
    -F c -f backup.dump

# 并行备份（目录格式）
pg_dump -U postgres -d mydb -F d -j 4 -f backup_dir

# 备份所有数据库
pg_dumpall -U postgres > all_databases.sql
pg_dumpall -U postgres --globals-only > globals.sql  # 只备份角色和表空间
```

### 16.2 恢复

```bash
# 从 SQL 文件恢复
psql -U postgres -d mydb < mydb_backup.sql

# 从自定义格式恢复
pg_restore -U postgres -d mydb mydb_backup.dump

# 恢复选项
pg_restore -U postgres -d mydb \
    --clean \                 # 先删除现有对象
    --if-exists \             # 删除时使用 IF EXISTS
    --no-owner \              # 不恢复所有者
    --no-privileges \         # 不恢复权限
    --schema=public \         # 只恢复特定 schema
    --table=users \           # 只恢复特定表
    -j 4 \                    # 并行恢复
    mydb_backup.dump

# 恢复到新数据库
createdb -U postgres newdb
pg_restore -U postgres -d newdb mydb_backup.dump

# 列出备份内容
pg_restore -l mydb_backup.dump
```

### 16.3 物理备份（pg_basebackup）

```bash
# 基础备份
pg_basebackup -U postgres -D /backup/base -Fp -Xs -P

# 选项说明
# -D: 备份目录
# -Fp: 普通格式
# -Ft: tar 格式
# -Xs: 流式传输 WAL
# -P: 显示进度

# 压缩备份
pg_basebackup -U postgres -D /backup/base -Ft -z -Xs -P

# 远程备份
pg_basebackup -h remote_host -U replication -D /backup/base -Fp -Xs -P
```

### 16.4 时间点恢复（PITR）

```bash
# 1. 配置 WAL 归档（postgresql.conf）
archive_mode = on
archive_command = 'cp %p /archive/%f'
wal_level = replica

# 2. 创建基础备份
pg_basebackup -U postgres -D /backup/base -Fp -Xs -P

# 3. 恢复到特定时间点
# 创建 recovery.signal 文件
touch /data/recovery.signal

# 配置 postgresql.conf
restore_command = 'cp /archive/%f %p'
recovery_target_time = '2024-01-15 10:30:00'
recovery_target_action = 'promote'

# 4. 启动数据库
pg_ctl start -D /data
```

### 16.5 备份策略建议

```bash
#!/bin/bash
# 每日备份脚本示例

BACKUP_DIR="/backup/postgresql"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=7

# 创建备份
pg_dump -U postgres -d mydb -F c -f "$BACKUP_DIR/mydb_$DATE.dump"

# 压缩
gzip "$BACKUP_DIR/mydb_$DATE.dump"

# 删除旧备份
find "$BACKUP_DIR" -name "*.dump.gz" -mtime +$RETENTION_DAYS -delete

# 验证备份
pg_restore -l "$BACKUP_DIR/mydb_$DATE.dump.gz" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Backup successful: mydb_$DATE.dump.gz"
else
    echo "Backup verification failed!" | mail -s "Backup Alert" admin@example.com
fi
```

---

## 17. 安全管理

### 17.1 用户与角色

```sql
-- 创建角色（用户是具有登录权限的角色）
CREATE ROLE readonly;
CREATE ROLE readwrite;
CREATE USER app_user WITH PASSWORD 'secure_password';

-- 角色属性
CREATE ROLE admin WITH 
    LOGIN                    -- 可以登录
    SUPERUSER                -- 超级用户
    CREATEDB                 -- 可以创建数据库
    CREATEROLE               -- 可以创建角色
    REPLICATION              -- 可以复制
    PASSWORD 'password'      -- 密码
    VALID UNTIL '2025-01-01' -- 密码过期时间
    CONNECTION LIMIT 10;     -- 连接限制

-- 修改角色
ALTER ROLE app_user WITH PASSWORD 'new_password';
ALTER ROLE app_user VALID UNTIL 'infinity';
ALTER ROLE app_user CONNECTION LIMIT 20;

-- 角色继承
GRANT readonly TO readwrite;      -- readwrite 继承 readonly 的权限
GRANT readwrite TO app_user;

-- 查看角色
\du
SELECT * FROM pg_roles;

-- 删除角色
DROP ROLE readonly;
REASSIGN OWNED BY old_user TO new_user;  -- 转移所有权
DROP OWNED BY old_user;                   -- 删除所有对象
DROP ROLE old_user;
```

### 17.2 权限管理

```sql
-- 数据库权限
GRANT CONNECT ON DATABASE mydb TO app_user;
GRANT CREATE ON DATABASE mydb TO app_user;
REVOKE ALL ON DATABASE mydb FROM PUBLIC;

-- Schema 权限
GRANT USAGE ON SCHEMA public TO readonly;
GRANT CREATE ON SCHEMA public TO readwrite;

-- 表权限
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO readwrite;
GRANT ALL PRIVILEGES ON TABLE users TO admin;

-- 列级权限
GRANT SELECT (id, username, email) ON users TO readonly;
GRANT UPDATE (email, phone) ON users TO app_user;

-- 序列权限
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO readwrite;

-- 函数权限
GRANT EXECUTE ON FUNCTION my_function() TO app_user;

-- 默认权限（新创建的对象自动授权）
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON TABLES TO readonly;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO readwrite;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO readwrite;

-- 查看权限
\dp tablename                    -- 查看表权限
\dp                              -- 查看所有表权限
SELECT * FROM information_schema.table_privileges WHERE grantee = 'app_user';

-- 撤销权限
REVOKE INSERT ON users FROM app_user;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM app_user;
```

### 17.3 行级安全（RLS）

行级安全允许控制用户可以访问哪些行。

```sql
-- 启用行级安全
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;

-- 创建策略
-- 用户只能看到自己的订单
CREATE POLICY user_orders_policy ON orders
    FOR ALL
    TO app_user
    USING (user_id = current_setting('app.current_user_id')::INTEGER);

-- 分离读写策略
CREATE POLICY orders_select_policy ON orders
    FOR SELECT
    USING (user_id = current_setting('app.current_user_id')::INTEGER);

CREATE POLICY orders_insert_policy ON orders
    FOR INSERT
    WITH CHECK (user_id = current_setting('app.current_user_id')::INTEGER);

-- 管理员可以看到所有数据
CREATE POLICY admin_all_policy ON orders
    FOR ALL
    TO admin
    USING (true);

-- 使用 RLS
SET app.current_user_id = '123';
SELECT * FROM orders;  -- 只返回 user_id = 123 的订单

-- 查看策略
\dp orders
SELECT * FROM pg_policies WHERE tablename = 'orders';

-- 删除策略
DROP POLICY user_orders_policy ON orders;

-- 禁用 RLS
ALTER TABLE orders DISABLE ROW LEVEL SECURITY;
```

### 17.4 SSL 加密

```bash
# 生成自签名证书
openssl req -new -x509 -days 365 -nodes -text \
    -out server.crt \
    -keyout server.key \
    -subj "/CN=dbserver.example.com"

chmod 600 server.key
chown postgres:postgres server.key server.crt

# 移动到数据目录
mv server.crt server.key /var/lib/postgresql/14/main/
```

```ini
# postgresql.conf
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
ssl_min_protocol_version = 'TLSv1.2'
```

```ini
# pg_hba.conf - 强制 SSL
hostssl all all 0.0.0.0/0 scram-sha-256
```

```bash
# 客户端连接
psql "host=dbserver.example.com dbname=mydb user=app_user sslmode=require"

# sslmode 选项:
# disable: 不使用 SSL
# allow: 优先不使用，服务器要求时使用
# prefer: 优先使用（默认）
# require: 必须使用
# verify-ca: 必须使用并验证 CA
# verify-full: 必须使用并验证 CA 和主机名
```

### 17.5 审计日志

```sql
-- 使用 pgAudit 扩展
CREATE EXTENSION pgaudit;

-- 配置审计（postgresql.conf）
-- pgaudit.log = 'all'
-- pgaudit.log_catalog = off
-- pgaudit.log_parameter = on

-- 或使用触发器实现审计（见第 9 节）
```

---

## 18. 常见错误与解决方案

### 18.1 连接问题

**错误：connection refused**
```
psql: error: connection to server at "localhost" (127.0.0.1), port 5432 failed: Connection refused
```
**原因与解决：**
```bash
# 1. 检查服务是否运行
sudo systemctl status postgresql

# 2. 检查监听地址（postgresql.conf）
listen_addresses = '*'  # 或具体 IP

# 3. 检查端口
sudo netstat -tlnp | grep 5432

# 4. 重启服务
sudo systemctl restart postgresql
```

**错误：no pg_hba.conf entry**
```
FATAL: no pg_hba.conf entry for host "192.168.1.100", user "app_user", database "mydb"
```
**解决：**
```ini
# pg_hba.conf 添加
host    mydb    app_user    192.168.1.0/24    scram-sha-256
```

**错误：password authentication failed**
```
FATAL: password authentication failed for user "app_user"
```
**解决：**
```sql
-- 重置密码
ALTER USER app_user WITH PASSWORD 'new_password';

-- 检查认证方法（pg_hba.conf）
-- 确保使用正确的认证方法（scram-sha-256 或 md5）
```

**错误：too many connections**
```
FATAL: too many connections for role "app_user"
```
**解决：**
```sql
-- 查看当前连接
SELECT count(*) FROM pg_stat_activity;

-- 增加连接数（需要重启）
-- postgresql.conf: max_connections = 200

-- 或使用连接池（推荐）
-- 安装 PgBouncer

-- 终止空闲连接
SELECT pg_terminate_backend(pid) 
FROM pg_stat_activity 
WHERE state = 'idle' 
  AND query_start < NOW() - INTERVAL '10 minutes';
```

### 18.2 查询问题

**错误：column does not exist**
```
ERROR: column "Username" does not exist
```
**原因与解决：**
```sql
-- PostgreSQL 默认将标识符转为小写
-- 错误
SELECT Username FROM users;

-- 正确（使用小写或双引号）
SELECT username FROM users;
SELECT "Username" FROM users;  -- 如果创建时用了双引号

-- 最佳实践：始终使用小写命名
```

**错误：operator does not exist**
```
ERROR: operator does not exist: character varying = integer
```
**解决：**
```sql
-- 类型不匹配，需要显式转换
-- 错误
SELECT * FROM users WHERE id = '1';

-- 正确
SELECT * FROM users WHERE id = 1;
SELECT * FROM users WHERE id = '1'::INTEGER;
```

**错误：division by zero**
```
ERROR: division by zero
```
**解决：**
```sql
-- 使用 NULLIF 避免除零
SELECT amount / NULLIF(quantity, 0) FROM orders;

-- 或使用 CASE
SELECT 
    CASE WHEN quantity = 0 THEN 0 
         ELSE amount / quantity 
    END
FROM orders;
```

**错误：value too long for type**
```
ERROR: value too long for type character varying(50)
```
**解决：**
```sql
-- 增加列长度
ALTER TABLE users ALTER COLUMN username TYPE VARCHAR(100);

-- 或截断数据
INSERT INTO users (username) VALUES (LEFT('very_long_username...', 50));
```

### 18.3 事务问题

**错误：current transaction is aborted**
```
ERROR: current transaction is aborted, commands ignored until end of transaction block
```
**原因与解决：**
```sql
-- 事务中发生错误后，必须回滚才能继续
ROLLBACK;

-- 或使用保存点
BEGIN;
SAVEPOINT sp1;
-- 可能失败的操作
ROLLBACK TO SAVEPOINT sp1;
-- 继续其他操作
COMMIT;
```

**错误：deadlock detected**
```
ERROR: deadlock detected
```
**解决：**
```sql
-- 1. 按固定顺序访问资源
-- 2. 减少事务持有锁的时间
-- 3. 使用 NOWAIT 或超时
SET lock_timeout = '5s';
SELECT * FROM accounts WHERE id = 1 FOR UPDATE NOWAIT;
```

**错误：could not serialize access**
```
ERROR: could not serialize access due to concurrent update
```
**解决：**
```sql
-- SERIALIZABLE 隔离级别下的冲突
-- 捕获错误并重试
DO $$
DECLARE
    retry_count INTEGER := 0;
BEGIN
    LOOP
        BEGIN
            -- 你的事务逻辑
            UPDATE accounts SET balance = balance - 100 WHERE id = 1;
            EXIT;  -- 成功则退出循环
        EXCEPTION
            WHEN serialization_failure THEN
                retry_count := retry_count + 1;
                IF retry_count > 3 THEN
                    RAISE;
                END IF;
                -- 等待后重试
                PERFORM pg_sleep(0.1 * retry_count);
        END;
    END LOOP;
END $$;
```

### 18.4 性能问题

**问题：查询很慢**
```sql
-- 1. 分析执行计划
EXPLAIN ANALYZE SELECT * FROM orders WHERE user_id = 1;

-- 2. 检查是否使用索引
-- 如果显示 Seq Scan，考虑添加索引
CREATE INDEX idx_orders_user_id ON orders(user_id);

-- 3. 更新统计信息
ANALYZE orders;

-- 4. 检查表膨胀
SELECT 
    relname,
    n_dead_tup,
    n_live_tup,
    round(n_dead_tup * 100.0 / NULLIF(n_live_tup + n_dead_tup, 0), 2) AS dead_ratio
FROM pg_stat_user_tables
WHERE n_dead_tup > 1000
ORDER BY n_dead_tup DESC;

-- 5. 清理死元组
VACUUM ANALYZE orders;
```

**问题：索引不生效**
```sql
-- 常见原因：

-- 1. 函数导致索引失效
-- 错误
SELECT * FROM users WHERE LOWER(email) = 'test@example.com';
-- 解决：创建表达式索引
CREATE INDEX idx_users_lower_email ON users(LOWER(email));

-- 2. 类型不匹配
-- 错误（id 是 INTEGER，但用字符串比较）
SELECT * FROM users WHERE id = '1';
-- 正确
SELECT * FROM users WHERE id = 1;

-- 3. LIKE 以通配符开头
-- 索引无法使用
SELECT * FROM users WHERE email LIKE '%@gmail.com';
-- 可以使用索引
SELECT * FROM users WHERE email LIKE 'john%';

-- 4. OR 条件
-- 可能不使用索引
SELECT * FROM users WHERE email = 'a@b.com' OR phone = '123';
-- 改用 UNION
SELECT * FROM users WHERE email = 'a@b.com'
UNION
SELECT * FROM users WHERE phone = '123';

-- 5. 数据量太小
-- 优化器认为全表扫描更快

-- 6. 统计信息过时
ANALYZE users;
```

### 18.5 数据完整性问题

**错误：duplicate key value violates unique constraint**
```
ERROR: duplicate key value violates unique constraint "users_email_key"
```
**解决：**
```sql
-- 使用 ON CONFLICT 处理
INSERT INTO users (email, username) VALUES ('test@example.com', 'test')
ON CONFLICT (email) DO UPDATE SET username = EXCLUDED.username;

-- 或先检查
INSERT INTO users (email, username)
SELECT 'test@example.com', 'test'
WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = 'test@example.com');
```

**错误：foreign key constraint violation**
```
ERROR: insert or update on table "orders" violates foreign key constraint "orders_user_id_fkey"
```
**解决：**
```sql
-- 确保引用的记录存在
INSERT INTO users (id, username) VALUES (1, 'john');
INSERT INTO orders (user_id, total_amount) VALUES (1, 100);

-- 或使用 ON DELETE CASCADE
ALTER TABLE orders 
DROP CONSTRAINT orders_user_id_fkey,
ADD CONSTRAINT orders_user_id_fkey 
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
```

**错误：null value in column violates not-null constraint**
```
ERROR: null value in column "email" violates not-null constraint
```
**解决：**
```sql
-- 提供值
INSERT INTO users (username, email) VALUES ('john', 'john@example.com');

-- 或设置默认值
ALTER TABLE users ALTER COLUMN email SET DEFAULT 'unknown@example.com';

-- 或允许 NULL
ALTER TABLE users ALTER COLUMN email DROP NOT NULL;
```

### 18.6 存储与维护问题

**问题：磁盘空间不足**
```sql
-- 查看数据库大小
SELECT pg_size_pretty(pg_database_size('mydb'));

-- 查看表大小
SELECT 
    relname,
    pg_size_pretty(pg_total_relation_size(relid)) AS total_size
FROM pg_catalog.pg_statio_user_tables
ORDER BY pg_total_relation_size(relid) DESC
LIMIT 10;

-- 清理死元组
VACUUM FULL tablename;  -- 会锁表！

-- 删除旧数据
DELETE FROM logs WHERE created_at < NOW() - INTERVAL '90 days';
VACUUM logs;

-- 清理 WAL 文件
-- 检查 pg_wal 目录大小
-- 确保 checkpoint 正常运行
CHECKPOINT;
```

**问题：序列值用尽或不同步**
```sql
-- 查看序列当前值
SELECT last_value FROM users_id_seq;

-- 重置序列
ALTER SEQUENCE users_id_seq RESTART WITH 1000;

-- 同步序列与表数据
SELECT setval('users_id_seq', (SELECT MAX(id) FROM users));

-- 或使用 pg_get_serial_sequence
SELECT setval(pg_get_serial_sequence('users', 'id'), (SELECT MAX(id) FROM users));
```

**问题：表膨胀**
```sql
-- 检查膨胀
SELECT 
    schemaname,
    relname,
    n_live_tup,
    n_dead_tup,
    round(n_dead_tup * 100.0 / NULLIF(n_live_tup, 0), 2) AS dead_pct
FROM pg_stat_user_tables
WHERE n_dead_tup > 0
ORDER BY n_dead_tup DESC;

-- 解决方案
-- 1. 普通 VACUUM（不锁表，不回收空间给 OS）
VACUUM tablename;

-- 2. VACUUM FULL（锁表，回收空间）
VACUUM FULL tablename;

-- 3. 使用 pg_repack（不锁表，回收空间）
-- 需要安装扩展
CREATE EXTENSION pg_repack;
-- 命令行执行
pg_repack -d mydb -t tablename
```

### 18.7 编码与字符集问题

**错误：character with byte sequence does not exist in encoding**
```
ERROR: character with byte sequence 0xe4 0xb8 0xad in encoding "UTF8" has no equivalent in encoding "LATIN1"
```
**解决：**
```sql
-- 检查数据库编码
SELECT pg_encoding_to_char(encoding) FROM pg_database WHERE datname = 'mydb';

-- 创建 UTF8 数据库
CREATE DATABASE mydb WITH ENCODING 'UTF8' LC_COLLATE 'en_US.UTF-8' LC_CTYPE 'en_US.UTF-8';

-- 设置客户端编码
SET client_encoding = 'UTF8';

-- 转换数据
SELECT convert_to('中文', 'UTF8');
SELECT convert_from(bytea_column, 'UTF8');
```

### 18.8 复制与高可用问题

**错误：requested WAL segment has already been removed**
```
ERROR: requested WAL segment 000000010000000000000001 has already been removed
```
**解决：**
```ini
# postgresql.conf - 增加 WAL 保留
wal_keep_size = 1GB  # PG 13+
# 或
wal_keep_segments = 64  # PG 12 及之前

# 或使用复制槽
SELECT * FROM pg_create_physical_replication_slot('replica_slot');
```

**问题：主从延迟**
```sql
-- 在主库查看
SELECT 
    client_addr,
    state,
    sent_lsn,
    write_lsn,
    flush_lsn,
    replay_lsn,
    pg_wal_lsn_diff(sent_lsn, replay_lsn) AS lag_bytes
FROM pg_stat_replication;

-- 在从库查看
SELECT 
    pg_is_in_recovery(),
    pg_last_wal_receive_lsn(),
    pg_last_wal_replay_lsn(),
    pg_last_xact_replay_timestamp();
```

---

## 附录：常用命令速查

### psql 命令

| 命令 | 说明 |
|------|------|
| `\l` | 列出所有数据库 |
| `\c dbname` | 切换数据库 |
| `\dt` | 列出表 |
| `\dt+` | 列出表（含大小） |
| `\d tablename` | 查看表结构 |
| `\di` | 列出索引 |
| `\dv` | 列出视图 |
| `\df` | 列出函数 |
| `\du` | 列出用户/角色 |
| `\dp` | 列出权限 |
| `\x` | 切换扩展显示 |
| `\timing` | 显示执行时间 |
| `\i file.sql` | 执行 SQL 文件 |
| `\o file.txt` | 输出到文件 |
| `\q` | 退出 |

### 系统管理命令

```sql
-- 重载配置
SELECT pg_reload_conf();

-- 查看配置
SHOW ALL;
SHOW shared_buffers;

-- 查看版本
SELECT version();

-- 查看运行时间
SELECT pg_postmaster_start_time();
SELECT NOW() - pg_postmaster_start_time() AS uptime;

-- 取消查询
SELECT pg_cancel_backend(pid);

-- 终止连接
SELECT pg_terminate_backend(pid);

-- 切换 WAL
SELECT pg_switch_wal();

-- 手动 checkpoint
CHECKPOINT;
```

---

> 📝 **笔记说明**
> - 本笔记基于 PostgreSQL 14 编写
> - 部分高级特性可能需要特定版本支持
> - 生产环境操作前请先在测试环境验证
> - 建议结合官方文档深入学习：https://www.postgresql.org/docs/14/

---

*最后更新：2024年*
